'use strict';

// A2A behavioural parity with the Python runtime (agentcreds-runtime/tests/test_a2a.py).
//
// The two verifiers implement the same protocol and, until 2026-09-07, asserted
// different subsets of it: Python carried 29 A2A tests to Node's 14, and the difference
// was not scope - it was behaviours (constructor guards, envelope handling, principal
// header validation, the replay guard's own contract) that Node implemented and never
// pinned. Each test below names its Python counterpart, so the next diff of the two
// suites is a name comparison rather than an archaeology project.
//
// Redis-backed replay (`a2a_replay_guard_with_redis_backend`) is deliberately absent:
// it needs a live Redis, and a mocked one would pin the mock. The in-memory guard's
// contract is pinned here instead.

const { test } = require('node:test');
const assert = require('node:assert');

const ac = require('@agentcreds/sdk');
const {
  CODES,
  A2AVerifier,
  makeA2AHeader,
  makeA2AEnvelope,
  makeA2ABoundArgsHeader,
  parseA2ABoundArgsHeader,
  parseA2APrincipalHeader,
  makeA2APrincipalHeader,
  InMemoryReplayGuard,
  classifyError,
  jcsCanonicalizeArgs,
  octetsBindArgs,
  parseBoundArgs,
  JCS_PROFILE,
  MAX_BOUND_ARGS_BYTES,
  A2A_HEADER_NAME,
} = require('..');

const RECEIVER = 'a2a://orders.example/agent';

function makeWorld(tools = ['tool:search']) {
  const anchor = ac.TrustAnchor.generate();
  const agent = ac.AgentIdentity.createDidKey();
  const claims = new ac.CapabilityClaims({ tools, maxDelegationDepth: 1, validForSecs: 3600 });
  const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, null);
  const token = ac.DelegationToken.mint(vc, new ac.Scope({ tools, budgetUsd: 100, maxDepth: 1 }), 300, agent);
  return { anchor, agent, vc, token };
}

function bind(token, vc, agent, tool, args) {
  const action = new ac.Action(tool, jcsCanonicalizeArgs(args));
  return makeA2AHeader(token, vc, agent, { audience: RECEIVER, action });
}
const DECLARED = { canonicalizationProfile: JCS_PROFILE };

// -- Constructor guards (Python: a2a_requires_anchor_or_resolver, a2a_requires_audience,
// and the revocation posture already pinned in a2a.test.js) -----------------------------

test('constructing a verifier without an anchor source throws', () => {
  assert.throws(
    () => new A2AVerifier({ audience: RECEIVER, revocationCheck: false }),
    /anchor/,
  );
});

test('constructing a verifier without an audience throws', () => {
  const { anchor } = makeWorld();
  assert.throws(
    () => new A2AVerifier({ anchor, revocationCheck: false }),
    /audience/,
  );
});

// -- Fresh vs replayed (Python: a2a_fresh_headers_are_each_admitted) --------------------

test('distinct fresh headers are each admitted under replay protection', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  // Two DIFFERENT headers (fresh nonce each): the guard must block reuse, not traffic.
  for (let i = 0; i < 2; i++) {
    const header = bind(token, vc, agent, 'tool:search', { call: i });
    const d = await verifier.authorize(header, 'tool:search', { call: i }, DECLARED);
    assert.equal(d.allowed, true, `fresh header ${i} must be admitted: ${d.code} ${d.reason}`);
  }
});

// -- Wrong anchor (Python: a2a_wrong_anchor_rejected) -----------------------------------

test('a header from a different organisation is rejected by a single-anchor verifier', async () => {
  const { agent, vc, token } = makeWorld();
  const stranger = ac.TrustAnchor.generate();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor: stranger });
  const header = bind(token, vc, agent, 'tool:search', {});
  const d = await verifier.authorize(header, 'tool:search', {}, DECLARED);
  assert.equal(d.allowed, false, 'a foreign issuer must not verify against this anchor');
});

// -- OBO guards (Python: a2a_obo_requires_resolver, a2a_obo_denies_unverifiable_...) ----

test('authorizeObo without a principalResolver throws', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const header = bind(token, vc, agent, 'tool:search', {});
  await assert.rejects(
    () => verifier.authorizeObo(header, 'not-a-token', 'tool:search', {}),
    /principalResolver/,
  );
});

test('an unverifiable principal token is denied, not ignored', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({
    revocationCheck: false,
    audience: RECEIVER,
    anchor,
    // The resolver CONTRACT is: return null for an unverifiable token (the shipped
    // `principalResolverFromOidc` catches validation failures and returns null).
    // A throwing resolver is a programming error and propagates - so this test uses
    // the contract's shape, and pins that null DENIES rather than skipping the check.
    principalResolver: async () => null,
  });
  const header = bind(token, vc, agent, 'tool:search', {});
  const d = await verifier.authorizeObo(header, 'garbage.jwt.value', 'tool:search', {}, DECLARED);
  assert.equal(d.allowed, false, 'an unverifiable principal must deny the call');
});

// -- Envelope handling (Python: envelope_non_obo_round_trip,
// envelope_missing_capability_header, envelope_header_lookup_is_case_insensitive) -------

test('a non-OBO envelope round-trips through authorizeEnvelope', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const action = new ac.Action('tool:search', jcsCanonicalizeArgs({ q: 'x' }));
  const headers = makeA2AEnvelope(token, vc, agent, {
    audience: RECEIVER, action, canonicalizationProfile: JCS_PROFILE,
  });
  const d = await verifier.authorizeEnvelope(headers, 'tool:search', { q: 'x' });
  assert.equal(d.allowed, true, `${d.code}: ${d.reason}`);
});

test('an envelope without the capability header is denied as malformed', async () => {
  const { anchor } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const d = await verifier.authorizeEnvelope({ 'x-unrelated': '1' }, 'tool:search', {});
  assert.equal(d.allowed, false);
  assert.equal(d.code, CODES.MALFORMED);
});

test('envelope header lookup is case-insensitive', async () => {
  // HTTP header names are case-insensitive on the wire; a verifier that only matched
  // the canonical casing would deny every call routed through a lowercasing proxy.
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const action = new ac.Action('tool:search', jcsCanonicalizeArgs({}));
  const headers = makeA2AEnvelope(token, vc, agent, {
    audience: RECEIVER, action, canonicalizationProfile: JCS_PROFILE,
  });
  const lowered = {};
  for (const [k, v] of Object.entries(headers)) lowered[k.toLowerCase()] = v;
  assert.notEqual(A2A_HEADER_NAME, A2A_HEADER_NAME.toLowerCase(), 'test premise: canonical name is mixed-case');
  const d = await verifier.authorizeEnvelope(lowered, 'tool:search', {});
  assert.equal(d.allowed, true, `lowercased headers must still verify: ${d.code} ${d.reason}`);
});

// -- Principal header validation (Python: parse_principal_header_rejects_bad_scheme) ----

test('parseA2APrincipalHeader rejects a wrong scheme and round-trips a right one', () => {
  assert.throws(() => parseA2APrincipalHeader('SomeOtherScheme/1.0 abc'), /scheme|Principal/i);
  const value = makeA2APrincipalHeader('the.principal.jwt');
  assert.equal(parseA2APrincipalHeader(value), 'the.principal.jwt');
});

// -- The in-memory replay guard's own contract (Python: in_memory_replay_guard_unit,
// in_memory_replay_guard_ttl_zero_never_blocks) -----------------------------------------

test('InMemoryReplayGuard: first sight passes, second is a replay, ttl 0 never blocks', () => {
  const guard = new InMemoryReplayGuard();
  assert.equal(guard.recordIfNew('sig-1'), true, 'first sight is not a replay');
  assert.equal(guard.recordIfNew('sig-1'), false, 'second sight is');
  assert.equal(guard.recordIfNew('sig-2'), true, 'unrelated signatures unaffected');
  // ttlSecs 0: every recorded entry is already expired, so nothing is ever blocked -
  // the way to neuter the guard without swapping it out.
  const off = new InMemoryReplayGuard({ ttlSecs: 0 });
  assert.equal(off.recordIfNew('sig-3'), true);
  assert.equal(off.recordIfNew('sig-3'), true, 'ttl 0 must never block');
});

// -- classifyError: the deny-code taxonomy ----------------------------------------------

test('classifyError maps core error kinds onto the wire codes', () => {
  // A misclassification here turns a cryptographic failure into something a client
  // might treat as retryable, so the mapping is a contract, not a convenience.
  const cases = [
    ['ProofOfPossessionError: sig mismatch', CODES.POSSESSION],
    ['PrincipalMismatchError: wrong human', CODES.PRINCIPAL],
    ['ActionDeniedError: tool not granted', CODES.NOT_AUTHORIZED],
    ['ScopeWideningError: nice try', CODES.NOT_AUTHORIZED],
    ['TokenExpiredError: too late', CODES.CREDENTIAL],
    ['CredentialRevokedError: gone', CODES.CREDENTIAL],
    ['DelegationError: broken chain', CODES.CREDENTIAL],
    ['something nobody anticipated', CODES.DENIED],
  ];
  for (const [message, expected] of cases) {
    assert.equal(classifyError(new Error(message)), expected, message);
  }
});

// -- Bound-args header round trip + size ceiling ----------------------------------------

test('bound-args header round-trips, and the size ceiling is enforced on parse', () => {
  const bound = octetsBindArgs({ q: 'café', n: 1 });
  const header = makeA2ABoundArgsHeader(bound);
  assert.equal(parseA2ABoundArgsHeader(header), bound, 'byte-identical round trip');

  // The ceiling is enforced where the VERIFIER consumes the bytes (`parseBoundArgs`),
  // not in the header codec - the codec is a transparent transport, and the reader is
  // the party that must not be handed an allocation of the sender's choosing.
  const huge = octetsBindArgs({ blob: 'x'.repeat(MAX_BOUND_ARGS_BYTES + 1024) });
  assert.throws(() => parseBoundArgs(huge), /over the .*-byte limit/);
  // And the codec really is transparent for oversized payloads.
  assert.equal(parseA2ABoundArgsHeader(makeA2ABoundArgsHeader(huge)), huge);
});
