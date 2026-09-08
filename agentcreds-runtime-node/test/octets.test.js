'use strict';

// The carry-the-octets binding profile (`agentcreds-octets-v1`).
//
// Canonicalization is a workaround for not having the original octets, and every bug it
// has produced comes from two implementations disagreeing about how to WRITE a value.
// This profile carries the holder's bytes, so the verifier checks the proof over exactly
// what was signed and then compares meanings rather than spellings.
//
// The load-bearing case is 'a serialization no canonicalizer would ever emit': if a
// holder can serialize perversely and still verify, no agreement about serialization is
// required, which is the entire claim.

const { test } = require('node:test');
const assert = require('node:assert');

const ac = require('@agentcreds/sdk');
const {
  CODES,
  A2AVerifier,
  makeA2AHeader,
  makeA2AEnvelope,
  jcsCanonicalizeArgs,
  octetsBindArgs,
  parseBoundArgs,
  semanticEq,
  OCTETS_PROFILE,
  JCS_PROFILE,
  MAX_BOUND_ARGS_BYTES,
  A2A_BOUND_ARGS_HEADER_NAME,
} = require('..');

const RECEIVER = 'a2a://orders.example/agent';
const TOOL = 'tool:search';

function makeWorld(tools = [TOOL]) {
  const anchor = ac.TrustAnchor.generate();
  const agent = ac.AgentIdentity.createDidKey();
  const claims = new ac.CapabilityClaims({ tools, maxDelegationDepth: 1, validForSecs: 3600 });
  const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, null);
  const token = ac.DelegationToken.mint(vc, new ac.Scope({ tools, budgetUsd: 100, maxDepth: 1 }), 300, agent);
  return { anchor, agent, vc, token };
}

function octetsVerifier(anchor) {
  return new A2AVerifier({ revocationCheck: false,
    audience: RECEIVER,
    anchor,
    canonicalizationProfile: OCTETS_PROFILE,
    requireArgumentBinding: true,
  });
}

// Sign over `signedOctets`, deliver `delivered`, carry `carried` (default: the signed
// bytes). Moving exactly one of the three is what separates "the arguments changed"
// from "the carried copy changed".
function headerFor(world, signedOctets) {
  const action = new ac.Action(TOOL, signedOctets);
  return makeA2AHeader(world.token, world.vc, world.agent, { audience: RECEIVER, action });
}

// -- semanticEq: the rules the profile rests on --------------------------------

test('semanticEq ignores spelling but not meaning', () => {
  assert.ok(semanticEq({ a: 1, b: 2 }, { b: 2, a: 1 }), 'key order is not meaning');
  assert.ok(!semanticEq([1, 2], [2, 1]), 'array order IS meaning');
  assert.ok(semanticEq({ n: 1 }, { n: 1.0 }), 'JS has one number type');
  assert.ok(!semanticEq({ n: 1 }, { n: 2 }));
  assert.ok(!semanticEq({ n: 1 }, { n: '1' }), 'number is not string');
  assert.ok(!semanticEq({ a: 1 }, { a: 1, b: 2 }), 'extra key');
  assert.ok(!semanticEq(null, 0));
  assert.ok(!semanticEq({ admin: true }, { admin: 1 }));
});

test('semanticEq does not treat a missing key as an undefined one', () => {
  // `{a: undefined}` and `{}` have different key sets. JSON cannot express the former,
  // so treating them as equal would let a delivered object carry a key the holder never
  // signed.
  assert.ok(!semanticEq({ a: undefined }, {}));
});

test('parseBoundArgs refuses what it cannot safely accept', () => {
  assert.throws(() => parseBoundArgs(null), /no bound arguments/);
  assert.throws(() => parseBoundArgs(''), /no bound arguments/);
  assert.throws(() => parseBoundArgs('{not json'));
  assert.throws(
    () => parseBoundArgs(JSON.stringify({ blob: 'x'.repeat(MAX_BOUND_ARGS_BYTES + 100) })),
    /over the/,
  );
  // JSON.parse already rejects these, unlike Python's json.
  assert.throws(() => parseBoundArgs('{"n": NaN}'));
});

// -- End to end ---------------------------------------------------------------

test('a serialization no canonicalizer would ever emit', async () => {
  // Indentation, unsorted keys, literal UTF-8: output no canonicalizer produces and no
  // verifier could guess. It verifies anyway, because the verifier never re-serializes.
  const world = makeWorld();
  const args = { q: 'café', amount: 1.0, zeta: [1, 2], alpha: null };
  const perverse = JSON.stringify(args, null, 4);
  assert.notStrictEqual(perverse, jcsCanonicalizeArgs(args), 'fixture must not be accidentally canonical');

  const decision = await octetsVerifier(world.anchor)
    .authorize(headerFor(world, perverse), TOOL, args, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: perverse });
  assert.ok(decision.allowed, decision.reason);
});

test('the same call under JCS needs the canonical form and only that', async () => {
  // The contrast that makes the case above meaningful: under a canonicalizing profile
  // the holder has no freedom, and a request nobody tampered with is refused.
  const world = makeWorld();
  const args = { q: 'café', amount: 1.0 };
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor: world.anchor, requireArgumentBinding: true });
  const decision = await verifier.authorize(headerFor(world, JSON.stringify(args, null, 4)), TOOL, args, { canonicalizationProfile: JCS_PROFILE });
  assert.ok(!decision.allowed);
  assert.strictEqual(decision.code, CODES.POSSESSION);
});

test('altering the delivered arguments is named for what it is', async () => {
  const world = makeWorld();
  const signed = octetsBindArgs({ amount: 10, to: 'alice' });
  const decision = await octetsVerifier(world.anchor).authorize(
    headerFor(world, signed), TOOL, { amount: 1000000, to: 'mallory' }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: signed },
  );
  assert.ok(!decision.allowed);
  assert.strictEqual(decision.code, CODES.ARGS_MISMATCH);
});

test('altering the carried copy breaks the proof instead', async () => {
  // The carried octets are not a free-text side channel: rewriting them to match
  // tampered arguments does not help, because the proof covered the originals.
  const world = makeWorld();
  const signed = octetsBindArgs({ amount: 10 });
  const forged = octetsBindArgs({ amount: 1000000 });
  const decision = await octetsVerifier(world.anchor).authorize(
    headerFor(world, signed), TOOL, { amount: 1000000 }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: forged },
  );
  assert.ok(!decision.allowed);
  assert.strictEqual(decision.code, CODES.POSSESSION);
});

test('the profile requires the carried copy', async () => {
  const world = makeWorld();
  const signed = octetsBindArgs({ amount: 10 });
  const decision = await octetsVerifier(world.anchor)
    .authorize(headerFor(world, signed), TOOL, { amount: 10 }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: null });
  assert.ok(!decision.allowed);
  assert.strictEqual(decision.code, CODES.BOUND_ARGS);
});

test('an oversized carried copy is refused before any crypto', async () => {
  const world = makeWorld();
  const signed = octetsBindArgs({ amount: 10 });
  const huge = JSON.stringify({ x: 'y'.repeat(MAX_BOUND_ARGS_BYTES + 10) });
  const decision = await octetsVerifier(world.anchor)
    .authorize(headerFor(world, signed), TOOL, { amount: 10 }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: huge });
  assert.ok(!decision.allowed);
  assert.strictEqual(decision.code, CODES.BOUND_ARGS);
});

test('key order and number spelling do not have to match', async () => {
  const world = makeWorld();
  const signed = '{"b":2,"a":1.0}';   // the holder's spelling
  const decision = await octetsVerifier(world.anchor)
    .authorize(headerFor(world, signed), TOOL, { a: 1, b: 2 }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: signed });
  assert.ok(decision.allowed, decision.reason);
});

test('the envelope carries the bound arguments end to end', async () => {
  const world = makeWorld();
  const args = { q: 'café', n: 1.0 };
  const signed = JSON.stringify(args, null, 2);
  const action = new ac.Action(TOOL, signed);
  const envelope = makeA2AEnvelope(world.token, world.vc, world.agent, {
    audience: RECEIVER, action, boundArguments: signed, canonicalizationProfile: OCTETS_PROFILE,
  });
  assert.ok(envelope[A2A_BOUND_ARGS_HEADER_NAME], 'envelope must carry the header');
  // Base64url, so argument text can never inject header syntax.
  assert.match(envelope[A2A_BOUND_ARGS_HEADER_NAME], /^[A-Za-z0-9_-]+$/);

  const decision = await octetsVerifier(world.anchor).authorizeEnvelope(envelope, TOOL, args);
  assert.ok(decision.allowed, decision.reason);
});

test('a tampered envelope call is still refused through the envelope path', async () => {
  const world = makeWorld();
  const signed = octetsBindArgs({ amount: 10 });
  const action = new ac.Action(TOOL, signed);
  const envelope = makeA2AEnvelope(world.token, world.vc, world.agent, {
    audience: RECEIVER, action, boundArguments: signed, canonicalizationProfile: OCTETS_PROFILE,
  });
  const decision = await octetsVerifier(world.anchor)
    .authorizeEnvelope(envelope, TOOL, { amount: 1000000 });
  assert.ok(!decision.allowed);
  assert.strictEqual(decision.code, CODES.ARGS_MISMATCH);
});

// -- The signed arguments, surfaced but never substituted ----------------------

test('an allow carries the arguments that were actually signed', async () => {
  // In JS there is no int/float distinction to demonstrate, so use key order: the
  // delivered object and the signed one are equivalent but not identical, and only the
  // signed copy preserves the holder's own view.
  const world = makeWorld();
  const signed = '{"b":2,"a":1}';
  const decision = await octetsVerifier(world.anchor)
    .authorize(headerFor(world, signed), TOOL, { a: 1, b: 2 }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: signed });
  assert.ok(decision.allowed, decision.reason);
  assert.deepStrictEqual(decision.boundArguments, { b: 2, a: 1 });
  assert.deepStrictEqual(Object.keys(decision.boundArguments), ['b', 'a'], 'the holder\'s order');
});

test('boundArguments is absent under a canonicalizing profile and on a denial', async () => {
  const world = makeWorld();
  const args = { amount: 10 };

  const jcsVerifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor: world.anchor });
  const allowed = await jcsVerifier.authorize(
    headerFor(world, jcsCanonicalizeArgs(args)), TOOL, args, { canonicalizationProfile: JCS_PROFILE });
  assert.ok(allowed.allowed, allowed.reason);
  assert.strictEqual(allowed.boundArguments, null, 'no carried copy exists under JCS');

  const signed = octetsBindArgs(args);
  const denied = await octetsVerifier(world.anchor)
    .authorize(headerFor(world, signed), TOOL, { amount: 999 }, { canonicalizationProfile: OCTETS_PROFILE, boundArguments: signed });
  assert.ok(!denied.allowed);
  assert.strictEqual(denied.boundArguments, null, 'a denial must not hand back arguments');
});

test('semanticEq reads each property once', async () => {
  // A getter that returns a different value on the second read could pass the
  // comparison and then hand the tool something else. Reading through Object.entries
  // takes one snapshot. (It cannot fix what the TOOL sees on ITS read - only authority
  // over the call can, which is why boundArguments exists.)
  let reads = 0;
  const shifty = { get amount() { reads += 1; return reads === 1 ? 10 : 999; } };
  assert.ok(semanticEq(shifty, { amount: 10 }));
  assert.strictEqual(reads, 1, 'the comparison must not read the property twice');
});
