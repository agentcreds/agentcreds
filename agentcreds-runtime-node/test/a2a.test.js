'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const ac = require('@agentcreds/sdk');
const {
  CODES,
  A2AVerifier,
  makeA2AHeader,
  makeA2AEnvelope,
  makeA2APrincipalHeader,
  parseA2APrincipalHeader,
  anchorResolverFromRegistry,
  revocationCheckFromList,
  principalResolverFromOidc,
  jcsCanonicalizeArgs,
  JCS_PROFILE,
} = require('..');

const RECEIVER = 'a2a://orders.example/agent';
const ISS = 'https://login.acme.com';
const AUD = 'agentcreds-prod';
const SUB = 'auth0|alice';

function makeWorld(tools = ['tool:search']) {
  const anchor = ac.TrustAnchor.generate();
  const agent = ac.AgentIdentity.createDidKey();
  const claims = new ac.CapabilityClaims({ tools, maxDelegationDepth: 1, validForSecs: 3600 });
  const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, null);
  const token = ac.DelegationToken.mint(vc, new ac.Scope({ tools, budgetUsd: 100, maxDepth: 1 }), 300, agent);
  return { anchor, agent, vc, token };
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

function forgeOidc(sub = SUB) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const header = b64u(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: 'k1' })));
  const payload = b64u(Buffer.from(JSON.stringify({
    iss: ISS, aud: AUD, sub, exp: Math.floor(Date.now() / 1000) + 3600,
  })));
  const signing = `${header}.${payload}`;
  const idToken = `${signing}.${b64u(crypto.sign(null, Buffer.from(signing), privateKey))}`;
  const jwks = JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: 'k1', use: 'sig', x: jwk.x }] });
  return { idToken, jwks };
}

function oboWorld(sub = SUB) {
  const anchor = ac.TrustAnchor.generate();
  const agent = ac.AgentIdentity.createDidKey();
  const human = ac.HumanIdentity.fromIdp(ISS, sub);
  const expires = new Date(Date.now() + 3600 * 1000);
  const auth = human.authorize(expires, ['tool:read_email'], ['mailbox:alice@acme.com/*']);
  const claims = new ac.CapabilityClaims({ tools: ['tool:read_email'], maxDelegationDepth: 2, validForSecs: 3600 });
  claims.setOnBehalfOf(auth);
  const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, null);
  const scope = new ac.Scope({ tools: ['tool:read_email'], maxDepth: 1 }).withResources(['mailbox:alice@acme.com/42']);
  const token = ac.DelegationToken.mint(vc, scope, 300, agent);
  return { anchor, agent, human, vc, token };
}

// Verifiers require a bound presentation by default (matching Python), so a test that
// is about something else - audience, scope, revocation - still has to bind the call it
// makes, or it is denied before reaching the property under test. These two helpers keep
// that plumbing from drowning out the assertion, and mean the tests exercise the posture
// that actually ships rather than a laxer one.
function bind(token, vc, agent, tool, args, extra = {}) {
  const action = new ac.Action(tool, jcsCanonicalizeArgs(args));
  return makeA2AHeader(token, vc, agent, { audience: RECEIVER, action, ...extra });
}
const DECLARED = { canonicalizationProfile: JCS_PROFILE };

test('A2A happy path', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const header = bind(token, vc, agent, 'tool:search', { q: 'x' });
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const d = await verifier.authorize(header, 'tool:search', { q: 'x' }, DECLARED);
  assert.equal(d.allowed, true);
  assert.equal(d.chain[0].agentDid, agent.did);
});

test('wrong audience is rejected', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const action = new ac.Action('tool:search', jcsCanonicalizeArgs({}));
  const header = makeA2AHeader(token, vc, agent, { audience: 'a2a://other.example/agent', action });
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  // Declared, so the refusal is the audience mismatch under test and not a missing
  // profile declaration - which is refused first, and for a different reason.
  const d = await verifier.authorize(header, 'tool:search', {}, DECLARED);
  assert.equal(d.code, CODES.POSSESSION);
});

test('tool not in scope is rejected', async () => {
  const { anchor, agent, vc, token } = makeWorld(['tool:search']);
  const header = bind(token, vc, agent, 'tool:admin', {});
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const d = await verifier.authorize(header, 'tool:admin', {}, DECLARED);
  assert.equal(d.code, CODES.NOT_AUTHORIZED);
});

test('malformed header is rejected', async () => {
  const { anchor } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const d = await verifier.authorize('not-a-header', 'tool:search', {});
  assert.equal(d.code, CODES.MALFORMED);
});

test('replay protection is on by default', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor });
  const header = bind(token, vc, agent, 'tool:search', {});
  assert.equal((await verifier.authorize(header, 'tool:search', {}, DECLARED)).allowed, true);
  assert.equal((await verifier.authorize(header, 'tool:search', {}, DECLARED)).code, CODES.REPLAY);
});

test('replay protection can be disabled', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor, enableReplayProtection: false });
  const header = bind(token, vc, agent, 'tool:search', {});
  assert.equal((await verifier.authorize(header, 'tool:search', {}, DECLARED)).allowed, true);
  assert.equal((await verifier.authorize(header, 'tool:search', {}, DECLARED)).allowed, true);
});

test('multi-issuer: registered accepted, unregistered rejected', async () => {
  const a = makeWorld();
  const b = makeWorld();
  const registry = new ac.TrustRegistry();
  registry.minimumTrustLevel = 'verified';
  registry.register(new ac.TrustEntry(a.anchor.did, 'Org A', a.anchor.publicKey, 'verified'));

  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchorFor: anchorResolverFromRegistry(registry) });
  const ha = bind(a.token, a.vc, a.agent, 'tool:search', {});
  assert.equal((await verifier.authorize(ha, 'tool:search', {}, DECLARED)).allowed, true);
  const hb = bind(b.token, b.vc, b.agent, 'tool:search', {});
  assert.equal((await verifier.authorize(hb, 'tool:search', {}, DECLARED)).code, CODES.UNTRUSTED_ISSUER);
});

test('revoked credential is rejected', async () => {
  const anchor = ac.TrustAnchor.generate();
  const agent = ac.AgentIdentity.createDidKey();
  const listUrl = 'https://issuer.example/revocation/1';
  const revList = new ac.RevocationList(listUrl, anchor, 1024);
  const status = new ac.CredentialStatus(listUrl, 7);
  const claims = new ac.CapabilityClaims({ tools: ['tool:search'], maxDelegationDepth: 1, validForSecs: 3600 });
  const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, status);
  const token = ac.DelegationToken.mint(vc, new ac.Scope({ tools: ['tool:search'], maxDepth: 1 }), 300, agent);

  const verifier = new A2AVerifier({ audience: RECEIVER, anchor, revocationCheck: revocationCheckFromList(revList, anchor) });
  assert.equal((await verifier.authorize(bind(token, vc, agent, 'tool:search', {}), 'tool:search', {}, DECLARED)).allowed, true);
  revList.revoke(7, anchor);
  assert.equal((await verifier.authorize(bind(token, vc, agent, 'tool:search', {}), 'tool:search', {}, DECLARED)).code, CODES.REVOKED);
});

test('argument binding: match allowed, tamper rejected', async () => {
  const { anchor, agent, vc, token } = makeWorld(['tool:transfer']);
  const action = new ac.Action('tool:transfer', jcsCanonicalizeArgs({ amount: 10 }));
  const header = makeA2AHeader(token, vc, agent, { audience: RECEIVER, action });
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor, requireArgumentBinding: true });
  const opts = { canonicalizationProfile: JCS_PROFILE };
  assert.equal((await verifier.authorize(header, 'tool:transfer', { amount: 10 }, opts)).allowed, true);
  assert.equal((await verifier.authorize(header, 'tool:transfer', { amount: 1000000 }, opts)).code, CODES.POSSESSION);
});

test('require argument binding rejects unbound header', async () => {
  const { anchor, agent, vc, token } = makeWorld();
  const header = makeA2AHeader(token, vc, agent, { audience: RECEIVER });
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor, requireArgumentBinding: true });
  assert.equal((await verifier.authorize(header, 'tool:search', {})).code, CODES.UNBOUND);
});

test('principal header round-trip', () => {
  const tok = 'eyJ.payload.sig';
  assert.equal(parseA2APrincipalHeader(makeA2APrincipalHeader(tok)), tok);
});

test('OBO envelope allows the verified human', async () => {
  const { anchor, agent, vc, token } = oboWorld();
  const { idToken, jwks } = forgeOidc();
  const provider = new ac.OidcProvider(ISS, AUD);
  provider.addKeysFromJwks(jwks);
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor, principalResolver: principalResolverFromOidc(provider) });

  // The resource is part of the binding digest, so an action bound without it does
  // not match a call made with it.
  const action = new ac.Action('tool:read_email', jcsCanonicalizeArgs({}))
    .withResource('mailbox:alice@acme.com/42');
  const envelope = makeA2AEnvelope(token, vc, agent, {
    audience: RECEIVER, principalToken: idToken, action, canonicalizationProfile: JCS_PROFILE,
  });
  const d = await verifier.authorizeEnvelope(envelope, 'tool:read_email', {}, { resource: 'mailbox:alice@acme.com/42' });
  assert.equal(d.allowed, true);
});

test('OBO envelope confused-deputy is rejected', async () => {
  const { anchor, agent, vc, token } = oboWorld('auth0|alice');
  const { idToken: bobToken, jwks } = forgeOidc('auth0|bob');
  const provider = new ac.OidcProvider(ISS, AUD);
  provider.addKeysFromJwks(jwks);
  const verifier = new A2AVerifier({ revocationCheck: false, audience: RECEIVER, anchor, principalResolver: principalResolverFromOidc(provider) });

  const action = new ac.Action('tool:read_email', jcsCanonicalizeArgs({}));
  const envelope = makeA2AEnvelope(token, vc, agent, {
    audience: RECEIVER, principalToken: bobToken, action, canonicalizationProfile: JCS_PROFILE,
  });
  const d = await verifier.authorizeEnvelope(envelope, 'tool:read_email', {}, { resource: 'mailbox:alice@acme.com/42' });
  assert.equal(d.code, CODES.PRINCIPAL);
});

test('a verifier must state its revocation posture', () => {
  // No default is possible: a revocation source cannot be invented the way an
  // in-process approval ledger can. Silence used to mean "accept every revoked
  // credential", so both postures have to be typed out.
  const { anchor } = makeWorld();
  assert.throws(() => new A2AVerifier({ audience: RECEIVER, anchor }), /revocationCheck/);
  // `false` is the explicit opt-out, and it builds.
  assert.ok(new A2AVerifier({ audience: RECEIVER, anchor, revocationCheck: false }));
});
