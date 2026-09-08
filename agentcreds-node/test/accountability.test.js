// Node/Python parity for the accountability surface.
//
// Every conformance script under deploy/local-harness is Python, so "conformance
// passes" has meant "passes for the Python binding". These assert the Node binding
// can do the two things a PEP must: RECORD who is accountable on a decision (not
// merely read it back), and compute a party commitment a Python issuer would
// recognize. A commitment that disagreed across bindings would make a Node verifier
// unable to check a credential a Python control plane stamped - and the disagreement
// would look like a tampered record rather than a binding mismatch.

const test = require('node:test');
const assert = require('node:assert');
const ac = require('../index.js');

const SALT = '0123456789abcdef0123';
const MEMBERS = ['alice@acme.example', 'bob@acme.example'];

test('ownership commitment is order-independent and salt-bound', () => {
  const a = new ac.OwnershipRecord('team:payments', 7, MEMBERS, SALT);
  const b = new ac.OwnershipRecord('team:payments', 7, [...MEMBERS].reverse(), SALT);
  assert.strictEqual(a.commitment, b.commitment, 'store order changed the commitment');
  assert.ok(a.matches(a.commitment));

  const other = new ac.OwnershipRecord('team:payments', 7, MEMBERS, 'fedcba9876543210fedc');
  assert.notStrictEqual(a.commitment, other.commitment, 'the salt does not bind');

  // A short salt makes the commitment brute-forceable from a candidate membership
  // list - the exact data it exists to keep out of the credential.
  assert.throws(() => new ac.OwnershipRecord('team:x', 1, [], 'tooshort'));
});

test('ownership commitment agrees with the Python binding', () => {
  // Pinned literal, not a cross-process call: this is the value both bindings must
  // produce for the same record. If a change moves it, every previously stamped
  // credential becomes unverifiable and this test says so.
  const rec = new ac.OwnershipRecord('team:demo-platform', 7, MEMBERS, SALT);
  assert.strictEqual(
    rec.commitment,
    '24f72a4e14fd7cd07a831f28e210966d979353aeb7b9ed81869a11cefa6e4333',
  );
});

test('a Node verifier can record accountability on a decision', () => {
  const rec = new ac.OwnershipRecord('team:payments-platform', 7, MEMBERS, SALT);
  const d = ac.AuthzDecision.allow('presentation', 'did:key:zSubject')
    .withAccountability('team:payments-platform', 'policy', 7, rec.commitment);

  assert.strictEqual(d.accountableParty, 'team:payments-platform');
  assert.strictEqual(d.accountabilitySource, 'policy');
  assert.strictEqual(d.partyVersion, 7);
  assert.strictEqual(d.partyCommitment, rec.commitment);
});

test('evaluation and admission are recorded separately', () => {
  // evaluation=allow with admission=deny is a replay: valid, policy-satisfying
  // evidence refused because its reliance unit was already spent. A single verdict
  // field reports that identically to evidence that never verified.
  const d = ac.AuthzDecision.allow('presentation', 'did:key:zSubject')
    .withVerdicts('allow', 'deny');
  assert.strictEqual(d.evaluation, 'allow');
  assert.strictEqual(d.admission, 'deny');

  // Rejected rather than defaulted: a typo read as "allow" would record an
  // admission that never happened.
  assert.throws(() => ac.AuthzDecision.allow('presentation', 'did:key:zS')
    .withVerdicts('maybe', null));
});

test('the record digest covers the accountability fields', () => {
  // Outside the hash, a stored log could be rewritten on exactly the fields an
  // audit reads and still verify against a signed checkpoint.
  const bare = ac.AuthzDecision.allow('presentation', 'did:key:zSubject');
  const party = bare.withAccountability('team:payments', 'policy', null, null);
  const versioned = bare.withAccountability('team:payments', 'policy', 7, null);
  const replay = bare.withVerdicts('allow', 'deny');
  const badEvidence = bare.withVerdicts('deny', 'deny');

  assert.notStrictEqual(bare.digestHex(), party.digestHex(), 'party unprotected');
  assert.notStrictEqual(party.digestHex(), versioned.digestHex(), 'version unprotected');
  assert.notStrictEqual(bare.digestHex(), replay.digestHex(), 'verdicts unprotected');
  assert.notStrictEqual(
    replay.digestHex(), badEvidence.digestHex(),
    'a replay can be rewritten as an evidence failure',
  );
});
