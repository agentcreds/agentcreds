// RFC 8785 canonicalization, asserted against the SHARED cross-language vectors.
//
// Argument binding hashes a string, so a Node holder and a Python enforcement point must
// emit byte-identical text from the same arguments or a legitimate call is refused as
// tampering. The previous profile (`agentcreds-json-sorted-v1`) was two independent
// readings of "sorted JSON"; measured on 2026-08-12 they disagreed on 9 of 18 ordinary
// cases - every non-ASCII string, and floats in four separate ways.
//
// ../../conformance/jcs_vectors.json is the contract, generated from the Python suite.
// Both runtimes assert against it, so drift fails on whichever side moved.

const test = require('node:test');
const assert = require('node:assert');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

// The fixture loop uses `jcsCanonicalize`, not `jcsCanonicalizeArgs`: the args helper
// deliberately short-circuits on a top-level string (already canonical) and on nullish
// (empty), so a scalar vector added later would pass through unwrapped and compare
// against the wrong thing. Rust and Python assert the same file through their general
// entry points; this keeps all three checking identically.
const { jcsCanonicalize, jcsCanonicalizeArgs, JCS_PROFILE } = require('../index.js');

const vectorsPath = join(__dirname, '..', '..', 'conformance', 'jcs_vectors.json');
const suite = JSON.parse(readFileSync(vectorsPath, 'utf8'));

test('profile identifier matches the shared vectors', () => {
  // The identifier travels on the wire; a silent change orphans every holder that
  // declares the old one.
  assert.strictEqual(JCS_PROFILE, suite.profile);
  assert.strictEqual(JCS_PROFILE, 'agentcreds-jcs-v1');
});

test('every shared vector canonicalizes to the same bytes as Rust and Python', () => {
  assert.ok(suite.cases.length > 0, 'vectors file is empty');
  for (const c of suite.cases) {
    assert.strictEqual(
      jcsCanonicalize(c.value),
      c.expected_jcs,
      `diverged from the shared vector for ${JSON.stringify(c.value)}`,
    );
  }
});

test('non-ASCII is literal, not escaped', () => {
  // The single biggest divergence in the old profile: Python escaped every non-ASCII
  // character, JSON.stringify emits literal UTF-8. RFC 8785 requires literal.
  const out = jcsCanonicalizeArgs({ q: 'café' });
  assert.ok(!out.includes('\\u'), out);
  assert.ok(out.includes('café'), out);
});

test('numbers follow ECMAScript Number::toString', () => {
  // Python and JS agree on the digits but not the format, and switch to exponential
  // notation at different magnitudes. RFC 8785 picks the JavaScript rules, so these are
  // the cases a Python port has to be held to.
  const cases = [
    [{ a: 1.0 }, '{"a":1}'],
    [{ a: 1e20 }, '{"a":100000000000000000000}'],
    [{ a: 1e21 }, '{"a":1e+21}'],
    [{ a: 1e-6 }, '{"a":0.000001}'],
    [{ a: 1e-7 }, '{"a":1e-7}'],
    [{ a: -0 }, '{"a":0}'],
  ];
  for (const [value, expected] of cases) {
    assert.strictEqual(jcsCanonicalizeArgs(value), expected, JSON.stringify(value));
  }
});

test('keys sort by UTF-16 code unit', () => {
  // The orderings differ only above the BMP: a surrogate pair begins 0xD800-0xDBFF and
  // so sorts BELOW U+E000-U+FFFF by code unit, and above it by code point.
  const out = jcsCanonicalizeArgs({ '\u{1f511}': 'non-BMP', '': 'private use' });
  assert.ok(out.indexOf('\u{1f511}') < out.indexOf(''), out);
});

test('values JSON cannot represent are refused, not guessed', () => {
  // Emitting `null` (JSON.stringify's behaviour for undefined in an object) would
  // produce a string the other side cannot reproduce - tampering on a clean request.
  assert.throws(() => jcsCanonicalizeArgs({ a: undefined }), TypeError);
  assert.throws(() => jcsCanonicalizeArgs({ a: NaN }), TypeError);
  assert.throws(() => jcsCanonicalizeArgs({ a: Infinity }), TypeError);
  assert.throws(() => jcsCanonicalizeArgs({ a: () => 1 }), TypeError);
});

test('strings and nullish pass through', () => {
  assert.strictEqual(jcsCanonicalizeArgs(null), '');
  assert.strictEqual(jcsCanonicalizeArgs(undefined), '');
  assert.strictEqual(jcsCanonicalizeArgs('already canonical'), 'already canonical');
});

// -- Precision hazards (2^53) ----------------------------------------------------
//
// JavaScript is the side that LOSES here: JSON.parse turned the literal into a double
// before canonicalization ever ran, so this cannot be corrected - only reported. A Rust
// or Python holder canonicalizes the exact integer and the binding mismatches on a
// request nobody tampered with.

// `process.emitWarning` dispatches on the next tick, which makes this fiddly in two
// ways. The listener has to stay attached across a turn of the loop, or it captures
// nothing and every "stays quiet" assertion passes vacuously. And the queue has to be
// drained BEFORE attaching, or warnings from an earlier synchronous test - the shared
// fixture canonicalizes 1e20 and 1e21, which are integral-and-unsafe in JS - land in
// this window and get counted here.
async function captureWarnings(fn) {
  await new Promise((r) => setImmediate(r));
  const seen = [];
  const listener = (w) => seen.push(w);
  process.on('warning', listener);
  try {
    fn();
    await new Promise((r) => setImmediate(r));
  } finally {
    process.removeListener('warning', listener);
  }
  return seen.filter((w) => w.name === 'AgentCredsJcsPrecisionWarning');
}

test('an integer past 2^53 warns, and still canonicalizes', async () => {
  const warnings = await captureWarnings(() => {
    // Already damaged by the parser - asserting the damaged value is the honest test.
    assert.strictEqual(jcsCanonicalizeArgs({ id: 9007199254740993 }), '{"id":9007199254740992}');
  });
  assert.strictEqual(warnings.length, 1, 'expected exactly one precision warning');
  assert.match(warnings[0].message, /Carry large identifiers as strings/);
});

test('the safe boundary is inclusive and ordinary values stay quiet', async () => {
  const warnings = await captureWarnings(() => {
    assert.strictEqual(jcsCanonicalizeArgs({ n: 9007199254740991 }), '{"n":9007199254740991}');
    assert.strictEqual(jcsCanonicalizeArgs({ n: 1.5 }), '{"n":1.5}');
    assert.strictEqual(jcsCanonicalizeArgs({ id: '9007199254740993' }), '{"id":"9007199254740993"}');
  });
  assert.deepStrictEqual(warnings, []);
});

test('the warning is one per canonicalization, not one per process', async () => {
  // Deduping across calls would make this order-dependent and would hide a hazard that
  // is present on every request.
  const first = await captureWarnings(() => jcsCanonicalizeArgs({ a: 9007199254740994 }));
  const second = await captureWarnings(() => jcsCanonicalizeArgs({ a: 9007199254740994 }));
  assert.strictEqual(first.length, 1);
  assert.strictEqual(second.length, 1, 'a later call must warn again');
});

test('two hazards in one call warn once, not twice', async () => {
  const warnings = await captureWarnings(() =>
    jcsCanonicalizeArgs({ a: 9007199254740994, b: 9007199254740996 }));
  assert.strictEqual(
    warnings.length,
    1,
    'the per-call cap keeps the authorization path from flooding the log',
  );
});
