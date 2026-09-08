'use strict';

// The shared A2A-layer agreement vectors, consumed from the Node side.
//
// `conformance/a2a_vectors.json` is the contract between the two runtimes for the
// A2A-specific layer above the cryptography. It is GENERATED from the Python runtime
// (agentcreds-runtime/tests/gen_a2a_vectors.py) - so a green run here means "Node agrees
// with the reference", the same relationship the core conformance vectors establish for
// the crypto layer. The Python consumer (test_a2a_conformance.py) is the regeneration
// guard on the other side.
//
// Octets bind OUTPUT is deliberately not asserted anywhere: the profile makes the
// serialization holder-chosen (Python ASCII-escapes, Node does not, both conformant).
// The contract pinned here is that this verifier PARSES either dialect and reaches the
// same semantic-equality verdict as Python.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const {
  CODES,
  A2A_HEADER_NAME,
  A2A_PRINCIPAL_HEADER_NAME,
  A2A_BOUND_ARGS_HEADER_NAME,
  A2A_CANON_PROFILE_HEADER_NAME,
  A2A_PRINCIPAL_SCHEME,
  makeA2APrincipalHeader,
  parseA2APrincipalHeader,
  makeA2ABoundArgsHeader,
  parseA2ABoundArgsHeader,
  parseBoundArgs,
  semanticEq,
  OCTETS_PROFILE,
  MAX_BOUND_ARGS_BYTES,
} = require('..');

const SUPPORTED_FORMAT = 1;
const DOC = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'conformance', 'a2a_vectors.json'), 'utf8'),
);
const CASES = DOC.cases;

// Python code names -> Node CODES keys. Same keys by construction; a rename on either
// side must show up here, not in production traffic.
const CODE_KEYS = Object.keys(CASES.codes);

test('vector format is supported', () => {
  assert.equal(DOC.format, SUPPORTED_FORMAT,
    `a2a_vectors.json is format ${DOC.format}; this consumer understands ${SUPPORTED_FORMAT}`);
});

test('header names and the principal scheme match the reference', () => {
  assert.equal(CASES.header_names.capability, A2A_HEADER_NAME);
  assert.equal(CASES.header_names.principal, A2A_PRINCIPAL_HEADER_NAME);
  assert.equal(CASES.header_names.bound_args, A2A_BOUND_ARGS_HEADER_NAME);
  assert.equal(CASES.header_names.canon_profile, A2A_CANON_PROFILE_HEADER_NAME);
  assert.equal(CASES.principal_scheme_prefix, A2A_PRINCIPAL_SCHEME);
});

test('the shared deny-code registry matches the reference', () => {
  for (const key of CODE_KEYS) {
    assert.equal(CODES[key], CASES.codes[key],
      `CODES.${key}: the code string is the wire contract with Python`);
  }
});

test('octets profile constants match', () => {
  assert.equal(CASES.octets_profile, OCTETS_PROFILE);
  assert.equal(CASES.max_bound_args_bytes, MAX_BOUND_ARGS_BYTES);
});

test('principal headers make and parse byte-identically to the reference', () => {
  for (const { token, header } of CASES.principal_headers) {
    assert.equal(makeA2APrincipalHeader(token), header, `make(${JSON.stringify(token)})`);
    assert.equal(parseA2APrincipalHeader(header), token, `parse round-trip`);
  }
});

test('malformed principal headers are rejected', () => {
  for (const value of CASES.malformed_principal_headers) {
    assert.throws(() => parseA2APrincipalHeader(value), undefined, JSON.stringify(value));
  }
});

test('bound-args headers make and parse byte-identically to the reference', () => {
  for (const { bound, header } of CASES.bound_args_headers) {
    assert.equal(makeA2ABoundArgsHeader(bound), header);
    assert.equal(parseA2ABoundArgsHeader(header), bound);
  }
});

test('octets parse + semantic equality agree with the reference verdicts', () => {
  for (const { bound, args, equal } of CASES.octets_parse_semantic) {
    const parsed = parseBoundArgs(bound);
    assert.equal(semanticEq(parsed, args), equal,
      `semanticEq(${bound}, ${JSON.stringify(args)}) must be ${equal}`);
  }
});
