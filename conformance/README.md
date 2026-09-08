# Cross-language conformance vectors

The AgentCreds offline core is implemented once in Rust (`agentcreds-core`) and
exposed to other languages through thin bindings (`agentcreds-node`, `agentcreds-py`).
A binding is only useful if it produces and consumes **byte-compatible** artifacts and
reaches the **same** authorization decisions as the core. These vectors prove it.

## What's here

- **`vectors.json`** - golden artifacts produced by the Rust core: a capability
  credential (JSON), a delegation token (CBOR), a full presentation (token +
  credential + proof-of-possession, CBOR), and a revocation status list (JSON). Each
  case carries the anchor/action a consumer must check and the expected `accept` /
  `reject` outcome.

  **Credentials** are minted a century out. **Tokens are not, and cannot be** -
  `max_token_ttl_secs` caps them at one hour (L0), which is a security control the
  vectors do not opt out of. The file therefore carries `evaluated_at`, and every
  consumer must verify **as of** that instant (`verify_rooted_at`, `verifyRootedAt`,
  `Presentation::verify_at`) rather than the wall clock. A wall-clock consumer fails
  every accept case and passes every reject case for the wrong reason once the file is
  an hour old - which is exactly what the public runner did until 2026-09-05.

- **`jcs_vectors.json`** - the canonicalization suite: 16 cases pairing a JSON value
  with the exact RFC 8785 canonical string every runtime must emit for it. Profile
  `agentcreds-jcs-v1`, versioned independently of `vectors.json`. Generated from
  `agentcreds-runtime/tests/test_jcs_canonicalization.py` (`VECTORS`) - regenerate
  there, not here. Asserted by `agentcreds-core/tests/jcs_conformance.rs` and
  `agentcreds-runtime/tests/test_jcs_conformance.py`.

  It exists because `vectors.json` structurally cannot catch canonicalization skew:
  actions are bound to canonicalized arguments, so two runtimes that canonicalize
  differently compute different digests for the same call and disagree about
  authorization while passing every delegation case.

- **Generator** - `agentcreds-core/examples/gen_conformance_vectors.rs`. Regenerate
  (only when a wire format changes) with:

  ```bash
  cargo run -p agentcreds-core --example gen_conformance_vectors -- conformance/vectors.json
  ```

  Keys are random per run, so regenerating rewrites the artifacts; that's expected -
  they are golden *inputs*, not a fixed byte snapshot.

## Who consumes them

Every binding ships a conformance test that loads `vectors.json`, deserializes each
artifact through its own FFI surface, verifies it, and asserts the outcome matches:

| binding          | test                                             | run |
| ---------------- | ------------------------------------------------ | --- |
| `agentcreds-node` | `test/conformance.test.js`                       | `npm run test:conformance` |
| `agentcreds-py`   | `tests/test_conformance.py`                       | `python tests/test_conformance.py` |

A binding that lags the core on a format change fails immediately here - for example,
a build predating the W3C->OAuth status-list change rejects the current revocation
vector. That is the harness working as intended.

## Coverage

Each case exercises a distinct wire form and decision:

| case | artifact / wire form | asserts |
| ---- | -------------------- | ------- |
| `presentation_accept` / `_reject_denied_tool` / `_reject_wrong_anchor` | Presentation (CBOR) + challenge (CBOR) | full token+credential+PoP check; scope denial; wrong-anchor rejection |
| `credential_accept` / `_reject_wrong_anchor` | Credential (JSON) | issuer-anchor signature check |
| `token_accept_permitted_action` / `_reject_denied_action` | Token (CBOR) + credential | anchor-rooted scope check |
| `revocation_lookup` | Status list (JSON) | signature + revoked/clear bit lookup |
