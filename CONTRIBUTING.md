# Contributing to AgentCreds

Thanks for contributing. This guide covers the repository layout, how to build
and test each package, and the conventions the codebase follows.

## Repository layout

```
agentcreds-core/          Rust core - all cryptography, OFFLINE (no network)
agentcreds-resolvers/     Networked DID resolvers (web/http) - kept OUT of the core
agentcreds-py/            Python bindings (PyO3)  -> agentcreds
agentcreds-node/          Node bindings (napi)    -> @agentcreds/sdk
agentcreds-runtime/       Python runtime (MCP middleware) -> agentcreds-runtime
agentcreds-runtime-node/  Node runtime (A2A)      -> @agentcreds/runtime
conformance/              Shared cross-language golden vectors
```

`agentcreds-core` and `agentcreds-resolvers` are the members of the root Cargo
workspace (`Cargo.toml`). The napi/pyo3 bindings and the Python/Node runtimes
build via their own toolchains and are excluded from the cargo workspace.

## Prerequisites

- **Rust** >= 1.88 (MSRV) with `clippy`.
- **Python** >= 3.8 and [`maturin`](https://github.com/PyO3/maturin) for the Python bindings.
- **Node** >= 16 and npm for the Node bindings (`@napi-rs/cli` is a devDependency).

## Build & test

### Core (Rust)

```bash
cd agentcreds-core
cargo test                                   # unit + integration + doctests
cargo test --features proptest               # also runs the property/fuzz suites
cargo test --features bbs                    # the optional BBS+ module (arkworks)
cargo test --features sd-jwt                 # the optional IETF SD-JWT interop format
cargo clippy --all-targets                   # lints
```

### Python bindings

```bash
cd agentcreds-py
maturin develop                              # build + install into the active env
python examples/quickstart.py                # smoke test
python tests/test_conformance.py             # cross-language golden vectors
```

### Node bindings

```bash
cd agentcreds-node
npm install
npm run build:debug                          # (re)build the native addon + index.d.ts
node examples/quickstart.js                  # smoke test
node --test test/conformance.test.js         # cross-language golden vectors
```

### MCP middleware / runtimes

```bash
cd agentcreds-runtime
pip install -e ".[test]" && pytest -q
python examples/enforce_loop.py
```

## The bindings rebuild loop

The bindings wrap `agentcreds-core` by path, so **a core change is not visible to
a binding until you rebuild it**:

1. Edit `agentcreds-core`.
2. Rebuild the binding: `maturin develop` (Python) or `npm run build:debug` (Node).
3. Re-run the binding's smoke test / your script.

When you add a binding method, keep the type stubs in sync:
- Python: update `agentcreds-py/agentcreds.pyi`.
- Node: `index.d.ts` is **regenerated** by `napi build` - don't edit it by hand.

## Architecture rules

- **The core stays offline.** Never add `tokio`, `axum`, or `reqwest` to
  `agentcreds-core` - verify with `cargo tree`. Networked DID resolvers live in
  the separate `agentcreds-resolvers` crate.
- **All cryptography lives in the core.** The bindings only marshal bytes; they
  never make trust decisions of their own.
- **Heavy/optional crypto is feature-gated.** BBS+ (pairing crypto) sits behind
  the `bbs` feature and SD-JWT behind `sd-jwt`, so the default build stays lean.

## Code style & lints

The core enforces, at compile time:

- `#![forbid(unsafe_code)]` - no `unsafe`, anywhere.
- `#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used)]` - every
  public item is documented; no `unwrap`/`expect` outside `#[cfg(test)]`. Use
  `?`, `ok_or_else`, `map_err`, or `unwrap_or_*` instead.
- `#![warn(clippy::pedantic, clippy::nursery)]` - advisory; keep new code clean.

Other conventions:

- Document public items with examples; prefer **doctests** - they run in CI and
  keep the docs honest.
- Match the surrounding code's naming and structure.
- Domain-separate and length-prefix any hashing/signing inputs (see existing
  modules for the pattern).
- Add tests for every change, including the security regressions a feature
  protects (forgery, widening, replay, etc.).

## Continuous integration

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on every push
across Linux, macOS, and Windows: the core (tests + fuzz + clippy), the Node and
Python bindings (build + smoke test + conformance vectors), the runtime suite, a
dedicated `bbs`-feature job, `cargo-deny`, and the MSRV check. Please ensure
`cargo test`, `cargo clippy`, and the relevant smoke tests pass locally before
opening a PR.

## Pull requests

- Branch from `main`; keep PRs focused.
- Include tests and update the relevant docs (the affected package README and
  `agentcreds.pyi` if you touched the Python surface).
- Add a `CHANGELOG.md` entry under `[Unreleased]` for user-facing changes.
- Note any wire-format or API change explicitly (the project is pre-1.0).

## Licensing & sign-off

This project is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)). Each
package's manifest `license` field (SPDX) is authoritative. By contributing you
agree to license your contribution under Apache-2.0.

All commits must be **signed off** under the [Developer Certificate of
Origin](DCO) - add a `Signed-off-by` trailer with `git commit -s`:

```
Signed-off-by: Your Name <you@example.com>
```

## Security

Do not file security issues as public PRs/issues - see [`SECURITY.md`](SECURITY.md).
