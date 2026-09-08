# Security Policy

## Reporting a vulnerability

**Please report security vulnerabilities privately - do not open a public issue
or pull request.**

Preferred: use GitHub's **[Report a vulnerability](https://github.com/agentcreds/agentcreds/security/advisories/new)**
(Security -> Advisories) to open a private advisory. Alternatively, email
**security@agentcreds.io**.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof-of-concept if possible),
- affected packages and versions.

We will acknowledge your report within a few business days, keep you updated on
remediation, and credit you in the advisory if you wish. Please allow a
reasonable embargo period (target: 90 days, or until a fix ships) before any
public disclosure so users can upgrade.

## Supported versions

AgentCreds is pre-1.0 (v0.1.x). Security fixes target the latest released
version; cryptographic wire formats may change between minor versions.

| Version | Supported |
|---------|-----------|
| 0.1.x   | DONE         |
| < 0.1   | NO         |

## Security foundations

- `#![forbid(unsafe_code)]` in the cryptographic core; private keys are zeroized
  on drop.
- Verification is **offline and deterministic** - the core makes no network
  calls and never trusts the transport, so it is safe to run on every tool
  invocation. Networked DID resolution is isolated in `agentcreds-resolvers`.
- Authority is **anchor-rooted** (`verify_rooted`): it cannot be self-asserted
  from an attacker-controlled DID.
- Delegation scope is cryptographically **monotone** - attenuation can only
  narrow authority; widening is structurally impossible, not a policy check.
- Proof-of-possession binds a presentation to the caller's leaf key, defeating
  token theft and delegation prefix-stripping.

The per-module guarantees and threat model are documented in the crate docs on
[docs.rs/agentcreds-core](https://docs.rs/agentcreds-core).
