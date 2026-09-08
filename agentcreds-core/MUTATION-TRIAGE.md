# Mutation-testing triage - agentcreds-core hot path

Mutation testing perturbs the source (flip a `&&`, stub a function to `Ok(())`, return
a constant) and reruns the suite. A **surviving** mutant means a test *executed* the
mutated line but did not *assert* the behavior the mutation broke - a latent gap the
line-coverage number cannot see. On the authorization path a survivor is a potential
auth-bypass with no regression test guarding it. This is the metric the nightly
`.github/workflows/mutants.yml` job tracks, and the one an external security audit
checks.

## Running it locally

```bash
cd agentcreds-core
cargo mutants --in-place --no-shuffle --features sd-jwt --timeout 120 \
  -f "**/delegation/mod.rs" -f "**/pop.rs" -f "**/approval.rs" -f "**/revocation.rs"
```

Notes:
- `-f` is a **glob matched against the full path**, so it must be `**/<file>` - a bare
  `src/foo.rs` matches nothing and the run tests zero mutants while exiting green.
- `--in-place` is required on Windows: the default copies the whole workspace to a temp
  dir and fails on the `node_modules` symlink in `agentcreds-runtime-node`
  (os error 1314). In-place needs a git-clean tree (it mutates and reverts source), and
  is single-threaded. **Do not run `cargo fmt` / edit these files while it runs** - two
  writers corrupt both the run and the tree.

## Baseline (first full run)

289 mutants across the four hot-path modules: **208 caught, 39 missed, 42 unviable** -
an **84% mutation score** (caught / (caught+missed)).

| module            | mutants | survivors (baseline) |
| ----------------- | ------- | -------------------- |
| approval.rs       | 30      | 0  DONE fully asserted  |
| pop.rs            | 45      | 11                   |
| revocation.rs     | 64      | 8                    |
| delegation/mod.rs | 150     | 20                   |

## Closed this pass - pop.rs + revocation.rs (18 of 19 survivors killed)

Re-run after the fixes: **1 missed, 94 caught, 15 unviable**. New tests:

| test                                      | kills |
| ----------------------------------------- | ----- |
| `pop::matches_requires_every_field_to_agree`   | `matches` `&&`->`||` (nonce/audience/issued_at must *all* agree) |
| `pop::challenge_cbor_round_trips` / `proof_cbor_round_trips` | `to_cbor` stubbed to empty/constant bytes (x6) |
| `pop::freshness_window_boundaries_are_inclusive` | `verify` freshness `>`/`<` boundary flips (x3) - via a new `verify_at(now)` seam |
| `revocation::is_revoked_rejects_out_of_bounds_index` | `check_index` stubbed to `Ok(())` (read path fail-open) |
| `revocation::freshness_bound_is_inclusive_at_the_edge` | `check_fresh` `>`->`>=` boundary |
| `revocation::list_carries_a_real_jws_alg` | `alg_for` returning `""`/junk (x2) |
| `revocation::from_status_list_token_rejects_empty_segments` | empty-segment guard `->true` / `&&`->`||` (x3) - an empty *signature* segment isn't re-checked downstream, so the parse must fail closed |

Design note: `ProofOfPossession::verify` now delegates to a private `verify_at(now)`;
`verify` is exactly that with `now = Utc::now()`. This mirrors `check_fresh(now, ...)` and
makes the freshness window deterministically testable (the offline core reads no clock).

## Accepted survivor (equivalent mutant - do not "fix")

- **`revocation.rs:207` `/`->`*`** in `from_status_list_token` - `raw_len*8 / bits` vs
  `raw_len*8 * bits`. The library only emits `bits == 1` lists, where `/1` and `*1` are
  identical, so no behavioural test can distinguish them. If multi-bit status lists are
  ever emitted (the format reserves 2/4/8), add a parse test asserting `size` for a
  `bits >= 2` token and this becomes killable.

## Closed this pass - delegation/mod.rs (17 of 20 survivors killed)

Re-run: **126 caught, 3 missed, 21 unviable**. New tests in `delegation/tests.rs`:

| test                                              | kills |
| ------------------------------------------------- | ----- |
| `authorizer_limits_uses_one_second_backstop`      | `authorizer_limits`->`Default` (`140`) - the 1s backstop vs biscuit-auth's flaky 1ms default |
| `first_widening_capability_names_the_widening_tool` | `first_widening_capability`->`None`/junk (`266` x3) |
| `budget_widening_is_rejected_on_attenuate`        | `attenuate` `||`->`&&` (`698`) - budget-only widening trips one guard, so they must be OR'd |
| `root_and_leaf_accessors_reflect_the_token`       | `root_agent_did` / `max_delegation_depth` / `leaf_binding` stubs (`1307`/`1341`/`1328`) |
| `root_resources_reflect_the_minted_allowlist`     | `root_resources`->`leak(...)` (`1321`) |
| `vc_pinned_gate_is_merged_and_enforced_for_the_action_tool` | gated-inclusion `==`->`!=`, `&&`->`||` (`1012`) |
| (extended did:web resolver test)                  | `verify_rooted_with_resolver`->`Ok(())` (`923`) - the rooted resolver path had no negative test |

The gated-inclusion test is the highest value: a VC-pinned gate (distinct from the
token's own scope) must be enforced for the matching tool and must **not** gate other tools.

### Accepted survivors (equivalent mutants - do not "fix")

- `846` `verify_inner` `>`->`>=` - token-expiry boundary vs `Utc::now()` (clock-seam). Add a
  `now` seam to `verify_inner` (as done for `ProofOfPossession::verify_at`) if it's worth killing.
- `1012:41` `delete !` on the `!effective.contains(g)` **dedup guard** - deleting it pushes a
  *duplicate* gate onto `effective`, which yields the identical allow/deny decision. Equivalent.
  (Its siblings - the `==` tool-match and `&&` join at `1012` - are real and are killed above.)
- `1130` `delete !` on the OBO resource-authority re-check - `mint` already rejects
  out-of-authority resources, so a violating token can't be built through the API; only a
  forged biscuit would distinguish it (a defense-in-depth re-check of what mint enforces).

## Final state

Across the four hot-path modules: **39 baseline survivors -> 4 remaining, all documented
equivalents** (revocation `207` bits==1; delegation `846`, `1012:41`, `1130`). Every
non-equivalent survivor on the authorization path now has a killing assertion.

| module            | baseline survivors | after | remaining are |
| ----------------- | ------------------ | ----- | ------------- |
| approval.rs       | 0                  | 0     | -             |
| pop.rs            | 11                 | 0     | -             |
| revocation.rs     | 8                  | 1     | equivalent (bits==1) |
| delegation/mod.rs | 20                 | 3     | equivalent (clock-seam, dedup, mint-redundant) |

## CI status

- The nightly's `-f` globs were `src/...` (matched nothing) and `src/delegation.rs` (renamed
  to `src/delegation/mod.rs`). Fixed to `**/...` with a **zero-match guard** that fails the
  job if the scope ever matches no files again.

### The four survivors are excluded, not tolerated (2026-08-27)

`cargo mutants` **exits non-zero if any mutant survives** - measured: a run over
`revocation.rs` alone reported `1 missed, 58 caught, 6 unviable` and exited **2**. So the
four accepted equivalents above would have failed the job on merit every time it ran,
and a permanently-red job is one nobody reads: a genuine new survivor would hide among
them.

They are excluded in **`.cargo/mutants.toml`** (workspace root - it is not
auto-discovered from the package directory; verified by the exclusions taking effect only
after the move). Each entry carries its rationale.

**The exclusions are pinned by `line:col`, deliberately.** The descriptions are not
unique - within the same functions:

| description | matches | the siblings are |
| --- | --- | --- |
| `replace > with >= in DelegationToken::verify_inner` | 2 | the **depth bound** |
| `delete ! in ...verify_rooted_gated_with_directory` | 2 | the **unrecognized-gate-kind fail-closed** |
| `delete ! in DelegationToken::verify_rooted_inner` | 3 | the **scope-widening subset test**, the `is_empty` guard |

Every sibling is a real check that must keep being tested, so a description-only regex
would silently stop testing them - the opposite of the point.

**Because line numbers drift, the workflow asserts the exclusions still match exactly
four** (`--list` with and without `--no-config`, compared). If an edit moves a line the
count changes and the job fails loudly, rather than quietly excluding the wrong mutant or
none. Re-triage and update both the toml and this file when that happens.

Current pinned lines, refreshed 2026-08-27 (the triage entries above cite the older,
pre-drift numbers 846 / 1012:41 / 1130):

| accepted equivalent | pinned at |
| --- | --- |
| `from_status_list_token` `/`->`*` | `revocation.rs:207:46` |
| `verify_inner` expiry `>`->`>=` | `delegation/mod.rs:1057:20 (re-pinned 2026-09-06)` |
| dedup guard `delete !` | `delegation/mod.rs:1261:41 (re-pinned 2026-09-06)` |
| OBO resource-authority re-check `delete !` | `delegation/mod.rs:1403:28 (re-pinned 2026-09-06)` |
| ~~`verify_presentation` expiry `>`->`>=`~~ | RETIRED 2026-09-07 - `verify_presentation_at` seam added; boundary pinned exactly |

### Scheduling

The scheduled runs repeatedly **failed to start on a GitHub Actions billing block**
(`steps: 0`, dead in 2s, "your spending limit needs to be increased") - first from
2026-07-28, then again for every scheduled run from 2026-08-23. Not a test failure.

Cause was cost, not the limit: a nightly mutation run allowed 350 minutes plus a nightly
full CI matrix at ~270 billed minutes (five macOS jobs at the **10x** private-repo
multiplier) came to 600+ billed minutes a night against a 2,000/month allowance - roughly
three nights to exhaustion. Changed 2026-08-27:

- mutation runs **weekly** (Saturdays), **sharded 4 ways** (`--shard k/4`), 120-minute cap
  per shard instead of 350 for one job;
- CI's full matrix runs **weekly** (Sundays) and **no longer includes macOS**.


## Pass of 2026-09-06 - interop.rs, wimse.rs, sd_jwt.rs added to scope

70 mutants: **44 caught, 6 missed, 18 unviable** on the first run. Triage:

| survivor | verdict | disposition |
| --- | --- | --- |
| `interop.rs:155/159` `map_out`/`map_in` -> `Null` (x2) | **real** - the stable wrapper contract's documented identity default was pinned by nothing; a vendor adapter relying on it would silently map every claim to null | killed by `interop::identity_claim_map_is_actually_the_identity` |
| `wimse.rs:98` `trusted_domains()` -> `vec![]` / `[""]` / `["xyzzy"]` (x3) | **real** - the "who do we federate with?" accessor could answer nothing, or invent a domain, unnoticed | killed by `wimse::trusted_domains_reports_exactly_what_was_federated` |
| `sd_jwt.rs:368` expiry `>`->`>=` | **accepted equivalent** - same clock-seam class as `delegation/mod.rs:915`; differs only at the exact nanosecond `now == exp`, and `verify_presentation` has no `now` seam. pop.rs killed its equivalents by adding a `verify_at(now)` seam - do the same here if this boundary becomes worth pinning | excluded in `.cargo/mutants.toml`; guard count 4 -> 5 |

Re-run after the fixes: **0 missed** (51 caught, 18 unviable, 1 excluded). Note the
distribution: the two REAL clusters were in exactly the modules flagged by low *function*
coverage (interop 84.6%, wimse 73.9%) - while sd_jwt, whose 50 mutants were the reason to
worry, came back clean apart from the boundary equivalent. Function-coverage numbers
predicted where the gaps were better than mutant count did.

## Pass of 2026-09-06 (later) - signed.rs added to scope

The shared fail-closed verify for anchor-signed fetched artifacts (trust config,
approver directory) had **no tests of its own** - 80% function coverage, all of it
indirect through its callers. Seven direct tests added covering check order (issuer
mismatch wins over an undecodable signature), forged/wrong-digest signatures, the
exclusive expiry boundary, the no-expiry path, and error labelling.

First run: 10 mutants, **10 caught, 0 missed** - including the expiry `>`->`>=`
boundary, pinned to the nanosecond because `verify_anchor_signed` takes `now` as a
parameter. That is the same mutation class accepted as equivalent at
`delegation/mod.rs:915` and `sd_jwt.rs:368`, and the contrast is the lesson: a clock
seam turns an untestable boundary into a one-line assertion.

## Pass of 2026-09-06 (CI first complete shards) - two survivors + a sharding hole

The first CI run with correct guard math surfaced what file-scoped local runs could not:

- **`--shard` is 0-indexed and the matrix said 1/4..4/4** - so shard 4/4 failed instantly
  and shard 0/4 NEVER RAN: a quarter of the corpus was silently untested by CI while the
  workflow comment asserted the indexing was 1-based. Fixed to 0/4..3/4.
- **`verify_at` -> `Ok(())` survived**: no core test called it (the vectors exercise it
  only through the bindings, invisible to cargo-mutants). Killed by
  `verify_at_enforces_scope_and_the_exact_expiry_boundary`, which also pins the expiry
  boundary to the nanosecond via the `now` parameter - retiring the 1057:20
  accepted-equivalent, whose "no seam exists" rationale the same test disproved.
- **`delete !` on the OBO `is_empty` guard survived**: equivalent for the same reason as
  its 1403 sibling - `verify_rooted_inner` binds token to credential by `vc_id` and
  `mint` refuses out-of-authority resources, so only a forged biscuit reaches the
  difference. Excluded with that shared rationale; net exclusion count unchanged at 5.
