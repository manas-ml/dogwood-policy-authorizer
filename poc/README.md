# Dogwood policy-enforcement PoC

An AI agent calls tools through a gateway on behalf of an OAuth user. Every call
is authorized by [Dogwood](https://github.com/dogwood-policy/dogwood) first;
history-dependent rules ("logged in within the last hour", "2+ exports in 10
minutes") are expressed with Dogwood's `when temporal { … }` clauses.

## Setup and run

Requirements: `git` and a Rust toolchain (`cargo`); network access to GitHub.

```sh
./poc/run.sh
```

`run.sh` clones `dogwood-policy/dogwood` at the pinned revision `996d756d` into
`poc/.dogwood-src` (override with `DOGWOOD_SRC=<existing checkout>` or
`DOGWOOD_BIN=<dogwood binary>`), builds the CLI with `cargo build -p dogwood-cli`
(~2 min the first time), then:

1. `dogwood validate` on the policies (must pass);
2. `dogwood validate` on every `negative/*.dw` (must exit 2);
3. `dogwood replay` for every `traces/*.log`, printing an event/time/decision
   table and diffing the output against `traces/<name>.expected`;
4. runs the Rust demo (`SKIP_RUST_DEMO=1` to skip).

It exits non-zero if anything fails. (I checked this by flipping one expected
verdict: exit 1. A fresh copy of `poc/` with no build cache also passes.)

## Layout

| Path | Contents |
|---|---|
| `schema/gateway.cedarschema` | Cedar schema, namespace `Drupe`: `OAuthUser` → `Gateway`, actions Login/Read/Write/Delete/Export, parameters under `context.input` (`user`, `path`, `sensitivity`). The event schema is Dogwood's default. |
| `policies/gateway.dw` | The policies below |
| `traces/*.log`, `*.expected` | Event traces and the verdict stream each must produce |
| `negative/unknown_field.dw` | Broken policy: reads `context.input.clearance`, which `Read` does not have |
| `rust-demo/` | SDK pipeline + simulated agent session (137 lines) |
| `run.sh` | Everything above |

## Policies

| Rule | `@id` | Meaning |
|---|---|---|
| 0 | `login_anyone` | *Supporting rule, not in the brief.* With the default event schema every `request` event is a decision point, including `Login`, so without a permit the login itself is denied. |
| 1 | `read_anyone` | **Policy 1.** Anyone can Read. |
| 2 | `delete_export_baseline` | Permit Delete/Export, so that policy 2 has something to override (the brief's baseline only covers Read). |
| 3 | `forbid_high_sensitivity` | **Policy 2.** `forbid` Delete/Export when `context.input.sensitivity == "high"`. Forbid beats permit. |
| 4 | `write_after_login` | **Policy 3.** Permit Write `when temporal { formerly within 1h Login::response{ input.user: context.input.user } }`. |
| 5 | `forbid_export_burst` | **Policy 4 (implemented).** `forbid` Export when `count … formerly within 10m Export::request{ input.user: context.input.user } && tp(t)) >= 3`. |

Notes on the temporal rules:

* "Same user" is the explicit `input.user: context.input.user` correlation. The
  default event schema additionally pins `callerPrincipal` to the request's
  principal, so events of other principals are invisible anyway
  (`e_wrong_user_login` shows bob's login doesn't help alice).
* Policy 3 keys on the Login **response** (a successful login), following the
  `read_after_login` example. A bare Login *request* does not unlock Write.
* Policy 4: the `count` window includes the current request, so "already 2 prior
  Exports" is `>= 3`. A denied Export still lands in history and counts.
  The temporal syntax supports this (`count for (t: Timepoint). where (…)`), so
  it was not skipped.

## Results

From `./poc/run.sh` (all match expected):

| Case | Trace | Event | Time | Decision |
|---|---|---|---|---|
| a | `a_login_read_write` | Login | @0 | ALLOW (rule 0) |
| a | | Read | @10 | ALLOW (rule 1) |
| a | | **Write** | @60 | **ALLOW** (rule 4: login 55s ago) |
| b | `b_login_expired` | Login | @0 | ALLOW |
| b | | Write | @100 | ALLOW (rule 4) |
| b | | **Write** | @7200 | **DENY** (login is 7195s old > 3600s) |
| c | `c_high_sensitivity` | Delete (high) | @10 | **DENY** (rule 3 beats rule 2) |
| c | | Export (high) | @20 | **DENY** (rule 3) |
| c | | Delete (low) | @30 | ALLOW (rule 2, control) |
| d | `d_write_without_login` | **Write** | @10 | **DENY** (no Login in history) |
| d | | Read | @20 | ALLOW (control) |
| – | `e_wrong_user_login` | Write (alice, bob logged in) | @10 | DENY |
| 4 | `f_export_burst` | Export (low) ×3 at @0, @60, @120 | | ALLOW, ALLOW, **DENY** (rule 5) |
| 4 | | Export (low) | @900 | ALLOW (earlier exports aged out of 10m) |

**The time-only flip (case b):** the policy, the Write event and its fields are
identical at @100 and @7200. Only the clock differs, and the verdict goes
ALLOW → DENY. Rust demo session 2 shows the converse for state: the same Write
on a fresh `Authorizer` with no Login in its history is denied.

The `expected` files were produced by running `dogwood replay` once and then
reviewing each line against the intent above (they are regression pins, not an
independent oracle).

## Validation

`negative/unknown_field.dw` is rejected (exit 2):

```
error: for policy `policy_0`, attribute `input.clearance` in context for Drupe::Action::"Read" not found
FAILED: 1 error(s), 0 warning(s).
```

## Rust demo

`cd poc/rust-demo && cargo run`. Pipeline: `ServiceSchema::defaults()` →
`PolicySchema::from_cedarschema_str` → `LoweredPolicySet::from_str` →
`Validator` → `Authorizer` → `Event::builder`. Schema and policies are
`include_str!`'d from `../schema` and `../policies`; Rust contains no policy
logic. A scripted agent session routes each call through `gateway()`, which
authorizes first and only calls the stub tool on Allow, then feeds the tool's
`response` event back as history. Output shows `Some(Response)` for requests,
`None` for the history-only `Login::response`, and a stateful authorizer
(session 1 vs. fresh session 2).

## Doc / API mismatches and gotchas

1. **`.field()` alone is not enough (important).** The getting-started and API
   tutorials build events with `.field("input", …)` only. The API reference says
   a field a policy reads via `context.input.*` *and* correlates temporally must
   also be set with `.request_context("input", …)`. I tested without it: the
   `forbid_high_sensitivity` rule silently stopped matching (high-sensitivity
   Delete was **ALLOWED**) and `write_after_login` denied. No error, no
   diagnostics; the Rust demo therefore sets both. The CLI trace format has a
   separate `request_context(…)` envelope for the same reason. Fail-open on a
   forbid is the dangerous part.
2. **`examples/` path.** The docs say `examples/` at the crate root; in the repo
   they are under `dogwood-docs/examples/`.
3. **Validation errors name `policy_0`, not the `@id`** (e.g. "for policy
   `policy_0`"), so the `@id` annotation doesn't help locate the failing rule.
4. **`login_anyone` is required** in practice because `Login::request` is itself
   a decision event (documented, but easy to miss: the docs' own `@0` Login → Deny).
5. `Authorizer::is_authorized` is `&mut` and `LoweredPolicySet` is moved into the
   `Authorizer`, so building a second authorizer re-lowers the policies.

Dogwood is pinned by git rev in `rust-demo/Cargo.toml` (the crate is not
consumed from crates.io), and the same rev in `run.sh`.
