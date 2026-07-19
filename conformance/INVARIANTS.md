# TLA+-invariant cross-language conformance

This directory's `run.mjs` replays canonical **receipt vectors** through the
JS/Python/Go verifiers. This file documents a second, complementary corpus:
**invariant** conformance — concrete cases derived from the TLA+ *safety
invariants* in `formal/ep_handshake.tla` and `formal/ep_capability.tla`, closing
audit GAP 9 ("shared vectors exist, but no TLA+-invariant-derived shared cases").

These are **state-machine** properties, not receipt-verification properties, so
they are driven differently: instead of feeding a static document to a verifier,
each case runs an **action sequence** against the real state machine and asserts
both the per-step outcome and a structural invariant on the resulting state.

## Corpus — `conformance/invariants.json`

Each entry is one safety invariant with a `spec` pointer (`file:line` into the
TLA+ model), a `domain`, and a list of `cases`. A case is a sequence of
`actions`; a capability case also carries a `structural` predicate checked on the
real store state after the sequence.

| Invariant | TLA+ | Domain | What a conformant impl must uphold |
|---|---|---|---|
| `ReserveWithinBudget` | `ep_capability.tla:135` | capability | `consumed + reserved <= budget`; over-budget reserve → `budget_exceeded` |
| `NoDoubleCommit` | `ep_capability.tla:196` | capability | an op commits at most once → `capability_operation_already_finalized` |
| `CommitRequiresReserve` | `ep_capability.tla:201` | capability | commit only from reserved + matching token |
| `ConsumptionMonotonic` | `ep_capability.tla:186` | capability | `consumed` never decreases |
| `ConsumeOnceSafety` | `ep_handshake.tla:102` | handshake | one accepted result per binding hash → `DUPLICATE_RESULT` |
| `TerminalStateIrreversibility` | `ep_handshake.tla:159` | handshake | finalized result is immutable → `RESULT_IMMUTABLE` |
| `ExpiredIsTerminal` | `ep_handshake.tla:136` | handshake | past-expiry binding cannot advance → `BINDING_EXPIRED` |
| `BindingIntegrityNoBypass` | `ep_handshake.tla:150` | handshake | omitting the payload hash must not bypass the check → `BINDING_INVALID` |

These derive from the TLA+ invariants; they do **not** duplicate any receipt
vector in `conformance/vectors/`.

## Lanes

| Lane | File | Status |
|---|---|---|
| JavaScript | `runners/run-invariants.mjs` | **Fully wired.** Drives the real production `createMemoryCapabilityStore` (same guards the Postgres store mirrors 1:1 via `CAPABILITY_SQL`) and the real `lib/handshake/invariants.js` guard functions. |
| Python | `runners/run_invariants.py` | **Scaffold (unwired).** Parses + dispatches the corpus; exits `2`. Blocker: no Python port of the capability store / handshake invariants exists in `packages/python-verify`. |
| Go | `runners/run_invariants.go` | **Scaffold (unwired).** Parses + dispatches the corpus; exits `2`. Blocker: no Go port exists in `packages/go-verify`. |

The Python/Go lanes are deliberately unwired rather than filled with an
author-written re-implementation: a port the same author writes cannot honestly
detect a *cross-port divergence* from the reference. They exit non-zero so they
can never be mistaken for a passing lane. When a genuine port lands, flip the
`UNWIRED`/`unwired` flag and implement the dispatch bodies — the corpus and the
JS oracle need no changes, and a real divergence will surface on first run.

## Running

```sh
node conformance/runners/run-invariants.mjs          # JS lane (CI-gated)
node conformance/runners/run-invariants.mjs --json    # machine-readable
python3 conformance/runners/run_invariants.py         # scaffold, exit 2
go run conformance/runners/run_invariants.go          # scaffold, exit 2
```

The JS lane runs in CI (`.github/workflows/ci.yml`, cross-language conformance
job) and as a vitest suite (`conformance/invariants.test.js`, which also asserts
the runner is non-vacuous by feeding it a mutated corpus).

A JS-lane failure means the real store or a real guard function diverged from a
TLA+-proven invariant — treat it as a conformance finding, not a flaky test.
