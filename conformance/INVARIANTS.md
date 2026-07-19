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
| JavaScript | `runners/run-invariants.mjs` | **Wired, CI-gated.** Drives the real production `createMemoryCapabilityStore` (same guards the Postgres store mirrors 1:1 via `CAPABILITY_SQL`) and the real `lib/handshake/invariants.js` guard functions. |
| Python | `runners/run_invariants.py` | **Wired, CI-gated.** Faithful Python port of the reserve/commit accounting (`capability-receipt.js:450-490`) and the four handshake guards (`invariants.js:96-309`). 21/21 hold. |
| Go | `runners/run_invariants.go` | **Wired, CI-gated.** Faithful Go port of the same accounting logic and guards; stdlib-only (`go run`, no `go.mod`). 21/21 hold. |

**What the Python/Go ports do and don't cover.** The invariants under test are
*accounting* and *predicate* properties (a budget identity, single-commit,
commit-requires-reserve, monotonic consumption, and the four handshake guards).
None is a property of the Ed25519 capability envelope or the durable Postgres
store, so each port reimplements **only** that ~30-line accounting logic and
those pure predicates — not the receipt crypto and not the durable store.
Capabilities are registered directly by `(budget, expiry, fingerprint)`, the
shape `createMemoryCapabilityStore` holds internally after it verifies and
unwraps the signed envelope; the JS lane's Ed25519 minting is only harness setup
and changes no outcome the corpus asserts.

This is genuine cross-port conformance, not a self-check: three independent
implementations (JS, Python, Go) of the same state machine, each checked against
the same TLA+-derived corpus of expected outcomes. If a port's logic diverged
from the spec, the corpus flags it (a `FAIL`, non-zero exit). Non-vacuity is
verified by feeding each runner a mutated corpus and confirming it diverges.
Every case is exercised in every lane; there are **no skipped invariants**.

## Running

```sh
node conformance/runners/run-invariants.mjs          # JS lane (CI-gated)
node conformance/runners/run-invariants.mjs --json    # machine-readable
python3 conformance/runners/run_invariants.py         # Python lane (CI-gated)
go run conformance/runners/run_invariants.go          # Go lane (CI-gated)
```

All three lanes run in CI (`.github/workflows/ci.yml`, cross-language
conformance job); the JS lane additionally runs as a vitest suite
(`conformance/invariants.test.js`, which also asserts the runner is non-vacuous
by feeding it a mutated corpus).

A failure in any lane means an implementation diverged from a TLA+-proven
invariant — either the real JS store/guard (JS lane) or one of the ports (Python
/ Go lane) no longer agrees with the shared corpus. Treat it as a conformance
finding, not a flaky test.
