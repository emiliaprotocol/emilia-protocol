# Continuous adversarial fuzzing (audit GAP 7)

A seeded, deterministic, CI-runnable property fuzzer for the concurrency-
sensitive surfaces of the protocol.

## Why this exists

The async-guard bypass was a **parallel-consumption race**: a check-then-act
window between reading a budget / consumption record and mutating it, so two
concurrent attempts could both pass the check. A property fuzzer that drives
many interleaved reserve/commit and consume-once attempts against the real
stores and asserts the safety invariants after every scenario catches that bug
class before it ships.

The harness is **not** a no-op. Its `invariant()` primitive was verified to fire
on a deliberately-broken store with exactly this race (an `await` between the
budget read and the mutation): 50 concurrent bids of 60 against a budget of 100
committed a total of 3000, and the check flagged `committed-sum=3000 > budget`.

## Determinism

- The RNG is `mulberry32`, seeded from an integer. Same seed → same stream.
- The interleaving scheduler (`interleave`) draws every scheduling decision from
  that same seeded RNG and awaits each step to completion, so interleaving
  happens only at operation-step boundaries and the whole run is reproducible.
- No `Math.random`, no `Date.now`: the stores take an injectable `now`, and the
  batch pins it to a fixed logical clock.
- Capability ids and reservation tokens are `node:crypto` UUIDs and so differ
  run to run, but they are opaque to every invariant — the PASS/FAIL verdict is
  stable for a given seed. (`--seed 7` twice drives the identical 6515 ops.)

## Targets

Both targets import and drive the **actual shipped modules**, never a reimpl.

### `capability-race` — `packages/gate/capability-receipt.js`

Mints a fresh capability, registers it in `createMemoryCapabilityStore()`, then
interleaves N randomized spend operations (reserve → commit) plus a seeded mix
of adversarial operations (double-commit, forged-token commit). Invariants:

- `total-committed<=budget` — checked on both an independently-tracked committed
  sum and the store's own `consumed_amount` (never trusting the store's
  self-report alone).
- `no-double-commit` — a committed operation cannot commit again; distinct
  committed operations only.
- `unique-reservation-tokens-among-commits`.
- `consumed-monotonic` — the consumed counter never decreases.
- `consumed+reserved<=budget` at settle.
- `consumed==sum-of-committed-amounts`.

### `handshake-consume` — `packages/gate/store.js`

**Scope, stated honestly.** The production handshake consume-once guarantee
(`lib/handshake/consume.js`) is enforced inside PostgreSQL — the
`consume_handshake_atomic` RPC takes `FOR UPDATE` on the handshake row and a
`UNIQUE` constraint on `handshake_id` makes a second consume a `23505` error
(migrations 074 / 085). That path needs a live Supabase/Postgres and is **not**
runnable in a CI fuzz harness, so this target does not pretend to drive it.

What it drives is the real, shipped, in-process consumption store that enforces
the identical invariant the handshake DB path mirrors — a key authorizes exactly
one action, once. `MemoryConsumptionStore` and `createDurableConsumptionStore`
are imported unmodified. The durable scenario runs several independent store
instances over one shared backend (the fleet model: many pods, one Redis/
Postgres). Invariants:

- `consume-once` — across all concurrent consumers of a single key, exactly one
  succeeds.
- `no-consume-after-commit` — a spent key never consumes again.
- `reservation-ownership-fenced` — a non-owner store cannot commit another
  store's reservation.

## Running

```sh
# One target, one seed, replayable:
node fuzz/harness.mjs capability-race --seed 7 --iterations 300

# A seed range:
node fuzz/harness.mjs handshake-consume --seeds 1..30 --iterations 300

# The exact bounded batch CI runs on every push (finishes in ~1.5s locally):
node fuzz/ci-batch.mjs
```

On the first invariant violation the harness prints the target, seed, iteration,
invariant, detail, and the exact replay command, then exits non-zero.

## CI

The `fuzz` job in `.github/workflows/ci.yml` runs `node fuzz/ci-batch.mjs` on
every push and pull request. The batch is fixed-seed and time-bounded
(`capability-race` and `handshake-consume`, seeds 1..24 × 250 iterations each;
~1.5s locally, well under the 60s budget) so it is a deterministic gate, not a
flaky one.

### Nightly-deeper (documented, not yet scheduled)

A deeper sweep — wider seed range and higher iteration counts, e.g.

```sh
node fuzz/harness.mjs capability-race   --seeds 1..500 --iterations 2000
node fuzz/harness.mjs handshake-consume --seeds 1..500 --iterations 2000
```

is intended to run on a nightly `schedule:` trigger so a rare interleaving that
the bounded per-push batch does not reach still gets exercised daily. Wire it as
a separate scheduled workflow (or a `schedule:`-gated job) rather than adding
minutes to the per-push path. A failing nightly seed is reproducible with the
same `--seed` locally.
