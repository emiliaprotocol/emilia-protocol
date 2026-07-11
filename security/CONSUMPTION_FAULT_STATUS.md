<!-- SPDX-License-Identifier: Apache-2.0 -->
# Durable consumption fault status

`EP-GATE-DURABLE-CONSUMPTION-v2` is checked against a deterministic
model-based scheduler in `packages/gate/store-linearizability.test.js`.

The enforced run covers 5,000 seeds with 32 generated operations per seed
(160,000 scheduled operations), in addition to focused concurrent and
boundary tests. Each schedule starts with overlapping duplicate presentation
and then mixes:

- reserve, pre-effect release, effect start, commit, and process crash;
- duplicate waves and ownership loss across restarted workers;
- healthy failover, lagging replicas, refused stale promotion, and follower
  rollback attempts;
- storage unavailable, failure before linearization, and response loss after
  linearization; and
- final duplicate delivery after every attempted external effect.

The oracle replays the backend's committed transition log as a sequential
reference history and enforces:

1. at most one external effect for one receipt;
2. at most one live reservation owner;
3. no deletion or reopening after an effect starts;
4. committed state never regresses;
5. stale or unavailable replicas return errors, never freshness; and
6. post-effect duplicate presentation never wins a reservation.

The Postgres adapter separately rejects malformed or regressing clocks before
an expiry-bearing write or cleanup can mutate state. Reservations never carry
a TTL. This establishes safety under the modeled backend contract; it does not
turn an eventually consistent database into a linearizable one. A production
backend must still provide the atomic conditional operations the store
constructor requires.

Run the complete gate with:

```sh
npm run test:consumption-faults
```
