# Running the Alloy models

This document gives the exact steps to run the Alloy Analyzer against the EP
relational models and record the result. As of the `formal/alloy-executed`
change these models **run in CI on every push that touches `formal/**.als`**
(`.github/workflows/alloy.yml`), so a counterexample now fails the build the
same way the TLC models do.

Models under `formal/`:

| Model | What it covers |
|-------|----------------|
| `ep_relations.als`  | Handshake + signoff lifecycle, single-consume, write-path exclusivity |
| `ep_federation.als` | Cross-issuer trust: authenticity, revocation, no trust laundering |
| `ep_quorum.als`     | Two-person rule: self-approval impossible, one-slot-per-human/key |
| `ep_delegation.als` | Capability delegation chain: acyclicity + non-increasing authority |

---

## Prerequisites

- Java 17 or later installed (`java -version`)
- The Alloy 6.2.0 distribution jar (`org.alloytools.alloy.dist.jar`, ~21 MB,
  bundles the pure-Java SAT4J solver, no native dependencies)

---

## Step 1 — Download Alloy 6.2.0

```bash
curl -fsSL -o alloy.jar \
  https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.2.0/org.alloytools.alloy.dist.jar

# Verify the pinned checksum (the same one CI enforces):
echo "6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d  alloy.jar" | shasum -a 256 -c -
```

> Note: there is no `v6.1.0` release asset, and the account of "flat dist jar
> only on v6.0.0" is wrong — `v6.2.0` ships `org.alloytools.alloy.dist.jar`.
> That is the version the models were executed against and the version CI pins.

---

## Step 2 — Run all commands (GUI, optional)

```bash
java -jar alloy.jar formal/ep_relations.als
```

In the Alloy Analyzer window, **Execute → Execute All**. Each `check` should
report **"No counterexample found."** and each `run` predicate should report an
instance (so the model is non-vacuous).

---

## Step 3 — Run all commands headless (this is what CI does)

The runner is a committed file, `formal/AlloyCheck.java`. It compiles each
`.als` file, executes every `check` and `run` command against the SAT4J solver,
and exits non-zero if any assertion produces a counterexample or any predicate
is vacuous.

```bash
# from the repo root, with alloy.jar downloaded to the repo root:
cd formal
javac -cp ../alloy.jar AlloyCheck.java
java -cp ../alloy.jar:. AlloyCheck \
  ep_relations.als ep_federation.als ep_quorum.als ep_delegation.als 2>/dev/null
```

(Kodkod's solver progress is written to stderr; `2>/dev/null` keeps the verdicts
readable. The exit code still gates.)

Actual output (Alloy 6.2.0, 2026-07-18):

```
========================================================
Model: ep_relations.als
========================================================
  check  NoDoubleConsumption                           No counterexample found. OK
  check  RevokedNeverConsumed                          No counterexample found. OK
  ... (15 checks total, all hold)
  run    showLifecycle                                 Instance found. (non-vacuous)
  ... (5 runs total, all satisfiable)

========================================================
Model: ep_federation.als
========================================================
  check  AcceptedIsAuthentic                           No counterexample found. OK
  ... (7 checks total, all hold)
  run    showFederation                                Instance found. (non-vacuous)

========================================================
Model: ep_quorum.als
========================================================
  check  SelfApprovalImpossible                        No counterexample found. OK
  ... (6 checks total, all hold)
  run    showStrongQuorum                              Instance found. (non-vacuous)

========================================================
Model: ep_delegation.als
========================================================
  check  DelegationAcyclic                             No counterexample found. OK
  check  DelegationIdsUnique                           No counterexample found. OK
  check  LeafIsNotItsOwnAncestor                       No counterexample found. OK
  check  AuthorityNonIncreasing                        No counterexample found. OK
  run    showChain                                     Instance found. (non-vacuous)

========================================================
Results: checks 32/32 held, runs 8/8 satisfiable
OK: all assertions hold, all predicates consistent.
========================================================
```

---

## What each `ep_relations.als` assertion covers

| Assert | What it proves | Facts relied on |
|--------|---------------|-----------------|
| NoDoubleConsumption | A handshake can only be consumed once | F3, F5 |
| RevokedNeverConsumed | Revoked handshakes have no consumption record | F9 |
| ConsumedWasVerified | Every consumed handshake had a VerifiedEvent | F16, F25 |
| BindingHashIsolation | Binding hashes are unique across all handshakes | F7, F2 |
| TerminalStateIntegrity | Revoked/Expired/Rejected → no consumption | F9-F11 |
| WritePathExclusive | All mutations go through CanonicalWrite only | F17, F18 |
| DelegationScopeRespected | Delegate scope never exceeds principal scope | F19 |
| NoDelegationCycles | No entity reachable from itself via delegations | F20, F21 |
| PolicyHashConsistency | Binding policy hash matches policy at bind time | F23 |
| MultiActorNoDoubleConsume | Multiple actors cannot both consume same handshake | F24 |
| EventStateExactCorrespondence | Terminal event appears exactly once per status | F25 |
| SignoffBindingIntegrity | Binding hash is consistent across signoff chain | F27, F28 |
| SignoffConsumeOnce | At most one consumption per attestation | F29 |
| SignoffRequiresHandshake | No signoff challenge without a verified handshake | F26 |
| FullChainIntegrity | Full signoff chain has one consistent binding | F26-F28 |

`ep_delegation.als` adds the capability-chain invariants (DelegationAcyclic,
DelegationIdsUnique, LeafIsNotItsOwnAncestor, AuthorityNonIncreasing), mirroring
`packages/gate/capability-receipt.js` `assertDelegationChain()` and the
`DelegationAuthorityNonIncreasing` invariant in `formal/ep_capability.tla`.

---

## If a counterexample is found

1. Record the counterexample trace in `formal/alloy-counterexample-ANN.txt`
2. Fix the assertion or the underlying model
3. Re-run to confirm the fix
4. File a critical bug referencing the counterexample

---

## CI Integration

`.github/workflows/alloy.yml` runs on every push or PR that touches
`formal/**.als`, `formal/AlloyCheck.java`, or the workflow itself. It downloads
Alloy 6.2.0 (pinned tag + SHA-256), compiles `formal/AlloyCheck.java`, runs all
four models, and fails the build if any assertion produces a counterexample.
The captured verdicts are uploaded as the `alloy-output` artifact.

```yaml
on:
  push:
    paths:
      - 'formal/**.als'
      - 'formal/AlloyCheck.java'
      - '.github/workflows/alloy.yml'
```
