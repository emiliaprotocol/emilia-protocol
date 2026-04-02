# Running Alloy on ep_relations.als

This document gives exact steps to run the Alloy Analyzer against the
EP relational model and record the result.

---

## Prerequisites

- Java 11 or later installed (`java -version`)
- Alloy 6.1.0 jar (the Alloy model checker, ~80 MB, no other dependencies)

---

## Step 1 — Download Alloy 6

```bash
curl -L -o alloy.jar \
  https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.1.0/org.alloytools.alloy.dist.jar
```

Or download manually from:
https://github.com/AlloyTools/org.alloytools.alloy/releases/tag/v6.1.0

Verify the download:
```bash
java -jar alloy.jar --help 2>&1 | head -3
```

---

## Step 2 — Run all assertions (GUI)

```bash
java -jar alloy.jar formal/ep_relations.als
```

In the Alloy Analyzer window:

1. Select **Execute → Check All Assertions**
2. Each of the 15 assertions should display: **"No counterexample found."**
3. Run the predicates (`showLifecycle`, `showAdversarial`, etc.) to confirm the
   model is non-vacuous (instances exist).

---

## Step 3 — Run all assertions (headless / CI)

The CI Java runner compiles and executes `AlloyCheck.java` against `alloy.jar`.
See `.github/workflows/alloy.yml` for the full pipeline.

To reproduce locally:

```bash
# 1. Compile the runner (from repo root, after downloading alloy.jar)
javac -cp alloy.jar AlloyCheck.java

# 2. Run all checks
java -cp .:alloy.jar AlloyCheck formal/ep_relations.als
```

Expected output:
```
Parsing: formal/ep_relations.als
Parse OK.
Commands: 20
  check        NoDoubleConsumption ... No counterexample found.
  check        RevokedNeverConsumed ... No counterexample found.
  check        ConsumedWasVerified ... No counterexample found.
  check        BindingHashIsolation ... No counterexample found.
  check        TerminalStateIntegrity ... No counterexample found.
  check        WritePathExclusive ... No counterexample found.
  check        DelegationScopeRespected ... No counterexample found.
  check        NoDelegationCycles ... No counterexample found.
  check        PolicyHashConsistency ... No counterexample found.
  check        MultiActorNoDoubleConsume ... No counterexample found.
  check        EventStateExactCorrespondence ... No counterexample found.
  check        SignoffBindingIntegrity ... No counterexample found.
  check        SignoffConsumeOnce ... No counterexample found.
  check        SignoffRequiresHandshake ... No counterexample found.
  check        FullChainIntegrity ... No counterexample found.
  run          showLifecycle ... instance found
  run          showAdversarial ... instance found
  run          showDelegation ... instance found
  run          showMultiActorConsumption ... instance found
  run          showSignoffLifecycle ... instance found

Results:
  checks: 15 passed, 0 failed
  runs:   5 satisfiable
OK: all checks passed.
```

---

## What Each Assertion Covers

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

---

## Updating PROOF_STATUS.md

After a successful run:

1. Note the Alloy version (`java -jar alloy.jar --version 2>&1 | head -1`)
2. Update `formal/PROOF_STATUS.md` A1-A15 status to `Verified (Alloy X.Y.Z, YYYY-MM-DD)`
3. Commit alongside any fixes to `ep_relations.als`

If a counterexample is found:
1. Record the counterexample trace in `formal/alloy-counterexample-ANN.txt`
2. Fix the assertion or the underlying model
3. Re-run to confirm fix
4. File a critical bug referencing the counterexample

---

## CI Integration

The Alloy CI workflow runs automatically on every push that touches `formal/*.als`:

```yaml
# .github/workflows/alloy.yml
on:
  push:
    paths:
      - 'formal/*.als'
      - '.github/workflows/alloy.yml'
  workflow_dispatch:
```

The workflow downloads Alloy 6.1.0, compiles the Java runner, and fails the build
if any assertion produces a counterexample. See the workflow file for full details.
