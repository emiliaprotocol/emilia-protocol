# Running TLC on ep_handshake.tla

This document gives exact steps to run the TLC model checker against the
EP handshake protocol specification and record the result.

---

## Prerequisites

- Java 11 or later installed (`java -version`)
- `tla2tools.jar` (the TLA+ model checker, ~6 MB, no other dependencies)

---

## Step 1 — Download tla2tools.jar

```
curl -L -o /usr/local/bin/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
```

Or download manually from:
https://github.com/tlaplus/tlaplus/releases/latest

Verify the download:
```
java -jar /usr/local/bin/tla2tools.jar 2>&1 | head -3
```

---

## Step 2 — Run TLC

From the repo root:

```
cd formal
java -jar /usr/local/bin/tla2tools.jar \
  -config ep_handshake.cfg \
  ep_handshake.tla \
  2>&1 | tee tlc-output.txt
```

TLC will:
1. Parse the spec and config
2. Generate the initial state from `Init`
3. Explore all reachable states via `Next`
4. Check every `INVARIANT` listed in `ep_handshake.cfg` at every state

With `Handshakes = {h1, h2}` and `Actors = {a1, a2}` the state space is large
but finite and tractable on a modern laptop (expect 1–10 minutes).

To use more CPU cores (e.g. 4 workers):
```
java -jar /usr/local/bin/tla2tools.jar \
  -workers 4 \
  -config ep_handshake.cfg \
  ep_handshake.tla \
  2>&1 | tee tlc-output.txt
```

---

## Step 3 — Interpret the output

**Success (all properties hold):**
```
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = ...
```

You will also see a state-space summary like:
```
The number of states found during the model checking job: NNNN
The number of distinct states found during the model checking job: NNNN
```

**Failure (invariant violated):**
```
Error: Invariant <Name> is violated.
```
TLC will print the full error trace showing how it reached the violating state.
Treat this as a critical bug — file an issue before claiming any property is verified.

---

## Step 4 — Record the result

Once TLC finishes with no errors:

1. Commit `tlc-output.txt` alongside `ep_handshake.cfg`:
   ```
   git add formal/ep_handshake.cfg formal/tlc-output.txt
   git commit -m "formal: add TLC cfg and verified output for ep_handshake"
   ```

2. Update `formal/PROOF_STATUS.md`:
   - Change every row that says `Specified — not yet verified` to
     `Verified (TLC, YYYY-MM-DD)` using today's date.
   - Update the "To verify" section to note TLC has been run and link to
     `tlc-output.txt`.
   - Update the `Last updated` line.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `java: command not found` | Install Java: `brew install openjdk` (macOS) |
| `OutOfMemoryError` | Add `-Xmx4G` before `-jar`: `java -Xmx4G -jar tla2tools.jar ...` |
| `Error: Unknown operator` | Ensure you are running from the `formal/` directory so TLC finds the spec |
| State space too large | Reduce to `Handshakes = {h1}`, `Actors = {a1}` in `ep_handshake.cfg` and re-run as a smoke test |
