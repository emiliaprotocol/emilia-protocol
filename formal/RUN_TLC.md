# Running the EMILIA TLC models

This document reproduces the pinned TLC checks for:

- `ep_handshake.tla`
- `ep_capability.tla`
- `ep_receipt_program.tla`
- `ep_authority_program.tla`
- `ep_trust_program.tla`
- `ep_lifecycle_remedy.tla`
- `ep_consequence_attempt.tla`
- `ep_consequence_attempt_unsafe.tla` (deliberately unsafe negative control)
- `ep_consequence_lifecycle.tla`
- `ep_revocation_witness.tla`
- `ep_effect_profiles.tla`

The checks are bounded safety checks. A clean run means TLC found no
counterexample in each model's checked finite configuration; it is not a proof
of the TypeScript/SQL implementation or an unbounded theorem.

## Prerequisites

- Java 17 (CI uses Temurin 17)
- `curl`
- `shasum` on macOS or `sha256sum` on Linux

## Download and authenticate the pinned checker

Run from the repository root:

```sh
TLA_VERSION=v1.7.4
TLA_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
curl -fsSL -o tla2tools.jar \
  "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
printf '%s  %s\n' "$TLA_SHA256" tla2tools.jar | shasum -a 256 -c -
```

Linux may use this final verification line instead:

```sh
printf '%s  %s\n' "$TLA_SHA256" tla2tools.jar | sha256sum -c -
```

Expected checksum output:

```text
tla2tools.jar: OK
```

The authenticated jar reports:

```text
TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)
```

Do not replace the tagged URL with the mutable `latest` URL. The same version
and checksum are pinned in `.github/workflows/tlc.yml`.

## Run all models

From the repository root:

```sh
cd formal

java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_handshake.cfg \
  ep_handshake.tla \
  2>&1 | tee tlc-output.txt

java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_capability.cfg \
  ep_capability.tla \
  2>&1 | tee tlc-capability-output.txt

java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_receipt_program.cfg \
  ep_receipt_program.tla \
  2>&1 | tee tlc-receipt-program-output.txt

java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_authority_program.cfg \
  ep_authority_program.tla \
  2>&1 | tee tlc-authority-program-output.txt

java -Xmx4G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_trust_program.cfg \
  ep_trust_program.tla \
  2>&1 | tee tlc-trust-program-output.txt

java -Xmx4G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_lifecycle_remedy.cfg \
  ep_lifecycle_remedy.tla \
  2>&1 | tee tlc-lifecycle-remedy-output.txt

java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_consequence_attempt.cfg \
  ep_consequence_attempt.tla \
  2>&1 | tee tlc-consequence-attempt-output.txt

set +e
java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_consequence_attempt_unsafe.cfg \
  ep_consequence_attempt_unsafe.tla \
  > tlc-consequence-attempt-unsafe-output.txt 2>&1
unsafe_status=$?
set -e
if [ "$unsafe_status" -eq 0 ] ||
  ! grep -q "Invariant InvokeAtMostOnce is violated" \
    tlc-consequence-attempt-unsafe-output.txt; then
  echo "The deliberately unsafe replay model did not produce its expected counterexample."
  cat tlc-consequence-attempt-unsafe-output.txt
  exit 1
fi

java -Xmx2G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_consequence_lifecycle.cfg \
  ep_consequence_lifecycle.tla \
  2>&1 | tee tlc-consequence-lifecycle-output.txt

java -Xmx4G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_revocation_witness.cfg \
  ep_revocation_witness.tla \
  2>&1 | tee tlc-revocation-witness-output.txt

java -Xmx4G -jar ../tla2tools.jar \
  -workers auto \
  -config ep_effect_profiles.cfg \
  ep_effect_profiles.tla \
  2>&1 | tee tlc-effect-profiles-output.txt

cd ..
TLA2TOOLS_JAR="$PWD/tla2tools.jar" npm run sync:formal-traces
git diff --exit-code -- formal/results/formal-runtime-refinement.v1.json
```

The generated `tlc-*-output.txt` files are local/CI run artifacts. CI uploads
them for 90 days; they are not required source files. The selected-trace
refinement result is deterministic and checked in because it content-addresses
the model, harness, adapters, and runtime sources.

## Interpret the output

A successful complete check contains:

```text
Model checking completed. No error has been found.
```

It also reports generated/distinct state counts, complete graph depth, and zero
states left on the queue. Record those exact values in `PROOF_STATUS.md` only
after the run completes.

A violation contains output such as:

```text
Error: Invariant <Name> is violated.
```

Preserve the full counterexample trace. Do not rename or weaken a property to
obtain a green run; reconcile the model with the implementation and determine
whether the defect is in the model, the code, or both.

`ep_receipt_program.cfg` intentionally sets `CHECK_DEADLOCK FALSE`: when both
bounded attempts reach `terminal`, the model is correctly quiescent. The model
makes no liveness claim; all listed safety invariants and action properties are
still checked over the complete reachable graph.

## CI

`.github/workflows/tlc.yml` repeats the authenticated download, runs the models,
and regenerates the selected-trace refinement evidence for relevant changes.
CI fails if TLC reports an error, an unsafe mutation is not detected, runtime
projections drift, or regenerated evidence differs from the checked-in bytes.

## Troubleshooting

| Symptom                      | Action                                                                                                                        |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `java: command not found`    | Install a Java 17 runtime.                                                                                                    |
| Checksum mismatch            | Delete the jar and stop; do not execute an unauthenticated artifact. Confirm the pinned release and checksum in the workflow. |
| `OutOfMemoryError`           | Increase `-Xmx2G` locally; do not reduce model bounds without documenting the changed scope.                                  |
| Parse/semantic error         | Run from `formal/` and preserve the exact SANY/TLC diagnostics.                                                               |
| Invariant/property violation | Preserve the trace and treat it as a model-or-implementation defect until resolved.                                           |
