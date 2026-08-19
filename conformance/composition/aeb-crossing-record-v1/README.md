# Carrier-neutral AEB crossing-record reproduction kit

This kit exercises `EP-AEB-CROSSING-RECORD-v1`: a signed, state-domain-bound
record that one relying-party boundary evaluated one exact action under one
verified native authority instance. The record is evidence of a past crossing.
It never authorizes a later crossing.

Run from the repository root:

```sh
npm run conformance:composition:crossing-record
```

The reference mappings deliberately come from different authority systems:

- a WIMSE/OAuth authorization-server decision; and
- an EMILIA bounded-capability receipt.

They share an open-set projection contract and one record verifier. They do not
produce identical records and the kit does not claim their native semantics are
equivalent. A conformant local boundary may narrow accepted native authority to
a refusal. It may never broaden rejected, stale, or indeterminate authority to
an admission.

## Covered attacks and boundaries

- action, replay-unit, and mapping-profile substitution;
- Ed25519 or ML-DSA-65 leg stripping;
- wrong relying-party verification key;
- stale authority flattened into current authority;
- missing admission evidence reported as admission;
- native rejection broadened into local admission; and
- carrier metadata injected into the signed record contract.

The committed report digest is the reproduction contract. Regenerate it only
for a deliberate semantic change, never to silence a failing test.

## Honest scope

A passing report verifies the EMILIA reference implementation against the
committed cases. It is not an independent implementation, does not prove that
all native authority formats are supported, and is not evidence of IETF
adoption, certification, endorsement, or production deployment.

