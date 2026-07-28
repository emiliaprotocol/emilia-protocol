# Coverage Reconciliation Attestation v1

`EP-COVERAGE-RECONCILIATION-ATTESTATION-v1` is a relying-party-signed,
bounded-period reconciliation of two supplied populations:

- the system-of-record population; and
- the EMILIA receipt population.

It is the period-level answer to “which supplied system effects have matching
receipts, and which supplied receipts have matching effects?” It is not a
claim that either inventory is complete.

## Conservation equations

The signer MUST supply counts satisfying both equations:

```text
system_of_record.count =
  matched + effect_without_receipt + excluded + exception

receipt_population.count =
  matched + receipt_without_effect + indeterminate
```

The implementation refuses negative, non-integral, or non-conserving counts.
Both populations carry an inventory identifier and a Merkle or equivalent
population root. The signed body also binds the relying party, Reliance
Program source and compiled digests, period, report hash, issue/expiry times,
and an optional RFC 3161, SCITT, or other evidence reference.

## Claim boundary

Verification establishes only that a trusted relying-party key signed the
exact supplied roots and conserving counts, within the artifact validity
window. It does not establish population completeness, legal compliance,
control effectiveness, insurance coverage, causation, liability, solvency,
payment, or the truth of the underlying source systems.

Implementations MUST NOT call this artifact a proof of full Gate coverage.
Where full-population assurance is required, an independent inventory and
collection control is still necessary.

## API

```js
import {
  signCoverageReconciliationAttestation,
  verifyCoverageReconciliationAttestation,
} from '@emilia-protocol/gate/coverage-reconciliation-attestation';
```

The verifier can pin the expected Reliance Program digest and the issuer key.
Unknown fields and modified signed bytes fail closed.

