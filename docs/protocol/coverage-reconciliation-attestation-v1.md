# Coverage Reconciliation Attestation v1

`EP-COVERAGE-RECONCILIATION-ATTESTATION-v1` is a relying-party-signed,
bounded-period reconciliation of two supplied populations:

- the system-of-record population; and
- the EMILIA receipt population.

It is the period-level answer to “which supplied system effects have matching
receipts, and which supplied receipts have matching effects?” It is not a
claim that either inventory is complete.

The attestation format is intentionally separate from population derivation.
`EP-COVERAGE-SOURCE-INVENTORY-v1` signs each supplied minimized population
under its source operator, and `EP-COVERAGE-RECONCILIATION-REPORT-v1`
deterministically joins the two verified populations by the exact pair
`(caid, action_digest)`. Deployments SHOULD use independently controlled source
and receipt operators. The reference runner requires that separation by
default.

## Population derivation

Each minimized record contains exactly:

```json
{
  "record_id": "pas:effect:PA-1002",
  "caid": "caid:1:...",
  "action_digest": "sha256:...",
  "classification": "effect"
}
```

System-of-record classifications are `effect`, `excluded`, or `exception`.
Receipt-population classifications are `receipt` or `indeterminate`. Duplicate
record identifiers, duplicate action joins, a CAID mapped to multiple action
digests, or an action digest mapped to multiple CAIDs fail closed.

The verifier, not the presenter, pins each source-system identifier, source
mapping-profile digest, source-operator identifier, trust key, and verification
time. A valid signature without those verifier-owned context pins is refused.

For the Da Vinci PAS reference path,
`lib/health/davinci-pas-coverage-connector.ts` accepts only an opaque server
record reference. A deployment-owned loader retrieves the authenticated FHIR
resources from the system of record, and the connector recomputes the
PHI-minimized CAID and action digest. It does not accept a client-computed
action identity or raw client-supplied PAS resources.

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
  coveragePopulationRoot,
  runCoverageReconciliation,
  signCoverageSourceInventory,
  verifyCoverageReconciliationReportBinding,
  verifyCoverageSourceInventory,
} from '@emilia-protocol/gate/coverage-reconciliation-runner';

import {
  signCoverageReconciliationAttestation,
  verifyCoverageReconciliationAttestation,
} from '@emilia-protocol/gate/coverage-reconciliation-attestation';
```

The attestation verifier can pin the expected Reliance Program digest, issuer
key, and coverage report hash. The report-binding verifier recomputes the report
hash and compares it with the signed envelope; callers still MUST separately
verify the attestation signature and relying-party context. Unknown fields and
modified signed bytes fail closed.

An executable synthetic reference is available at `/gate/consequence-coverage`. It runs the
real signing, source verification, exact-action join, and attestation code, but
touches no production system and does not claim source-population completeness.
