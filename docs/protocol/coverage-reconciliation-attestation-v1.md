# Coverage Reconciliation Attestation

`EP-COVERAGE-RECONCILIATION-ATTESTATION-v2` is a relying-party-signed,
bounded-period reconciliation of two supplied populations:

- the system-of-record population; and
- the EMILIA receipt population.

It is the period-level answer to "which supplied system effects have matching
receipts, and which supplied receipts have matching records in the supplied
system population?" It is not a claim that either inventory is complete.

The attestation format is intentionally separate from population derivation.
`EP-COVERAGE-SOURCE-INVENTORY-v2` signs each supplied minimized population
under its source operator, and `EP-COVERAGE-RECONCILIATION-REPORT-v2`
deterministically joins the two verified populations by the exact pair
`(caid, action_digest)`. Deployments SHOULD use independently controlled source
and receipt operators. The reference runner requires that separation by
default.

## Changes from v1

Version 2 of the schema family makes three changes. Artifacts signed under the
v1 version strings fail closed under v2 verifiers; there is no compatibility
alias for the renamed field.

1. The bin previously named `receipt_without_effect` is renamed
   `receipted_without_observation`. The join only establishes that a receipt
   has no matching record in the supplied source population; it does not
   establish that no effect occurred. The old name claimed more than the code
   proves.
2. Every `excluded` and `exception` record carries a `classification_rule_id`
   (see below). A record whose rule id is missing or does not resolve is
   reclassified to the new system-side `system_indeterminate` bin instead of
   being treated as excluded.
3. The runner asserts, before emitting any report, that the bin counts sum
   back to the signed record counts of both populations, and refuses with
   `population_conservation_violation:<side>` on violation.

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

`excluded` and `exception` records additionally carry a
`classification_rule_id`: the id of the rule, under the pinned mapping
profile, that produced the classification. The field is part of the record,
so the signed population root covers it; tampering with a rule id is a
`population_root_mismatch`. The field is forbidden on every other
classification. The current resolution set is the compiled-in registry
`EP-COVERAGE-CLASSIFICATION-RULES-v1` (`COVERAGE_CLASSIFICATION_RULES`); rule
ids are stable and versioned, and declared mapping-profile rules replace the
compiled-in registry when mapping-profile documents ship. A record whose rule
id is missing, unknown, or bound to a different classification is demoted to
`system_indeterminate` with a `reclassification_reason` of
`classification_rule_missing` or `classification_rule_unresolved`. An
unresolvable rule never widens an exclusion and never refuses the population.

The verifier, not the presenter, pins each source-system identifier, source
mapping-profile digest, source-operator identifier, trust key, and verification
time. A valid signature without those verifier-owned context pins is refused.

For the Da Vinci PAS reference path,
`lib/health/davinci-pas-coverage-connector.ts` accepts only an opaque server
record reference. A deployment-owned loader retrieves the authenticated FHIR
resources from the system of record, and the connector recomputes the
PHI-minimized CAID and action digest. It does not accept a client-computed
action identity or raw client-supplied PAS resources. Its projection requests
require a `classification_rule_id` for `excluded` and `exception` and forbid
it for `effect`.

## Conservation equations

The runner and the signer MUST produce counts satisfying both equations
against the SIGNED record counts:

```text
system_of_record.count =
  matched + effect_without_receipt + excluded + exception
  + system_indeterminate

receipt_population.count =
  matched + receipted_without_observation + indeterminate
```

`excluded`, `exception`, and `system_indeterminate` are system-side-only
bins; `indeterminate` (source-declared) and `receipted_without_observation`
are receipt-side-only bins; `matched` consumes one record from each side.
The runner refuses with `population_conservation_violation:system` or
`population_conservation_violation:receipt` instead of emitting a report when
the sums do not reconcile, and the report carries both signed counts and all
bin counts so a reader can re-check the sums independently. The attestation
implementation additionally refuses negative, non-integral, or non-conserving
counts at sign and verify time. Both populations carry an inventory
identifier and a Merkle or equivalent population root. The signed body also
binds the relying party, Reliance Program source and compiled digests, period,
report hash, issue/expiry times, and an optional RFC 3161, SCITT, or other
evidence reference.

## Claim boundary

Verification establishes only that a trusted relying-party key signed the
exact supplied roots and conserving counts, within the artifact validity
window. It does not establish population completeness, legal compliance,
control effectiveness, insurance coverage, causation, liability, solvency,
payment, or the truth of the underlying source systems. In particular,
`receipted_without_observation` does not establish that no effect occurred;
it establishes only that no matching record was present in the supplied
source population.

Implementations MUST NOT call this artifact a proof of full Gate coverage.
Where full-population assurance is required, an independent inventory and
collection control is still necessary.

## API

```js
import {
  COVERAGE_CLASSIFICATION_RULES,
  assertCoveragePopulationConservation,
  coveragePopulationRoot,
  resolveCoverageClassificationRule,
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
