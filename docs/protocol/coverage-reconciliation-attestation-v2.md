# Coverage Reconciliation Attestation v2

`EP-COVERAGE-RECONCILIATION-ATTESTATION-v2` is a relying-party-signed,
bounded-period reconciliation of two supplied populations:

- the system-of-record population; and
- the EMILIA receipt population.

It answers which supplied system observations have matching receipts and which
supplied receipts have matching system observations. It does not prove that an
effect did or did not occur, and it does not establish that either inventory is
complete.

`EP-COVERAGE-SOURCE-INVENTORY-v2` signs each supplied minimized population
under its source operator. `EP-COVERAGE-RECONCILIATION-REPORT-v2`
deterministically joins the two verified populations by the exact pair
`(caid, action_digest)`. Deployments SHOULD use independently controlled source
and receipt operators. The reference runner requires that separation by
default.

## Population derivation

An ordinary observation or receipt contains exactly:

```json
{
  "record_id": "pas:effect:PA-1002",
  "caid": "caid:1:...",
  "action_digest": "sha256:...",
  "classification": "effect"
}
```

Every `excluded` or `exception` system record also contains a required
`classification_rule_id`:

```json
{
  "record_id": "pas:excluded:PA-1003",
  "caid": "caid:1:...",
  "action_digest": "sha256:...",
  "classification": "excluded",
  "classification_rule_id": "rule:non-adverse-disposition"
}
```

The rule identifier is part of the signed population root. It identifies the
mapping-profile rule the source operator says it applied. It does not prove
that the exclusion was factually or legally correct.

System-of-record classifications are `effect`, `excluded`, or `exception`.
Receipt-population classifications are `receipt` or `indeterminate`. Duplicate
record identifiers, duplicate action joins, a CAID mapped to multiple action
digests, or an action digest mapped to multiple CAIDs fail closed.

The verifier, not the presenter, pins each source-system identifier, source
mapping-profile digest, source-operator identifier, trust key, and verification
time. A valid signature without those verifier-owned context pins is refused.

## Reconciliation outcomes

The v2 report uses observation-bounded names:

- `matched`
- `observed_without_receipt`
- `receipted_without_observation`
- `indeterminate`
- `excluded`
- `exception`

In particular, `receipted_without_observation` means only that no matching
system observation exists in the supplied population. It is not evidence that
the external effect did not occur.

## Conservation equations

```text
system_of_record.count =
  matched + observed_without_receipt + excluded + exception

receipt_population.count =
  matched + receipted_without_observation + indeterminate
```

The implementation refuses negative, non-integral, or non-conserving counts.
Both populations carry an inventory identifier and a population root. The
signed body also binds the relying party, Reliance Program source and compiled
digests, period, report hash, issue and expiry times, and an optional RFC 3161,
SCITT, or other evidence reference.

## Claim boundary

Verification establishes only that a trusted relying-party key signed the
exact supplied roots and conserving counts within the artifact validity
window. It does not establish population completeness, legal compliance,
control effectiveness, insurance coverage, causation, liability, solvency,
payment, or the truth of the underlying source systems.

Implementations MUST NOT call this artifact a proof of full Gate coverage.
Where full-population assurance is required, an independent inventory and
collection control is still necessary.

The reference verifier continues to accept correctly signed v1 attestations
and source inventories for migration. New issuance uses v2. Verifiers do not
reinterpret a v1 outcome name as a stronger v2 claim.
