# Receipt Census v1

`EP-RECEIPT-CENSUS-v1` is a deterministic, governed-taxonomy aggregate with
coarse primary suppression over a
supplied receipt inventory. It is intended for loss-experience analysis,
operations, and underwriter-facing reporting without exporting action payloads
or case-level identities.

Every bucket binds:

- action class;
- Reliance Program version;
- outcome;
- record count;
- open-exposure amount in integer minor units;
- externally reported loss amount in integer minor units; and
- currency.

The relying party pins a closed action-class and outcome taxonomy; unknown
labels fail verification even when the producer signed or generated them. The
producer sets a minimum cell count between 2 and 1,000. Buckets below that
threshold are removed, and only their aggregate bucket and record counts are
retained. The input schema is closed, so raw-payload fields, member-identifier
fields, claim-detail fields, and arbitrary extensions are refused. The
implementation does not inspect the semantic content of relying-party-approved
action/outcome labels. A taxonomy that embeds an identifier in an otherwise
valid label can still disclose it; safe-vocabulary design and review remain
relying-party responsibilities.

The census digest binds the relying party, period, complete Reliance Program
identity (`program_id`, version, source digest, and compiled digest), and
verifier-owned taxonomy digest,
visible buckets, suppression totals, source-inventory digest, and generation
time. The census is not signed by itself; use a signed Coverage Reconciliation
Attestation or a signed Loss Experience Feed to bind it to an accountable
issuer.

## Claim boundary

A census is an aggregate observation with primary suppression over a supplied
inventory. It is not differential privacy and does not by itself prevent
differencing, complementary-cell disclosure, or repeated-query attacks. It
also does not detect identifiers encoded inside allowed taxonomy strings.
Deployments releasing overlapping aggregates require separate query budgets,
secondary suppression, and access audit. It is also not
evidence of causation, insurance coverage, legal liability, adjudicated loss,
solvency, payment, or population completeness. It must remain synthetic and
PHI-free in public examples and conformance material.

```js
import {
  createReceiptCensus,
  receiptCensusTaxonomyDigest,
  validateReceiptCensus,
} from '@emilia-protocol/gate/receipt-census';

const taxonomy = {
  taxonomy_id: 'rp.example.census-taxonomy.v1',
  allowed_action_classes: ['health.prior-authorization'],
  allowed_outcomes: ['executed', 'refused', 'indeterminate'],
};
const census = createReceiptCensus(input, taxonomy);
validateReceiptCensus(census, taxonomy);
receiptCensusTaxonomyDigest(taxonomy); // pin this in relying-party configuration
```
