# Receipt Census v1

`EP-RECEIPT-CENSUS-v1` is a deterministic, privacy-bounded aggregate over a
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

The producer sets a minimum cell count between 2 and 1,000. Buckets below that
threshold are removed, and only their aggregate bucket and record counts are
retained. The input schema is closed: raw payloads, member identifiers, claim
details, and arbitrary extension fields are refused.

The census digest binds the relying party, period, Reliance Program digest,
visible buckets, suppression totals, source-inventory digest, and generation
time. The census is not signed by itself; use a signed Coverage Reconciliation
Attestation or a signed Loss Experience Feed to bind it to an accountable
issuer.

## Claim boundary

A census is an aggregate observation over a supplied inventory. It is not
evidence of causation, insurance coverage, legal liability, adjudicated loss,
solvency, payment, or population completeness. It must remain synthetic and
PHI-free in public examples and conformance material.

```js
import {
  createReceiptCensus,
  validateReceiptCensus,
} from '@emilia-protocol/gate/receipt-census';
```

