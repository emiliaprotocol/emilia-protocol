# Loss Experience Feed v1

`EP-LOSS-EXPERIENCE-FEED-v1` is a signed, closed-schema batch of externally
reported loss observations linked to one receipt census and one Reliance
Program. It supplies the actuarial input without turning EMILIA into an
insurer, adjudicator, or payment rail.

Each record contains only:

- a record identifier and receipt digest;
- action class;
- one of `NO_REPORTED_LOSS`, `LOSS_REPORTED`, `NEAR_MISS`, `DISPUTED`, or
  `UNKNOWN`;
- reported amount in integer minor units and currency;
- occurrence and reporting times;
- a source-record digest; and
- an append-only event type.

`OBSERVED` records have no predecessor. `CORRECTED` and `WITHDRAWN` records
MUST identify the digest they supersede. Existing signed history is never
rewritten. Record timestamps must fall within the bounded report period and
must not post-date issuance. Unknown or raw payload fields fail closed.

The feed binds the reporting party, relying party, Reliance Program source and
compiled digests, census digest, source-inventory digest, issue/expiry times,
and an optional timestamp evidence reference. The reporting party must sign
with a pinned Ed25519 key.

## Claim boundary

The feed verifies who reported which exact observations. It does not verify
causation, insurance coverage, legal liability, adjudicated loss, solvency,
payment, authorization, or the truth of the source records. An amount is
always “reported amount,” never “proven loss.”

```js
import {
  signLossExperienceFeed,
  verifyLossExperienceFeed,
} from '@emilia-protocol/gate/loss-experience-feed';
```

