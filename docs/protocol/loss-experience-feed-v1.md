# Loss Experience Feed v1

`EP-LOSS-EXPERIENCE-FEED-v1` is a signed, closed-schema batch of externally
reported loss observations linked to one receipt census and one Reliance
Program. It supplies the actuarial input without turning EMILIA into an
insurer, adjudicator, or payment rail.

Each record contains only:

- a record identifier, opaque lineage digest, and receipt digest;
- action class;
- one of `NO_REPORTED_LOSS`, `LOSS_REPORTED`, `NEAR_MISS`, `DISPUTED`, or
  `UNKNOWN`;
- reported amount in integer minor units and currency;
- occurrence and reporting times;
- a source-record digest; and
- an append-only event type.

`OBSERVED` records have no predecessor. `CORRECTED` and `WITHDRAWN` records
MUST identify the digest they supersede. Verification requires a trusted
relying-party lineage store that atomically locks/loads every current head,
invokes the supplied predecessor validator inside that transaction, and only
then registers all successors. A refused validation MUST leave every lineage
unchanged. The validator rederives predecessor digests, confirms current-head
status, and preserves reporter, relying-party, program, receipt, action-class,
currency, and lineage bindings. Missing, withdrawn, stale-head, forked, or
context-mismatched predecessors fail closed. Existing signed history is never
rewritten. Record timestamps must fall within the bounded report period and
must not post-date issuance. Unknown or raw payload fields fail closed.

The feed binds the reporting party, relying party, complete Reliance Program,
census digest, census-taxonomy digest, source-inventory digest, issue/expiry
times, and an optional timestamp evidence reference. The reporting party must
sign with a pinned Ed25519 key. Verifier-owned configuration independently
pins the complete program, census, taxonomy, relying party, and allowed action
classes.

## Claim boundary

The feed verifies who reported which exact observations and, for corrections,
that a trusted atomic lineage transaction accepted the referenced current head
before committing its successor. It does not verify
causation, insurance coverage, legal liability, adjudicated loss, solvency,
payment, authorization, or the truth of the source records. An amount is
always “reported amount,” never “proven loss.”

```js
import {
  signLossExperienceFeed,
  verifyLossExperienceFeed,
} from '@emilia-protocol/gate/loss-experience-feed';

verifyLossExperienceFeed(feed, {
  trusted_keys,
  expected_program,
  expected_census_digest,
  expected_taxonomy_digest,
  expected_relying_party_id,
  expected_action_classes,
  commit_lineage_batch: (request) => lineageStore.validateAndCommit(request),
});
```
