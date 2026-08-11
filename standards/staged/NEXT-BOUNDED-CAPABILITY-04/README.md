# Bounded Capability Receipts -04 staging packet

Upload only:

`UPLOAD-THIS/draft-schrock-ep-bounded-capability-receipts-04.xml`

The -04 change repairs the scope-profile contract identified in the Agent2Agent review. It defines the mandatory CAID-set attenuation relation, requires reflexivity and transitivity disclosure, distinguishes demonstrated from asserted transitivity, records whether a mechanical proof was run locally or taken from an authenticated conformance record, and prevents local per-hop comparisons from being promoted into chain-wide non-widening without a composable relation.

The prior-run path is content-bound: an authenticated record made against a different profile, relation rule, complete domain, or procedure contributes no current comparison result. Reliance on an authenticated, matching run from a relying-party-trusted runner remains deliberately permitted and visible to relying-party policy; repeat enumeration is not required merely to avoid disclosing reliance.

The publication red team also closes four composition attacks: independently transitive but heterogeneous relations cannot be chained, off-domain values cannot inherit a finite-domain proof, a self-authenticated but untrusted runner cannot establish the property, and local-only evidence cannot establish authority across a multi-hop delegation path. It also aligns operation identity with the capability-scoped runtime key, defines replay-preserving `not_entered` restoration, makes issuance consumption plus root registration idempotent and reconcilable, and separates budget reservation from freshness of mutable external predicates. The packet checker executes paired positive and negative decision-model controls for the relation and operation-key cases. These are editorial controls over the normative contract, not an implementation-conformance claim.

This packet is staged only. It has not been submitted to the Datatracker.
