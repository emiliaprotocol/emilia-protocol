# Bounded Capability Receipts -04 staging packet

Upload only:

`UPLOAD-THIS/draft-schrock-ep-bounded-capability-receipts-04.xml`

The -04 change repairs the scope-profile contract identified in the Agent2Agent review. It defines the mandatory CAID-set attenuation relation, requires reflexivity and transitivity disclosure, distinguishes demonstrated from asserted transitivity, records whether a mechanical proof was run locally or taken from an authenticated conformance record, and prevents local per-hop comparisons from being promoted into chain-wide non-widening without a composable relation.

The prior-run path is version-bound: an authenticated record made against a different profile, rule, complete domain, or procedure is stale and can support only a local result. Reliance on an authenticated matching run remains deliberately permitted and visible to relying-party policy; repeat enumeration is not required merely to avoid disclosing reliance.

This packet is staged only. It has not been submitted to the Datatracker.
