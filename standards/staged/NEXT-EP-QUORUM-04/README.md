# Quorum -04 maintenance packet

Published September 6, 2026. Author confirmation completed; public IETF XML matches this packet exactly. Retained for publication provenance, not re-upload.

Submitted XML: `UPLOAD-THIS/draft-schrock-ep-quorum-04.xml`. It is
dated 6 September 2026, an individual IETF Internet-Draft with informational
category. TXT and HTML are in `RENDERS`; exact digests are in `SHA256SUMS.txt`.
The pre-existing `THRESHOLD-SIGNATURES.md` is a separate proposal and has not
been incorporated into this security-maintenance packet.

This revision replaces context-only chronology with the explicit
`EP-QUORUM-SIGNOFF-CHAIN-v1` profile. Each successor's signed context binds a
domain-separated digest of the complete predecessor signoff, including its
actual signature. Old context-only chains cannot silently satisfy the new
strong requirement. Fresh contexts and signatures are required; plain ordered
and threshold policies remain available only where explicitly permitted.

The relying party pins the entire expected policy outside the artifact.
JavaScript/browser and Python use `expectedPolicy`; Go exposes
`VerifyQuorumWithPolicy`. Existing unpinned APIs report internal consistency,
not satisfaction of a trusted organizational floor. The legacy database
template constrains roster ordering but does not configure a causal-chain
floor; no database migration was introduced.

The new profile does not establish trusted time, human comprehension, current
enrollment, unused authority, or execution. Old fixed 2-of-2 symbolic results
do not prove this new construction. Same-team cross-language agreement is a
consistency check, not independent interoperability or a formal proof.
