# Action Evidence Boundary -04 publication-provenance packet

This packet contains the exact source submitted as
`draft-schrock-action-evidence-boundary-04`. It was posted by the IETF
Datatracker on 2026-08-16 as submission 167790. The immutable archive XML is
byte-for-byte identical to `UPLOAD-THIS/draft-schrock-action-evidence-boundary-04.xml`.

Revision -04 adds one executor-side input without changing AEB's neutral-waist
role: a relying party may require a native field-origin assertion for selected
action fields before admission. The assertion verifier, trusted issuer and key,
field selectors, allowed origin classes, versioned transformations, snapshot
policy, freshness, and unavailable-input behavior remain relying-party pins.

The claim boundary is explicit. A successful verifier result establishes that
a pinned issuer signed an assertion about field origin and that the assertion
matches the observed action. It does not independently prove where the bytes
truly originated, detect prompt injection generally, authorize the action,
settle it, or prove an external effect.

`EP-FIELD-ORIGIN-v0.1` and the 14-case Gap 6 runner are informative
same-repository implementation evidence. They are not a mandatory AEB wire
format, an independent implementation, IETF adoption, or an interoperability
result.

This retained packet is publication provenance, not an upload candidate.
