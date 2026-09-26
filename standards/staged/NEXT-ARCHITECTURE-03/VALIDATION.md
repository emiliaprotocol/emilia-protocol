# EMILIA Protocol Architecture -03 validation

6 September 2026 correction: current references and the AuthZEN comparison
were corrected. XML rendering, idnits (no nits), packet checksums, the shared
packet checker, protocol discipline and repository boundaries were checked
again. The PostgreSQL evidence below is prior evidence, not a new runtime run
performed for this editorial correction. Referenced AEC-06 and Quorum-04 are
coordinated corrective packets, not assertions of working-group adoption.

- `xmllint --noout`: pass.
- `xml2rfc 3.34.0`: TXT and HTML rendered successfully.
- `idnits 3.1.0`: pass, no nit reported.
- `npm run check:emergency-authority-freeze-drafts`: pass. The checker verifies
  packet identity, required doctrine, forbidden overclaims, render presence,
  checksums, and the shared freeze-race decision model.
- `npm run check:protocol`: pass with the repository's existing advisory route
  size warnings and zero critical findings.
- `npm run check:standards-staged`: pass for the six separately governed legacy
  staged sources and their renders.
- `npm run check:repository-boundary`: pass.

This architecture revision states protocol boundaries. It records same-team
reference implementation and ephemeral PostgreSQL race evidence for the local
admission-control epoch profile. It does not claim disconnected-edge leases,
independently verifiable freeze events, independent reproduction, or complete
mediation of every adapter path.

## Publication check

Checked on 2026-09-26, when the posted snapshot was mirrored into
`standards/posted/`:

- The Datatracker submission API lists submission 168691 for
  `draft-schrock-ep-architecture` revision 03 in state `posted`, and the
  document record shows revision 03 at 2026-09-06T17:31:40Z, the time of its
  "New version available" event. No later revision exists.
- The IETF archive XML has SHA-256
  `9b37d4911dc32d19198e4a0874ee64256e93a8f851a01553a445027b631371bf` and the
  archive text has SHA-256
  `fe17950838c6432b7562c7cbd84710576acb341cd546f08438e1d74e9b3bc710`. Both
  match `SHA256SUMS.txt` byte-for-byte.
- The archive HTML differs from the retained render. Both record xml2rfc
  3.34.0; the archive copy lists different Python and library versions, and
  its delivery path injects request-specific Cloudflare markup, so the
  retained render stays the checksum-pinned local form. The posted HTML is
  that render with trailing whitespace removed.

Publication is not working-group adoption, RFC status, protocol-owner review,
implementation interoperability, or deployment evidence.
