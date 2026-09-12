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
