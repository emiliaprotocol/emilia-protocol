# Bounded Capability Receipts -05 validation

6 September 2026 correction: XML parsing/rendering and idnits were rerun on
the revised bytes. The packet checker passed with refreshed checksums. The
protocol and repository-boundary checks were rerun successfully. The earlier
live PostgreSQL execution described below was not repeated by this editorial
correction. Direct and inherited revocation rechecks at entry and delegated
funding commit remain explicitly unimplemented; the new prose is not runtime
conformance evidence.

- `xmllint --noout`: pass.
- `xml2rfc 3.34.0`: TXT and HTML rendered successfully.
- `idnits 3.1.0`: pass, no nit reported.
- `npm run check:emergency-authority-freeze-drafts`: pass. The checker verifies
  packet identity, required doctrine, forbidden overclaims, render presence,
  checksums, and an executable editorial model of the freeze races.
- `npm run check:protocol`: pass with the repository's existing advisory route
  size warnings and zero critical findings.
- `npm run check:standards-staged`: pass for the six separately governed legacy
  staged sources and their renders.
- `npm run check:repository-boundary`: pass.

The executable editorial cases cover freeze before reservation, freeze between
reservation and provider entry, provider entry before freeze, wrong-holder
retention, no relabeling after provider entry, old-epoch refusal after restore,
continued reconciliation, exact idempotent retry after authority consumption,
conflicting operation identifiers, and one budget transition without double
debit. The reference hostile suite separately executes both freeze/provider
entry serializations against an ephemeral live PostgreSQL 17 instance.

The Implementation Status section identifies the local admission-control epoch
and freeze transaction as same-team reference implementation evidence. It keeps
the disconnected-edge lease, portable signed freeze-event artifact, and atomic
portable detector-capability consumption explicitly unimplemented.
