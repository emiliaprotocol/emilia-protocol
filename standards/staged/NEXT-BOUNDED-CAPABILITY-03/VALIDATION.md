# Validation record

Validated on 2026-08-08 from the isolated -03 candidate packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings.
- `idnits 3.1.0 -m submission` passed with no nit reported.
- A fresh `xml2rfc 3.34.0` rebuild produced TXT and HTML byte-identical to the
  retained renderings.
- The source, TXT, and HTML bytes are pinned in `SHA256SUMS.txt`.
- The focused Node capability suites passed 75 tests; five PostgreSQL-only
  cases were skipped in that non-database run.
- Against an isolated PostgreSQL 17 instance, the migration-chain integration
  suite passed all 8 cases and the capability suite passed all 58 cases with
  no skips. These runs include both serialized race orderings and the
  migration quarantine for missing or untrusted ancestor policy.
- TLC 2.19 exhaustively explored the bounded revocation model: 24,180 states
  generated, 7,544 distinct, complete depth 8, and no errors.

The Implementation Status section records same-team runtime, PostgreSQL
migration, regression, and bounded-model evidence for `revocation_mode`,
complete ancestor traversal, direct/cascade behavior, unavailable lineage, and
the serialized revocation race. It does not claim independent implementation,
cross-domain cascade enforcement, revocation distribution, or complete
wire-format conformance.
