# Validation record

Validated on 2026-08-08 from the isolated -03 candidate packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings.
- `idnits 3.1.0 -m submission` passed with no nit reported.
- A fresh `xml2rfc 3.34.0` rebuild produced TXT and HTML byte-identical to the
  retained renderings.
- The source, TXT, and HTML bytes are pinned in `SHA256SUMS.txt`.
- The focused evidence-challenge suite passed 48 tests, including the
  transport-neutral lifecycle, durable challenge state, RFC 9457 binding,
  status 403, `application/problem+json`, `no-store`, retired 428/media-type
  refusal, and exact-action substitution cases.
- The repository Vitest run passed 8,644 tests with 103 explicit skips across
  521 files. All 11 discovered package suites passed.
- Core, library, application, secure-application, declaration, and SDK
  typechecks passed, and the production Next.js build completed all 767 static
  paths.
- The regenerated formal/runtime conformance artifact passed 78 scenarios,
  51 paired negative controls, and 21 claims. The executable security case and
  governed proof-statistics checks passed against the committed candidate.

The Implementation Status section records same-team core and HTTP-binding
evidence. It does not claim independent interoperability, a DMSC carrier,
admission transfer, or cross-gateway double-admission prevention.

