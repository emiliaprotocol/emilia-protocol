# Validation record

Validated on 2026-08-03:

- `xml2rfc 3.34.0` generated the TXT and HTML renderings.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found`.
- The source renders as `Intended status: Standards Track`.
- The governed August 3 six-draft packet still passes
  `node scripts/check-standards-staged.mjs` unchanged.
- `node scripts/check-authorization-receipts-09.mjs` verifies the isolated
  source, renderings, metadata, and checksums.

`xml2rfc` emits its expected informational warning that Standards Track IETF
documents use `consensus="true"`; this is the permitted value for the category.
