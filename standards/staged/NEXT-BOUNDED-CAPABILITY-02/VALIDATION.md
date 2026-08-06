# Validation record

Validated on 2026-08-06 from the isolated -02 working packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings.
- `idnits 3.1.0 -m submission` passed with no nit reported.
- The source, TXT, and HTML bytes are pinned in `SHA256SUMS.txt`.
- A fresh `xml2rfc 3.34.0` rebuild produced TXT and HTML byte-identical to the
  committed renderings.
- The August 3 six-draft publication provenance packet remains unchanged.
- `npm --prefix packages/gate run build`: pass.
- Focused capability-receipt runtime: 47 passed, 4 PostgreSQL tests skipped
  because `ADMISSION_STORE_POSTGRES_TEST_URL` was not configured.
- The focused cases include cross-domain aggregate refusal, explicit
  single-executor fallback, policy-shaped human-proof substitution refusal,
  wrong-action human-proof refusal, and one admitted exact-action composition.

The state-domain digest is a relying-party deployment binding. These checks do
not prove that two independently configured processes reach the same physical
database, and the skipped PostgreSQL cases are not represented as passing.

This packet is a working maintenance revision. It has not been filed and does
not change the posted -01 snapshot or the repository's published-status record.
