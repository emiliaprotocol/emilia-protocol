# Validation record

Validated on 2026-08-06 from the isolated CAID -02 working packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings. The generated HTML's
  non-semantic trailing spaces were normalized before checksums were recorded.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the
  authoritative TXT rendering.
- The source intentionally omits `submissionType` because this remains an
  individual draft with no adopted document stream. `xml2rfc` uses its IETF
  rendering default and emits an informational warning. It also renders the
  Standards Track category with the required consensus default.
- `node caid/conformance/run.mjs` passed the registry identity check and all
  existing JavaScript, Python, and Go core, mapping, and consequential-action
  vectors.
- `node scripts/check-caid-02.mjs` verifies Standards Track metadata, current
  receipts/AEB/AEC/OASNT references, absence of stale revision strings, the
  `tool.call.1` public registry shape, the independently recomputed example
  CAID, render status, and all three checksums.
- A fresh `xml2rfc 3.34.0` rebuild, followed by the same HTML whitespace
  normalization, produced TXT and HTML byte-identical to the staged renders.

This packet is staged and unfiled. It must follow receipts-10 so its reference
to that revision resolves when CAID-02 is submitted.
