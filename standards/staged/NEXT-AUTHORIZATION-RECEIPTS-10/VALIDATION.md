# Validation record

Validated on 2026-08-06:

- `xml2rfc` generated the TXT and HTML renderings from the candidate XML; five
  non-semantic trailing spaces in the generated HTML were normalized before
  the packet checksums were recorded.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the
  authoritative TXT rendering. The XML source intentionally omits
  `submissionType` because this remains an individual draft with no adopted
  document stream; `xml2rfc` uses its IETF rendering default and emits an
  informational default warning.
- `node scripts/check-authorization-receipts-10.mjs` verifies the isolated
  source, renderings, metadata, profile split, normative CAID placement, stable
  display refusal names, the CAID-02 revision pin, and checksums.
- `npx vitest run tests/presentation-binding.test.ts` executes sixteen cases,
  including positive binding, unbound and mismatch refusals, independent
  action-hash re-derivation, malformed-input failure closure, untrusted-native
  handling, and OASNT cross-profile composition.
- `node scripts/check-conformance-doc-counts.mjs` confirms the historical
  `EP-TRUST-RECEIPT-v1` harness remains byte-pinned. The candidate and issue
  package expose `EP-AUTHORIZATION-RECEIPT-v1` as the detailed Section 6
  out-of-band profile identifier without rewriting the frozen vector bytes.

The draft remains an individual Internet-Draft and does not assert an adopted
document stream. The source intentionally omits `submissionType`; the
rendering default does not change that status, and the packet checker enforces
the omission. File it only after Datatracker shows CAID-02.
