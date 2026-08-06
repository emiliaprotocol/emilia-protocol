# Validation record

Validated on 2026-08-06:

- `xml2rfc` generated the TXT and HTML renderings from the candidate XML; five
  non-semantic trailing spaces in the generated HTML were normalized before
  the packet checksums were recorded.
- `idnits 3.1.0` completed all structural validations. Its remaining findings
  are the expected Standards Track downward-reference review for RFC 8785 and
  the two Standards Track work-in-progress references (CAID and OASNT), plus
  non-blocking BCP 14 and plaintext-indentation suggestions.
- `node scripts/check-authorization-receipts-10.mjs` verifies the isolated
  source, renderings, metadata, profile split, normative CAID placement, stable
  display refusal names, and checksums.
- `npx vitest run tests/presentation-binding.test.ts` executes eight cases,
  including positive binding, unbound and mismatch refusals, independent
  action-hash re-derivation, malformed-input failure closure, untrusted-native
  handling, and OASNT cross-profile composition.
- `node scripts/check-conformance-doc-counts.mjs` confirms the historical
  `EP-TRUST-RECEIPT-v1` harness remains byte-pinned. The candidate and issue
  package expose `EP-AUTHORIZATION-RECEIPT-v1` as the detailed Section 6
  out-of-band profile identifier without rewriting the frozen vector bytes.

The draft remains an individual submission and does not assert an adopted
document stream. `xml2rfc` warns that no `submissionType` is declared and uses
the IETF rendering default; the source intentionally does not claim a stream.
