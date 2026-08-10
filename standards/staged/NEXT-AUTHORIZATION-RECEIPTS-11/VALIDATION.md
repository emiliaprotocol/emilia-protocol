# Validation record

Validated on 2026-08-09:

- `xml2rfc` generated the TXT and HTML renderings from the candidate XML; a
  second clean temporary-directory build was byte-identical to both retained
  renderings.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the
  authoritative TXT rendering. The XML source intentionally omits
  `submissionType` because this remains an individual draft with no adopted
  document stream; `xml2rfc` uses its IETF rendering default and emits an
  informational default warning.
- `node scripts/check-authorization-receipts-11.mjs` verifies the isolated
  source, renderings, metadata, normative references, both media-type requests,
  24-case vector inventory, packed-vector byte identity, neutral-core
  implementation guardrail, separate OAuth/RAR profile, and checksums.
- The combined Authorization Bundle and OAuth/RAR profile test run passes 30
  tests:
  24 generated hostile cases, inventory integrity, hostile accessor/proxy
  failure closure, atomic-store helper behavior, and three closed-profile
  OAuth/RAR parsing and matching cases.
- `npm --prefix packages/verify run build` type-checks and emits the package
  runtime and declarations.
- `npm run check:standalone-runtimes` confirms generated Node 20 companions are
  synchronized with their TypeScript sources.
- `npx vitest run tests/presentation-binding.test.ts` executes sixteen cases,
  including positive binding, unbound and mismatch refusals, independent
  action-hash re-derivation, malformed-input failure closure, untrusted-native
  handling, and OASNT cross-profile composition.
- `node scripts/check-conformance-doc-counts.mjs` confirms the historical
  `EP-TRUST-RECEIPT-v1` harness remains byte-pinned. The candidate and issue
  package expose `EP-AUTHORIZATION-RECEIPT-v1` as the detailed Section 6
  out-of-band profile identifier without rewriting the frozen vector bytes.

The Authorization Bundle implementation and vectors are same-repository
evidence, not an external or cross-language interoperability result. The pure
grant-binding helper does not provide a durable store or prove deployment-side
atomicity. The draft remains an individual Internet-Draft and does not assert
an adopted stream. The source intentionally omits `submissionType`; the
rendering default does not change that status, and the packet checker enforces
the omission. This packet has not been submitted.
