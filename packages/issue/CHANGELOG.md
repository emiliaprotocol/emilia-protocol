<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/issue` are documented here.

## Unreleased

### Added

- `strictJsonGate(text, { refuseNoncharacters: true })` also refuses a
  string or member name that holds a Unicode noncharacter after unescaping,
  which I-JSON (RFC 7493) excludes. It is opt-in: without the option the
  gate behaves as before. Callers that decode JSON text carrying a CAID
  action object pass it (draft-schrock-canonical-action-identifier-04,
  Section 2.4).

## 0.7.0 (2026-08-30)

### Added

- Add opt-in `EP-RECEIPT-HYBRID-v1` issuance with Ed25519 and ML-DSA-65 legs,
  custody-resolved issuance posture, and package exports for the hybrid issuer.

### Security

- Keep the signed hybrid algorithm set inside the canonical payload and refuse
  malformed or incomplete issuance inputs before producing a receipt.

## 0.6.4 (2026-08-01)

### Security

- Use the shared strict JSON domain for signed receipt construction so cycles,
  sparse arrays, accessors, symbol members, non-plain objects, and non-JSON
  values fail closed instead of collapsing to ambiguous canonical bytes.
- Clarify that offline authenticity is neither current authorization nor
  one-time admission, and that log checkpoints prove ordering and
  non-alteration rather than independent wall-clock time.

### Packaging

- Ship the strict JSON runtime, declarations, and source map used by the
  published issuer entry point.
