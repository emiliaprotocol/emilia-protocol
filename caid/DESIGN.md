# CAID design: where the rules live

This file is no longer normative. The normative text of CAID is the
Internet-Draft `draft-schrock-canonical-action-identifier` (revision -04,
staged at `../standards/staged/NEXT-CAID-04/`; the posted -03 is at
`../standards/posted/`). Where this directory and the draft disagree, the
draft wins and this directory has a bug.

Everything else here is derived from the draft or governed by it:

| What | Where | Status |
| --- | --- | --- |
| Grammar (identifier, digest syntax, field types, code formats, field names, JSON Pointer, reasons) | `spec/caid.abnf` | Derived: the draft's Appendix A carries it verbatim (`scripts/check-caid-04.mjs` compares them) |
| Limits, reason codes and phase ranks, field-type member lists, definition projection, verification details, mapping closed sets | `spec/core.json` | Derived: machine-read data, no prose rules |
| Constants compiled into the JavaScript, Python and Go ports and the vendored Verify copy | `spec/gen.mjs` (`--write`, `--check`) | Generated from the two files above and `registry/suites.json` |
| Proof that every generated matcher equals the grammar and is linear-time safe | `spec/abnf-check.mjs` | Dev-time check |
| Reference validator used by the registry check | `spec/reference.mjs` | Dev-time tooling, not a port |
| Action types, suites, value sets, frozen registry versions, definition digests | `registry/` | Governed by `registry/GOVERNANCE.md` |
| Reference implementations | `impl/js`, `impl/python`, `impl/go` | Conform to the draft |
| Conformance corpora | `conformance/`, `interop/` | Shared by every port |

## Former sections of this file

Earlier revisions of this file carried the normative core under numbered
sections that other documents still cite. Each now lives in the draft:

| Former section | Draft section |
| --- | --- |
| Design goals, "What this is" | Introduction |
| 1. The action object | Data Model and JSON Input (the action object, data model, numbers, JSON text input, host values) |
| 2. Suites and the identifier | Suites and the Identifier; Appendix A |
| 3. Action types and the registry | Action Types and the Registry (type definitions, definition conformance and digest, field types, code formats, enum resolution); `registry/GOVERNANCE.md` |
| 4. Computation and verification | Computation; Verification; Appendix B (reason codes) |
| 5. Action-Mapping Profile | Action-Mapping Profile |
| 6. What CAID is NOT | What a CAID Is Not |
| 7. Security considerations | Security Considerations; Privacy Considerations |
| 8. Naming note | This file, below |
| 9. Package layout | The table above |
| 10. Publication boundary | This file, below |

The text of the former sections is in the repository history of this file.

## Naming note

"CAID" was chosen over "CAI" deliberately: CAI collides with the Content
Authenticity Initiative (C2PA's sister organization) in the adjacent
provenance space. CAID's known collision (a Chinese advertising identifier)
is remote from this domain. Pronounce "kay-eye-dee" or "kade".

## Publication boundary

The core, registry, implementations, vectors, and draft are intended as open
infrastructure. A binding note in `bindings/` is not a claim that the named
protocol has adopted CAID; external submissions and announcements require
their own review and approval.
