# AAIF — Cover Email

**Recipient**: AAIF program intake (verify current email — last referenced
contact is in `docs/AAIF-PROPOSAL-v3.md` itself; cross-check at
https://aaif.org/ or via direct ask if unclear).
**Attachment**: `docs/AAIF-PROPOSAL-v3.md` (already drafted in repo).
**Status**: Ready to send.

---

## Subject

EMILIA Protocol — AAIF proposal v3 (formal-verified pre-action authorization for AI agents)

## Body

Hello,

Submitting EMILIA Protocol (EP) for AAIF consideration. EP is an open
standard and Apache-2.0 reference runtime for verifiable pre-action
authorization in AI agent systems — the layer between model capability
and action execution.

The full proposal is attached as `AAIF-PROPOSAL-v3.md`. The headline
numbers reviewers usually want first:

- **Formal verification**: 26 TLA+ properties verified by TLC 2.19
  (T1–T26, 413,137 states explored, 0 errors). 35 Alloy relational facts
  + 15 assertions verified by Alloy 6.0.0 (0 counterexamples).
  All re-run on every commit in CI.
- **Test surface**: 3,483 automated tests across 132 files. 85 cataloged
  red-team / adversarial cases.
- **Compliance mappings**: 38 NIST AI RMF subcategories across all four
  RMF functions; EU AI Act Articles 9–15 + 26.
- **License**: Apache 2.0, irrevocable. No open-core bait-and-switch —
  the protocol is fully open; the managed cloud is the commercial layer.

What we are asking AAIF for is in the body of the proposal — the
short version is funding to ship a federation reference deployment,
complete the cross-language verification ports (Python, Go, Rust),
and underwrite a third-party crypto audit so the verification library
can be trusted by external operators without case-by-case review.

Happy to walk through any section, demo the live system, or talk
through the formal models. Public artifacts (repo, formal proofs,
compliance mappings) are linked at the bottom of the proposal for
reviewers who want to verify before the call.

Best,
Iman Schrock
Founder, EMILIA Protocol
iman@emiliaprotocol.ai
github.com/emiliaprotocol

---

## Submission notes

- The AAIF proposal v3 lives at `docs/AAIF-PROPOSAL-v3.md`. Today's
  numbers there are accurate as of 2026-04-30 — verify they match the
  PROOF_STATUS.md before sending in case main has moved.
- Recommended attachments alongside the proposal:
  - `formal/PROOF_STATUS.md`
  - `docs/conformance/RED_TEAM_CASES.md` (or its TOC)
  - `docs/compliance/NIST-AI-RMF-MAPPING.md`
  - `docs/compliance/EU-AI-ACT-MAPPING.md`
  - `docs/security/AUDIT_METHODOLOGY.md`
- The AAIF program may have a web submission form (if so, paste body
  text into the form's free-text field and upload the proposal as PDF).
  Convert the markdown to PDF via `pandoc docs/AAIF-PROPOSAL-v3.md -o aaif-proposal-v3.pdf`
  before sending if the recipient prefers PDF.
