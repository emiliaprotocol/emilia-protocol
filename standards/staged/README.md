# August 1, 2026 Internet-Draft upload packet

This directory is a submission packet, not a publication record. Upload only
the six XML files in `UPLOAD-THIS/`. `RENDERS/` contains local review copies.
Nothing in `posted/`, `archive/`, or `profiles/` should be uploaded.

Recommended upload order:

1. `draft-schrock-ep-authorization-evidence-chain-05.xml`
2. `draft-schrock-action-evidence-boundary-03.xml`
3. `draft-schrock-model-to-matter-03.xml`
4. `draft-schrock-ep-reliance-agreement-00.xml`
5. `draft-schrock-ep-bounded-capability-receipts-01.xml`
6. `draft-schrock-ep-bounded-execution-program-00.xml`

AEC, AEB, Model-to-Matter, and Bounded Capability Receipts are successor
revisions of active individual drafts. Reliance Agreement and Bounded Execution
Program are new `-00` submissions. A published individual Internet-Draft is not
an RFC, working-group adoption, IETF consensus, or IETF endorsement.

## Claim boundaries

- AEC-05 specifies a new `role_constraints` requirement member. The legacy AEC
  evaluator does not yet implement that member; it currently obtains
  distinct-human evidence through the native `ep-quorum` verifier.
- AEB-03 is implementation-backed but does not prove that a deployment
  completely mediates every effect path.
- Model-to-Matter-03 does not claim physical truth, scientific validation, a
  wet-lab deployment, partner endorsement, or independent implementation. Its
  new program digests are not yet wired into the reference clearance object.
- Reliance Agreement-00 verifies signed terms and digest bindings. It does not
  authorize an action, establish enforceability, issue insurance, determine
  coverage or fault, prove solvency, escrow funds, or compel payment.
- Bounded Capability Receipts-01 conserves delegated authority only within one
  authoritative atomic state domain. It does not provide cross-domain or
  offline global double-spend prevention.
- Bounded Execution Program-00 constrains Gate-observed admissions. It does not
  prove plan understanding, safety, legality, provider truth, effect truth, or
  complete mediation.

Use `ADDITIONAL-RESOURCES.md` or `ADDITIONAL-RESOURCES.json` when completing the
Datatracker form. Enter the tag token and URL in separate form fields.
