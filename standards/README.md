# EP standards work

This directory holds EMILIA Protocol's specification drafts intended for the
open standards process.

## draft-schrock-ep-authorization-receipts-00

**Authorization Receipts for High-Risk Agent Actions** — the EP receipt as a
protocol: action-bound approver signatures (approver-held keys via WebAuthn),
one-time consumption, separation of duties, offline verification, and honest
conformance classes.

**Status: pre-submission individual draft.** It has not yet been submitted to
the IETF datatracker and has no standing of any kind. We say this plainly for
the same reason the draft's Section 9 exists: claiming a stronger status than
you hold is the category's most common failure, and we hold ourselves to the
rule first. (The same description applies to other individual drafts in this
space, e.g. `draft-nelson-agent-delegation-receipts` — an individual
submission is a proposal, not a standard.)

### Submitting (author checklist)

1. Create an account at <https://datatracker.ietf.org> (email confirmation
   goes to the author address — `team@emiliaprotocol.ai` must be receivable).
2. The submission-ready artifacts are already in this directory, generated and
   validated with xml2rfc 3.34.0:
   - `draft-schrock-ep-authorization-receipts-00.xml` — the file the
     datatracker requires (xml2rfc v3).
   - `draft-schrock-ep-authorization-receipts-00.txt` — the rendered I-D.
   To regenerate after edits: `pip install xml2rfc && xml2rfc <file>.xml --text`.
3. Upload the `.xml` at <https://datatracker.ietf.org/submit/>, confirm via
   the email link. The draft posts within minutes and auto-expires in 185 days
   unless revised (-01, -02, …).
4. Where to discuss: `secdispatch@ietf.org` is the IETF venue for "where does
   new security work belong"; a courtesy note to the DRP author (Section 10
   describes how the two compose) is the collegial move.

### What changed in the 2026-06-09 hardening pass

Five substantive fixes applied before submission, each answering a critique a
first-hour reviewer would raise:

1. **Presentation attacks (§11.3, §11.1)** — "render from the hashed bytes"
   is a restatement of the problem, not a mitigation. High-value policies now
   REQUIRE an independently-authored second rendering surface; §11.1's
   operator-compromise claim is downgraded to what is actually true ("cannot
   forge a signature" ≠ "cannot obtain an unauthorized approval").
2. **Offline verification scope (§6.3, G5)** — offline verification proves
   authenticity and log inclusion at commit time, not non-revocation and not
   log honesty. Stated as a MUST NOT overclaim.
3. **Directory authority (§5.2, new §11.6)** — the Approver Directory root
   MUST be organization-signed, not operator-signed; otherwise the operator
   re-enters the trust path one layer up by enrolling keys it controls.
4. **SoD scope (new §11.7)** — separation of duties defeats unilateral
   self-approval, full stop. It does not defeat collusion, multi-identity
   control, or coercion; receipts make those attributable, not impossible.
5. **Approver fatigue (new §11.8)** — a gate humans route around protects
   nothing. Deployments MUST scope signoff to high-risk low-frequency
   actions; time-to-sign monitoring and consented mismatch drills are the
   operational countermeasures.

Also fixed: CIBA was mis-cited as RFC 9126 (that's OAuth PAR); CIBA is an
OpenID Foundation specification, not an RFC.
