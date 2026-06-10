# EP standards work

This directory holds EMILIA Protocol's specification drafts intended for the
open standards process.

## draft-schrock-ep-authorization-receipts-00

**Authorization Receipts for High-Risk Agent Actions** — the EP receipt as a
protocol: action-bound approver signatures (approver-held keys via WebAuthn),
one-time consumption, separation of duties, offline verification, and honest
conformance classes.

**Status: posted individual Internet-Draft (2026-06-09).** Live on the
datatracker:
<https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/>.
"Posted" means accepted and published — it does **not** mean adopted: this is
an individual submission with no IETF working-group standing, no RFC stream,
and no endorsement. We say this plainly for the same reason the draft's
Section 9 exists: claiming a stronger status than you hold is the category's
most common failure, and we hold ourselves to the rule first. (The same
description applies to other individual drafts in this space, e.g.
`draft-nelson-agent-delegation-receipts` — a posted individual submission is a
proposal, not a standard.)

The -00 idnits check passed with zero errors; the one warning (non-ASCII
em-dashes / curly quotes) is queued for the -01 cleanup. -00 is otherwise
frozen — changes go into -01, driven by reviewer and pilot feedback.

### Source artifacts

Generated and validated with xml2rfc 3.34.0:
- `draft-schrock-ep-authorization-receipts-00.xml` — the datatracker source (xml2rfc v3).
- `draft-schrock-ep-authorization-receipts-00.txt` — the rendered I-D.

Regenerate after -01 edits: `pip install xml2rfc && xml2rfc <file>.xml --text`.
The draft auto-expires 185 days after posting unless revised (-01, -02, …).

### Next (post-submission)

1. **Announce on `secdispatch@ietf.org`** (subscribe before posting) — the IETF
   venue for "where does new security work belong." Ask for dispatch guidance.
2. **Courtesy note to the DRP author** (`ryan@authproof.dev`) — Section 10
   describes how EP and DRP compose; the collegial move is to ask whether that
   framing is fair to DRP. Convert a potential rival into a peer.
3. **-01**: fold in reviewer + pilot feedback and the idnits ASCII cleanup.

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
