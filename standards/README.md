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

## draft-schrock-ep-quorum-01

**Multi-Party Quorum Authorization (EP-QUORUM)** — M-of-N / ordered approval over
*distinct* humans (the two-person rule) binding a quorum to one exact action;
purely additive over the base receipt. **Status: posted individual Internet-Draft
(2026-06-21).** Source: `draft-schrock-ep-quorum-01.{xml,txt}`.

## draft-schrock-ep-authorization-evidence-chain-00

**Authorization Evidence Chains (EP-AEC)** — the composition layer. Verifies that,
for ONE action, heterogeneous receipts (delegation, policy-permit, human
authorization) all bind the same canonical action digest and each verify, yielding
a single offline ALLOW/DENY. Introduces no new receipt type; composes the cluster
(DRP, Permit Receipts, ACTA, AgentROA) as pluggable component types and supplies
the human-authorization leg none of the others do. Fills the composition gap the
2026-06 landscape survey (`docs/strategy/AGENT-AUTHORIZATION-LANDSCAPE-2026.md`)
identified as the most-validated unowned slot.

**Status: POSTED on datatracker as -00 (2026-06-22); verified live 2026-06-26. Content current — only file -01 if a substantive change is made (do NOT re-file -00).** Reference verifier `packages/verify/evidence-chain.js`;
conformance vectors `conformance/vectors/aec.json` (JS/Python/Go agree). Source:
`draft-schrock-ep-authorization-evidence-chain-00.{xml,txt}`.

## draft-schrock-ep-evidence-record-00

**Long-Term, Crypto-Agile Preservation of Authorization Evidence
(EP-EVIDENCE-RECORD)** — an RFC 4998 (ERS)-style renewal chain that keeps EP
receipts verifiable across algorithm aging (sha256 → sha384 → …) for multi-year
retention obligations (DORA, HIPAA, SEC 17a-4). Offline, fail-closed. Fills the
long-term-preservation gap the landscape survey found unowned.

**Status: written + render-clean, NOT yet filed (file standalone -00; EP-AEC is already posted). Verified 2026-06-26: not on datatracker.**
Tri-language verifier `packages/verify/evidence-record.js`. Source:
`draft-schrock-ep-evidence-record-00.{xml,txt}`.

## draft-schrock-emilia-eye-00

**Verifiable, Scope-Bound Advisories for Authorization Posture (EMILIA Eye)**
— a scope-bound statement that an authorization posture for a named scope has
changed, designed to be signed and offline-verifiable, carrying a
scope-binding hash that prevents replay or re-targeting to a different scope.
The central normative invariant: an advisory MUST NEVER be the sole gate on an
action — a signal may only TIGHTEN posture, never itself constitute the
authorization.

**Status: written + render-clean, NOT yet filed (intended status: Experimental). Verified 2026-06-26: not on datatracker.**
As with every draft in this directory, "posted" means accepted and published —
it does **not** mean adopted: this is an individual submission with no IETF
working-group standing, no RFC stream, and no endorsement. We say this plainly
because claiming a stronger status than you hold is the category's most common
failure, and we hold ourselves to the rule first.

### Source artifacts

- `draft-schrock-emilia-eye-00.xml` — the xml2rfc v3 source.
- `draft-schrock-emilia-eye-00.txt` — the rendered I-D.

## draft-schrock-scitt-authorization-evidence-00

**A Human-Authorization Evidence Profile for SCITT Agent-Action Statements** —
the composition profile that makes EP citable *by* the SCITT agent-action
cluster (permit profiles, action-receipt envelopes, action capsules,
post-execution evidence). It defines how a host statement references a
named-human (or quorum) authorization receipt
(`draft-schrock-ep-authorization-receipts`) **by digest** — subject digest =
`SHA-256(JCS(action))`, authority-reference digest = `receipt_payload_digest`
(offline) or `statement_digest` (when registered as a SCITT Signed Statement) —
and the fail-closed verification that binds the recorded action to the human
authorization. Composes by digest, not containment; defines no log, envelope,
policy language, or identity scheme. Verdict-complete (a denied authorization
is itself a referenced signed event).

**Status: written + render-clean (xml2rfc v3), NOT yet filed (intended status: Informational).**
"Posted" is not "adopted" — individual submission, no working-group standing.
Runnable companions: `examples/scitt/ep-receipt-scitt-end-to-end.mjs`,
`examples/scitt/capsule-seam-vector.mjs`; engagement frame in
`docs/standards-engagement/EP-HUMAN-AUTHORIZATION-RECEIPT-PROFILE.md`.

### Source artifacts

- `draft-schrock-scitt-authorization-evidence-00.xml` — the xml2rfc v3 source.
- `draft-schrock-scitt-authorization-evidence-00.txt` — the rendered I-D.

## draft-schrock-agent-action-manifest-00

**The Agent Action Manifest** — the robots.txt / CORS / SBOM-tier declaration
standard for dangerous machine actions. A service publishes
`/.well-known/agent-actions.json` declaring which of its actions are
consequential, the assurance class each requires, and the 428 challenge an
agent receives when it attempts one without a valid authorization receipt
(`draft-schrock-ep-authorization-receipts`). Machine-readable so an agent
self-serves the requirement and an independent scanner can audit it. Declares
policy; does **not** replace enforcement (the boundary is authoritative — a
manifest can't be edited to disable protection). Formalizes the shipped
`EP-ACTION-RISK-MANIFEST` fixture at `public/.well-known/agent-actions.json`.
Requests registration of the `agent-actions.json` well-known URI (RFC 8615).

**Status: written + render-clean (xml2rfc v3), NOT yet filed (Informational, individual submission).**

### Source artifacts

- `draft-schrock-agent-action-manifest-00.xml` — the xml2rfc v3 source.
- `draft-schrock-agent-action-manifest-00.txt` — the rendered I-D.

## draft-schrock-ep-assurance-classes-00

**Assurance Classes for Authorization Receipts** — the policy primitive for
*how strong* the human authorization must be. Defines an ordered taxonomy —
Class C (software signer) < Class B (authenticated human, reserved/optional) <
Class A (device user-verified human) < Class Q (quorum of distinct humans) —
mapped to the receipt assurance values `software` / `class_a` / `quorum`; the
monotonic comparison rule (required class satisfied iff proven class ≥ it); and
the anti-forgery invariant that a **claimed** class is treated as Class C until
**proof-backed** (matches the shipped gate: `TIER_RANK` + self-asserted tier =
software floor). Consumed by the manifest, enforcement-point, and authority-registry profiles.

**Status: written + render-clean (xml2rfc v3), NOT yet filed (Informational, individual submission).**

### Source artifacts

- `draft-schrock-ep-assurance-classes-00.xml` — the xml2rfc v3 source.
- `draft-schrock-ep-assurance-classes-00.txt` — the rendered I-D.

## draft-schrock-ep-authority-registry-00

**A Human Authority Registry for Agent-Action Authorization** — the record a
verifier consults to decide whether the human who signed was *entitled* to
approve this action class, for this org, in this window, with this key, and
whether self-approval is barred. Orthogonal to WIMSE (workload identity);
complementary to delegation / evidence-chain. Defines the authority entry, the
`authority-backed` verification rule (key resolves to an active in-scope entry;
class within `action_classes`; proven assurance ≤ `max_assurance_class`; SoD;
quorum distinctness), and signed-snapshot offline verification with a freshness
bound. Grounds the shipped `createKeyRegistry` + `lib/revocation` + SoD
primitives as a claimable standard.

**Status: written + render-clean (xml2rfc v3), NOT yet filed (Informational, individual submission).**

### Source artifacts

- `draft-schrock-ep-authority-registry-00.xml` — the xml2rfc v3 source.
- `draft-schrock-ep-authority-registry-00.txt` — the rendered I-D.

## draft-schrock-ep-enforcement-point-00

**An Enforcement-Point Profile for Authorization Receipts (EP)** — a Policy
Enforcement Point (PEP) profile that composes on the shared verifier core in
`draft-schrock-ep-authorization-receipts`. It gives an enforcement point a
small, stable contract: a registered decision vocabulary (`allow` /
`allow_with_signoff` / `deny`, with an out-of-band `observe` mode), a
decision-request/response schema bound to the exact action under evaluation,
and a requirement that every decision be bound to an offline-verifiable
EP-RECEIPT-v1. Conformance requires fail-closed behavior on uncertainty,
honoring of one-time consumption, and receipt emission.

**Status: written + render-clean, NOT yet filed (intended status: Informational). Verified 2026-06-26: not on datatracker.**
Same honest caveat applies as above: "posted" is not "adopted" — this is an
individual submission with no IETF working-group standing, no RFC stream, and
no endorsement.

### Source artifacts

- `draft-schrock-ep-enforcement-point-00.xml` — the xml2rfc v3 source.
- `draft-schrock-ep-enforcement-point-00.txt` — the rendered I-D.
