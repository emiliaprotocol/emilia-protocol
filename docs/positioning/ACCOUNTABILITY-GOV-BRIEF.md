# Who Answers for the AI? — The Two-Way Protection Brief

**Date:** 2026-06-12
**Audience:** Government finance, treasury, and CIO conversations — pilot calls, NASCIO briefings, ACFE webinars.
**Companion:** [`docs/pilots/GOVGUARD-PILOT-OFFER.md`](../pilots/GOVGUARD-PILOT-OFFER.md) — the 60-day observe-mode pilot this brief points to.

---

## 1. The fear, named plainly

When AI touches disbursements, a named official answers for it. For public money, that is already statute:

- **Ohio** (Rev. Code § 9.39): *"All public officials are liable for all public money received or collected by them or by their subordinates under color of office."* Strict liability — ordinary care is no defense.
- **Washington** (Const. art. XI, § 5, as amended by Amendment 12): county officers face "strict accountability" for public moneys — the AG has read that as accountability *"irrespective of the cause of their loss"* (AGO 1953 No. 94).
- **Minnesota** (Stat. § 385.18): the county treasurer and bond sureties are released from liability for lost deposits **only** when the funds sat in the statutorily designated depository.

Notice the structure of that last one: liable by default, released by provable compliance with a prescribed control. An authorization receipt is the kind of proof such a regime rewards — a named human approved this exact disbursement, on their own device, before the money moved, verifiable offline with open-source code. No statute names a receipt as a safe harbor today; it makes who approved what provable, and your counsel decides what that proof is worth.

So when an agent drafts a payment release or a vendor bank-account change, the official's real question is not "is the AI accurate?" It is: *am I the named person — and what evidence do I have?* (Not legal advice; your counsel owns the state-by-state analysis.)

## 2. The two-way protection table

The usual framing is one-way: the human checks the agent. **A human-in-the-loop protects the human from the agent. The receipt protects the agent — and its maker — from the human.** One artifact, both directions:

| Who | What the receipt proves for them |
|---|---|
| **The approving clerk** | **Exact-scope ownership.** You own what you approved — the exact action, hashed and signed — and nothing more. An approval cannot be stretched afterward to cover a disbursement you never saw. |
| **The treasurer / the office** | **Provable controls — audit defense.** Every gated action either carries a named approver's receipt or visibly does not. You find the gap before the auditor does. |
| **The county** | **Evidence that survives vendor turnover.** Receipts verify offline against open-source code and the approver's public key, whether or not the issuing vendor is still in business. |
| **The AI provider / vendor** | **The action was human-owned.** A named person approved this exact action, on their own device, before it ran — the agent asked rather than acted. |

That last row matters because procurement increasingly asks "who is liable when the AI is wrong?" A shared evidence instrument gives both sides something they can accept: the county proves which human owned each action; the vendor proves its agent escalated rather than acted alone.

**Honest scope:** a receipt is evidence, not indemnity — it makes the right party provable, not what a court or auditor concludes — and it only covers harms a human was asked to own. The escalation policy decides the protection surface; the pilot maps it.

## 3. The accountability-surface map

The 60-day observe-mode pilot blocks nothing and changes no workflow. Its deliverable: **a map of every action that *would* have needed a named owner** — which disbursements, which vendor bank-account changes, which policy fired for each (pinned to an immutable version), plus sample authorization receipts your auditors verify offline, themselves. That map *is* your accountability surface. Have you seen yours?

## 4. The escalation question for CIOs

When must an agent involve a human? The recurring factors: **irreversibility** (the money leaves), **magnitude** (amount tiers), **uncertainty** (low agent confidence), **novelty** (a destination never paid before), and **authority gap** (beyond the agent's standing authority). The reference policy in this repository (`lib/guard-policies.js`) implements three of these today: vendor bank-account and routing changes always escalate to named signoff; payment releases tier at $50,000 (single approver) and $1,000,000 (dual); any AI-agent-initiated financial action requires a named human. Uncertainty and novelty checks are not yet implemented.

Two properties for the CIO meeting:

- **Prompt injection changes what an agent proposes; it cannot change what a named human approves on their own device.** The signature happens on the approver's hardware, outside the model's context: a gated action either carries a valid receipt, or its absence is itself audit evidence the control was bypassed. Caveat: the receipt proves what was approved, not that approving it was wise.
- **A draft extension (PIP-007) records the agent's own escalation reason** — "I judged this exceeds what I should do alone" — inside the signed Authorization Context, so the human's signature covers the agent's stated reason as well as the action. That attestation is a claim by an identified-but-never-trusted initiator, not a window into the model's internal state — but it makes the escalation itself part of the verifiable record.

## 5. Why now

AI — including agentic AI — is the **#1 priority of US state CIOs for 2026**: the first time in NASCIO's twenty-year survey that anything has displaced cybersecurity, which had held the top spot for twelve straight years. The priority is framed around governance — the gap between "we have a human in the loop" and "we can prove which human owned which action." An observe-mode pilot measures that gap on one real workflow.

**The pilot:** [`docs/pilots/GOVGUARD-PILOT-OFFER.md`](../pilots/GOVGUARD-PILOT-OFFER.md) — 60 days, observe mode, $25,000 fixed, nothing blocked. You get the accountability-surface map and receipts your auditors verify without trusting us.

EMILIA Protocol is the open standard for authorization receipts (Apache 2.0), with a posted IETF Internet-Draft (`draft-schrock-ep-authorization-receipts`).

**Sources:** Ohio Rev. Code § 9.39 (codes.ohio.gov/ohio-revised-code/section-9.39) · Wash. Const. art. XI, § 5 & AGO 1953 No. 94 (atg.wa.gov/ago-opinions/county-treasurer-duty-distrain-personal-property-tax-authority-charge-realty-personal) · Minn. Stat. § 385.18 (revisor.mn.gov/statutes/cite/385.18) · NASCIO State CIO Top Ten 2026 (nascio.org/press-releases/theres-a-new-day-in-state-technology).

---

## Prepared IETF note (send when timing is right)

*Timing — all four must be true before sending: (1) -01 is confirmed on datatracker (the note cites §4.1); (2) verify 1.4.0 + issue 0.2.0 are live on npm (the note says "published packages"); (3) the Songbo layering reply has been sent and has breathed for a day or two — never three EP posts on the list in one day; (4) the CHEQ author has replied to the private compare-notes email, or roughly a week has passed — posting his draft's framing on-list before he answers would read as going around him. Send as a reply inside the live survey thread, not a new thread.*

```text
Subject: Re: [Secdispatch] Re: Authorization Evidence for High-Risk Actions —
survey of independent efforts (PSEA, EP, DRP, ScopeBlind) and a narrow
dispatch question

One more composition point for this thread, bringing in a draft the survey
did not cover: CHEQ (draft-rosenberg-cheq), which is circling the same
problem from the confirmation side. The framing that has clarified the
landscape for us: the agent asks; the receipt proves.

CHEQ specifies the confirmation interaction — how a resource server
interrupts an agent's call and reaches a human. DRP
(draft-nelson-agent-delegation-receipts) covers delegation scope — what a
user authorized an operator to do on their behalf. EP
(draft-schrock-ep-authorization-receipts) specifies the portable evidence
the interaction leaves behind — a named approver's device-bound signature
over the exact action, verifiable offline, without querying any of the
operators involved.

These read less like competitors than drafts that could converge on a shared
verifier core: canonical serialization, an action hash, a signature an
outside party can check. If dispatch lands this work anywhere, converging on
that core seems like the highest-value outcome.

One concrete convergence point, now specified in -01 of the EP draft
(Section 4.1): the agent's own escalation decision, recorded as a field
inside the signed authorization context — "I judged this action exceeds what
I should do alone, because X." The ask is CHEQ's domain; recording it inside
the evidence is EP's. The human's signature then covers not just the action
but the agent's stated reason for escalating. To be precise about what that
proves: it is a claim by an identified-but-never-trusted initiator, not a
window into the model — but it makes the escalation itself part of the
verifiable record, which neither the confirmation interaction nor the
delegation alone captures today. A reference implementation ships in the
published issuer and verifier packages.

Happy to be told this composition is wrong — that is what the list is for.

Iman
```
