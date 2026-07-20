# Making Human Oversight Verifiable

**Content source for a 30-minute California Assembly policy briefing**

**Audience:** Josh Tosney, Chief Consultant, and Slater Sharp, Senior Consultant, California
Assembly Privacy and Consumer Protection Committee

**Briefing posture:** Broad policy perspective first. EMILIA is a concrete, inspectable example,
not the policy prescription and not the opening subject.

**Meeting objective:** Leave staff with a technology-neutral test for whether a claimed human
oversight control can actually be examined after a consequential automated action.

**Core thesis:** A rule that says “keep a human in the loop” is incomplete unless the system can
show which accountable person approved which material action, what that person was shown, what
authority applied, whether the approval could be reused or retargeted, and what the executor
actually did.

**Recommended pacing:** 18–20 minutes of presentation, 10–12 minutes of discussion.

---

## One-sentence policy takeaway

For consequential automated actions, California should focus less on whether a workflow is labeled
“human supervised” and more on whether the oversight is **specific, attributable, bounded,
outcome-aware, privacy-preserving, and independently verifiable**.

## Terms in plain English

- **Consequential automated action:** A machine-initiated or machine-supported action that can
  materially change money, access, benefits, care, legal status, regulated records, infrastructure,
  energy, or physical state.
- **Exact action:** The complete material action presented for approval—not a generic task,
  standing permission, ticket number, or broad session.
- **Independent verification:** A reviewer can reproduce the relevant checks from a portable
  record under disclosed rules and trusted keys, without relying only on the deployer’s mutable
  internal log. It does not require making sensitive data public.
- **Indeterminate outcome:** The executor was called, but the system cannot yet prove whether the
  external effect occurred. An indeterminate action must not be treated as either safely failed or
  safely retryable.

---

# The policy test: seven properties of verifiable oversight

These properties are intentionally vendor-neutral. A statute, regulation, procurement rule, or
agency standard could require the outcome without prescribing one company, protocol, signature
format, or implementation.

## 1. Exact-action identity

The approval record should bind to the material terms of the action that could actually execute.
Changing a payee, amount, patient, provider, service period, destination, permission, facility,
duration, or other material field should produce a different action identity and require a new
decision.

**Policy question:** Can the deployer prove that the action reviewed by the person is the action
submitted to the executor?

## 2. Named, accountable authority

The record should identify the person or role that exercised authority and the basis for that
authority at the time of the decision. Shared accounts, generic “approved” flags, and undocumented
service identities are not enough for high-consequence actions.

**Policy question:** Can a reviewer determine who approved the action, why that person was
authorized to do so, and whether required separation of duties was observed?

## 3. Understandable approval

The approval surface should present the material terms, the proposed consequence, the applicable
policy or criteria version, and any material uncertainty in a form designed for a reasonable
decision-maker—not merely ask the person to approve an opaque identifier.

The evidence can show what was presented and what ceremony occurred. It cannot, by itself, prove
that the person understood, acted wisely, was uncoerced, or reached a lawful result.

**Policy question:** Does the record preserve what the person was shown, not just that a button was
pressed?

## 4. Bounded, single-use execution

Approval should authorize only the reviewed action or a clearly bounded envelope. It should expire,
be revocable where appropriate, and be consumed at most once within the protected execution domain.
It should not become a reusable credential that can be replayed, split, expanded, or redirected.

**Policy question:** What prevents a valid approval from being reused for a second effect or a
materially different effect?

## 5. Outcome and indeterminate handling

The record should distinguish at least: refused before execution, submitted to an executor,
confirmed executed, confirmed not executed, and indeterminate. If the executor times out after
receiving the request, the system should refuse blind replay and reconcile only against
authenticated evidence tied to the same action.

**Policy question:** If the provider committed the effect but its response was lost, what prevents
the system from doing it twice?

## 6. Portable, independent verification

The evidence should be reviewable outside the operating system under a disclosed verification
method and relying-party-selected trust anchors. A regulator, auditor, court, inspector general, or
other authorized reviewer should not have to accept the deployer’s dashboard as the final word.

This does not mean that every underlying record must be public. It means the relevant claim can be
re-performed from a scoped evidence package, with assumptions and limitations that travel with the
result.

**Policy question:** Can another authorized party check the oversight claim without asking the
operator to validate its own story?

## 7. Privacy minimization

The oversight record should include only what verification requires. Sensitive source records can
remain in controlled systems while the portable record uses pseudonymous references, content
commitments, selective disclosure, access controls, and purpose-limited retention.

**Policy question:** Can the oversight claim be verified without creating a new public dossier or
copying protected data into another uncontrolled log?

---

# Eight-slide narrative

## Slide 1 — “Human oversight should be something California can verify”

### On-slide copy

**Human oversight should be something California can verify**

Not just a policy promise.<br>
Not just a checkbox.<br>
A record of the person, the exact action, and the consequence.

**Footer:** Broad policy briefing · California Assembly · July 2026

### Visual direction

Use one clean horizontal contrast:

`“Human reviewed”` → **claim**

`Who + exact action + authority + one-time execution + outcome` → **evidence**

No product screenshot and no standards logos on the opening slide.

### Speaker notes

“Thank you for making time. You asked for the broader policy perspective, so I will stay at that
level. The narrow question is: when a law or policy requires meaningful human oversight, what
should exist afterward so the state can tell whether that oversight actually occurred for the
action that mattered?

The core idea is simple. ‘A human was in the loop’ is a description of a workflow. It is not yet
evidence. For high-consequence actions, the state should be able to examine who made the decision,
what exact action they reviewed, what authority they had, whether the approval was reused or
changed, and what happened at the executor.”

**Time:** 1.5 minutes

---

## Slide 2 — “The gap is between review and consequence”

### On-slide copy

**Most controls prove access or activity—not exact authorization**

| Existing control | Useful answer | Question it may leave open |
| --- | --- | --- |
| Identity and access management | Who or what had access? | Did a person approve this exact action? |
| Policy engine | Did configured rules permit it? | What material facts did the person review? |
| Workflow approval | Was an approval status recorded? | Could it be retargeted, replayed, or backfilled? |
| Audit log | What does the operator say happened? | Can an outside reviewer reproduce the claim? |

**Bottom line:** The highest-value control point is immediately before the system that changes
money, access, records, benefits, infrastructure, or physical state.

### Visual direction

Show an automated workflow approaching a bold “system of record / executor” boundary. Put existing
identity, policy, and logs upstream. Highlight the final pre-effect boundary in a contrasting color.

### Speaker notes

“This is not an argument against identity, policy engines, fraud analytics, workflow tools, or
logs. All of them are useful. They answer different questions.

The gap appears when a machine holds valid credentials and a rule technically permits an action,
but the state later needs to know whether an accountable person approved that action in that exact
form. A generic case approval does not necessarily prove the amount, destination, beneficiary,
provider, criteria version, or physical command that reached the executor.

The policy opportunity is to define the evidence expected at the point of consequence without
dictating the upstream software stack.”

**Time:** 2.5 minutes

---

## Slide 3 — “A technology-neutral test: seven properties”

### On-slide copy

**Verifiable oversight is:**

1. **Exact** — bound to the material action
2. **Attributable** — tied to named, authorized responsibility
3. **Understandable** — preserves what the person was shown
4. **Bounded** — limited, expiring, revocable where appropriate
5. **Single-use and outcome-aware** — no blind replay after uncertainty
6. **Portable** — another authorized party can reproduce the check
7. **Privacy-minimized** — proves the claim without copying the whole case

### Visual direction

Use seven compact tiles around a central phrase: **“Evidence at the point of consequence.”**

### Speaker notes

“These are the properties I would use to evaluate any proposed human-oversight rule. They are
technology-neutral.

First, the decision is bound to the exact material action. Second, authority is attributable.
Third, the record preserves what was shown, while avoiding the false claim that technology can
prove comprehension or wisdom. Fourth, authority is bounded. Fifth, it is single-use and handles
uncertain outcomes safely. Sixth, the claim is portable enough for an authorized outside reviewer
to reproduce. Seventh, the record minimizes personal and operational data.

The point is not to require a particular cryptographic format. The point is to make ‘human
oversight’ testable.”

**Time:** 3 minutes

---

## Slide 4 — “What the control looks like in practice”

### On-slide copy

**One lifecycle, from proposed action to reviewable outcome**

1. **Construct** the complete material action
2. **Challenge** for the required authority and evidence
3. **Present** the material terms to the accountable person
4. **Verify and reserve** the bounded authority
5. **Execute once** at the protected system boundary
6. **Record outcome**: refused, executed, not executed, or indeterminate
7. **Reconcile** uncertainty from authenticated same-action evidence
8. **Export** a privacy-minimized evidence package

**Rule of thumb:** No valid evidence, no protected mutation.

### Visual direction

Use a left-to-right lifecycle with one branch after execution:

- confirmed → record result
- timeout/uncertain → indeterminate → authenticated reconciliation

Draw a clear “no blind retry” barrier on the uncertainty branch.

### Speaker notes

“The most easily missed part is after the executor is called. Imagine a payment provider commits a
release, but its response is lost. If the system treats the timeout as failure and simply retries,
the oversight control may authorize the effect twice.

A safer design records the operation as indeterminate, consumes or freezes the authority, refuses a
blind retry, and reconciles only against authenticated evidence tied to the same provider,
operation, and material action.

That is a useful policy distinction: oversight should cover not only the approval ceremony but the
full consequence lifecycle.”

**Time:** 2.5 minutes

---

## Slide 5 — “The same policy test travels across sectors”

### On-slide copy

| Example | Material action | What verifiable oversight adds |
| --- | --- | --- |
| **Payment release / Action Escrow** | Release one milestone payment to one destination | Named party approvals bind to the milestone, amount, payee, completion evidence, and one release attempt |
| **Energy / GRACE** | Curtail a facility by a defined amount and duration | Authorized order, bounded envelope, separate meter evidence, replay refusal, and reviewable settlement record |
| **Medi-Cal program integrity** | Admit a provider, accept a hospice authorization, or release a claim payment | Provider, member reference, service period, authorization evidence, amount, and destination stay joined through the protected action |

**Common policy principle:** The evidence follows the consequence—not the industry label.

### Visual direction

Three vertical scenario cards with a common evidence spine beneath them:

`exact action → accountable authority → one-time effect → outcome → portable review`

### Speaker notes

“These examples are intentionally different.

In a payment release, the concern is that a valid approval for one milestone or destination must not
become authority for another.

In an energy event, the authorization, the dispatch, the meter evidence, and the settlement claim
must refer to the same bounded curtailment.

In program integrity, analytics may flag risk and existing systems may verify an authorization, but
the final protected action should preserve the join among the provider, pseudonymous member
reference, service period, authorization evidence, amount, and payment destination.

The technology can vary. The policy properties remain stable.”

**Time:** 3 minutes

---

## Slide 6 — “California is already strengthening Medi-Cal controls”

### On-slide copy

**Build on the controls California already operates**

DHCS reports:

- fraud analytics, provider screening, audits, investigations, payment stops, and recovery
- a 2026 hospice scheme involving **14 fraudulent providers** and **more than $267 million** in
  improper billing
- system safeguards that block a hospice claim unless a valid authorization form is on file and
  verified

**The additional layer to test:** Bind the verified authorization and provider standing to the
exact claim/payment action; refuse replay; preserve indeterminate outcomes; export a scoped record
for authorized review.

**Not the claim:** This is not a replacement for fraud detection, clinical review, provider
screening, licensing, investigation, or law enforcement.

### Visual direction

Use two stacked layers:

1. **California’s existing safeguards** — analytics, screening, audit, payment stop, investigation
2. **Exact-action consequence evidence** — bind, consume once, reconcile, verify

The second layer should visibly sit on top of—not replace—the first.

### Speaker notes

“California should get full credit for the controls it already has. DHCS describes a broad program
integrity system: provider screening, licensing and site checks, predictive analytics, audits,
investigations, payment stops, recovery, and law-enforcement coordination.

In April, DHCS described a hospice identity-theft scheme involving 14 fraudulent providers and more
than $267 million in improper billing. DHCS also reported that it updated payment-system safeguards
to block hospice claims unless a valid authorization form is on file and verified.

The responsible question is not ‘Would one new technology have prevented the entire scheme?’ We
cannot claim that. The useful question is whether a future control can keep provider standing,
authorization evidence, member and service references, amount, destination, execution attempt, and
outcome bound to the same protected action—and make that join reviewable without weakening privacy.

That is a complement to California’s existing program integrity work.”

**Time:** 3 minutes

**Source note:** California Department of Health Care Services, “California Stops Major Identity
Theft and Hospice Fraud Scheme,” April 9, 2026; DHCS “Program Integrity.”

---

## Slide 7 — “Policy can specify the evidence outcome without choosing a vendor”

### On-slide copy

**Four policy levers**

1. **Definitions** — identify “material automated actions” by consequence, not model type
2. **Control duty** — require action-specific, attributable oversight before protected effects
3. **Evidence duty** — preserve a privacy-minimized, independently reviewable record
4. **Outcome duty** — prohibit blind replay after an indeterminate external effect

**Procurement can move first:** Apply the test to one high-consequence state workflow in
observe mode before considering a broader mandate.

### Visual direction

Four simple policy blocks feeding into a fifth block labeled **“Measurable compliance question.”**

### Speaker notes

“This does not require the Legislature to mandate a protocol, a vendor, or even cryptography.

The state can define the consequence classes it cares about, require that oversight bind to the
material action before the effect, require a reviewable and privacy-minimized evidence record, and
require safe handling when the executor’s outcome is uncertain.

Procurement or an agency pilot may be the cleanest first vehicle. It can test whether these
properties improve accountability in one workflow without changing eligibility rules, clinical
standards, payment policy, or the underlying system of record.”

**Time:** 2.5 minutes

---

## Slide 8 — “A practical next step: test the evidence, not the slogan”

### On-slide copy

**60-day, observe-mode policy pilot**

- Select one high-consequence, bounded workflow
- Define the material action and required authority
- Run the evidence control alongside the current process
- Exercise valid, mismatched, replayed, revoked, and indeterminate cases
- Give an authorized reviewer the portable record and verification method
- Report what the evidence proves, what it does not, privacy impact, and integration burden

**Staff deliverables available:** short technical note · model language · pilot scorecard · live
reference demonstration

**Closing line:** Human oversight becomes enforceable when it leaves evidence tied to the action
that mattered.

### Visual direction

Show a compact 60-day timeline:

- Days 1–10: scope
- Days 11–30: observe-mode integration
- Days 31–45: adversarial exercises
- Days 46–60: independent review and policy memo

### Speaker notes

“The most useful next step is not a broad claim that this solves AI accountability. It is a small,
measurable test.

Choose one bounded workflow. Run the evidence control alongside the existing process. Test the
normal path and the hard cases: mismatched action, replay, revoked authority, and provider timeout
after possible execution. Then give the record and the verification method to a reviewer who did
not operate the system.

The policy question at the end is concrete: Did this make the human-oversight claim easier to
examine without creating a new privacy or operational burden?

We can provide staff with model language, a neutral scorecard, a technical note, and a live
reference demonstration if that would be useful.”

**Time:** 2 minutes, then discussion

---

# Model policy-language options

These are working options for legislative counsel and committee discussion, not a representation
that a particular bill should use every provision.

## Option A — Outcome-based duty for material automated actions

> A deployer that uses an automated system to initiate a material action shall maintain reasonable
> technical and organizational measures sufficient to demonstrate that any required human
> oversight was completed before execution and was bound to the material terms of the action
> submitted for execution.

**Why this option is useful:** It establishes the evidence outcome without prescribing a technical
format.

## Option B — Minimum contents of an oversight record

> An oversight record for a material automated action should identify or bind, as applicable:
>
> (1) the material terms of the proposed action;
>
> (2) the person or accountable role exercising oversight and the basis of authority;
>
> (3) the information and material terms presented for decision;
>
> (4) the applicable policy, criteria, or rule version;
>
> (5) the time and validity period of the decision;
>
> (6) whether the authority was accepted, refused, expired, revoked, or consumed; and
>
> (7) the execution status, including whether the outcome is indeterminate.

**Drafting note:** “Bind” allows privacy-preserving references or commitments rather than requiring
the record to duplicate protected source data.

## Option C — Material-change rule

> A prior oversight decision shall not authorize an action whose material terms differ from those
> presented for decision. A change to a material term requires a new decision or must fall within a
> previously disclosed and expressly approved bounded range.

**Why this option is useful:** It addresses retargeting and “approval laundering” while permitting
legitimate bounded discretion.

## Option D — Replay and indeterminate-outcome rule

> A deployer shall use reasonable measures to prevent an oversight decision from being consumed
> more than once for the same protected effect. If an external executor has received the action but
> the result cannot be reliably determined, the deployer shall preserve an indeterminate status and
> shall not automatically resubmit the action unless authenticated evidence establishes that
> resubmission cannot duplicate the effect.

**Drafting note:** Technical reviewers may prefer “shall not blindly resubmit” plus a requirement
for action-bound reconciliation. Legislative counsel should assess the appropriate reasonableness
standard and sector-specific exceptions.

## Option E — Independent reviewability

> A deployer shall make the oversight record and the method necessary to evaluate it available to
> an authorized regulator, auditor, court, or other authorized reviewer in a form that permits the
> reviewer to reproduce the material verification without relying solely on the deployer’s
> representation that the control succeeded.

**Why this option is useful:** It asks for re-performance, not public disclosure or dependence on a
particular third party.

## Option F — Privacy and data minimization

> An oversight record shall be limited to information reasonably necessary to establish the
> required oversight and execution facts. The record may use pseudonymous references,
> cryptographic commitments, selective disclosure, or comparable methods when those methods permit
> authorized verification without duplicating protected source records.

**Why this option is useful:** It prevents an accountability requirement from becoming a new
centralized store of health, identity, security, or operational data.

## Option G — Emergency and continuity handling

> A covered policy may provide a documented exception where delay would create a substantial risk
> to life, safety, continuity of essential services, or other interests specified by law. The
> exception should be narrowly scoped, time-limited, attributable, and subject to prompt
> post-action review.

**Why this option is useful:** It avoids designing a control that blocks medically necessary care
or essential public operations while preserving accountability for bypass use.

## Option H — Procurement and pilot language

> In procuring an automated system that can initiate a material action, a state entity may require
> the vendor or integrator to demonstrate action-specific oversight, bounded and single-use
> execution, explicit outcome handling, privacy-minimized evidence, and reviewability under
> verification methods and trust anchors selected by the state.

**Why this option is useful:** It creates an implementation path before a generally applicable
mandate and keeps control of the verification criteria with the state.

---

# Questions staff may ask

## “Isn’t this just better logging?”

No. Logging is necessary, but an operator-controlled log generally reports what the operator says
happened after the event. The stronger control binds the decision to the material action before the
effect, enforces bounded use at the executor, records uncertain outcomes, and lets an authorized
reviewer reproduce the relevant checks.

## “Does a signature prove that the person understood or made the right decision?”

No. Evidence can establish which enrolled credential completed a defined ceremony over specified
material terms. It cannot prove comprehension, wisdom, voluntariness, legality, medical
correctness, or proportionality. Policy should separately address presentation quality,
qualifications, substantive standards, coercion, and appeal.

## “Would this have prevented the hospice scheme?”

That should not be claimed. DHCS describes a scheme involving identity theft, fraudulent provider
enrollment, nonexistent services, billing, and organized criminal conduct. Exact-action controls
could strengthen selected authorization, provider, claim, payment, and outcome boundaries, but
they do not replace identity proofing, site visits, licensing, analytics, audits, investigations,
payment suspensions, recovery, or prosecution.

## “Does this require public blockchains or public disclosure?”

No. Verification can occur within a controlled review process. Sensitive facts can remain in the
agency or covered entity’s source systems while the evidence package carries pseudonymous
references, content commitments, selective disclosures, and the minimum material facts needed for
the authorized review.

## “Does this require the state to choose EMILIA?”

No. The seven policy properties can be implemented through different architectures. A sound rule
should define the consequence, evidence, privacy, and outcome requirements and allow interoperable
implementations to compete.

## “How is this different from identity and access management?”

Identity and access management establishes who or what may access a system and within what general
scope. Exact-action oversight asks whether an accountable person approved the complete material
action that is about to execute, whether the approval can be consumed only as intended, and whether
the result can be independently reviewed.

## “Where should the control sit?”

Immediately before the system or adapter that can cause the protected effect, with complete
mediation for the action paths in scope. A dashboard upstream of an unguarded executor can document
intent but cannot prevent bypass.

## “What counts as a material action?”

Define it by effect, not by whether a model is called “AI.” Examples include release or redirection
of funds, denial or modification of a benefit or care determination, change to provider
enrollment, grant of a privileged permission, mutation of an official record, infrastructure
deployment, energy dispatch, and control of physical equipment. Sector law should determine the
threshold and exceptions.

## “What if an emergency requires immediate action?”

Design a narrow, attributable, time-limited emergency path with defined eligibility, minimal
authority, contemporaneous logging where possible, and prompt post-action review. The control
should not block medically necessary care or essential continuity. Emergency authority should not
become an undocumented permanent bypass.

## “Who performs the independent verification?”

Depending on the context: the agency, an inspector general, a regulator, an external auditor, a
court, a contracting counterparty, or another authorized reviewer. “Independent” here means the
reviewer can reproduce the material check without relying solely on the operator’s stated verdict;
it does not automatically mean an accredited certification or a separate commercial witness.

## “How do we avoid creating a costly statewide replacement project?”

Start at one executor boundary in observe mode. Keep the existing case, payment, provider,
identity, clinical, and analytics systems. Measure integration burden, false refusals, privacy
impact, and review value before any production enforcement or general mandate.

## “What would a pilot prove?”

A pilot can prove whether one protected action is consistently identified, whether required
authority and evidence remain bound to it, whether replay and mismatches are refused, whether
indeterminate outcomes are handled safely, and whether a separate reviewer can reproduce the
result. It cannot prove that every upstream fact is true or that every authorized decision is
correct.

---

# EMILIA as an inspectable example—not the policy prescription

This section is for questions after the broad policy case is understood. It should not lead the
briefing.

## Shipped and inspectable in the current repository

- **EMILIA Gate:** Deny-by-default checks at a protected executor path, exact-action evidence
  challenges, one-time consumption, execution records, bounded capability reserve/commit, explicit
  indeterminate state, replay refusal, and authenticated same-action reconciliation.
- **EMILIA Protocol verifier and evidence formats:** Open, offline verification under trust anchors
  selected by the relying party.
- **EMILIA Approver reference surfaces:** Device-bound exact-action signoff mechanisms and
  presentation binding, with explicit limits on what a signature proves.
- **Action Escrow reference experience:** A runnable contractor-milestone example that binds
  document mapping, party acceptances, completion evidence, release approval, provider attempt, and
  effect state. It is not a licensed custodian and does not itself hold or move money.
- **GRACE reference circuit:** A runnable, non-physical simulation joining bounded curtailment
  authority, distinct approvals, dispatch state, separately keyed meter evidence, replay refusal,
  and one-time settlement entitlement.
- **Government adapters:** Reference policy and precheck paths for provider enrollment,
  disbursement, payment destination, benefit routing, eligibility, and accountable overrides.

## Staged research and deliberately limited claims

- Individual Internet-Drafts and repository research explore receipt, quorum, exact-action,
  authority, evidence-chain, bounded-capability, and outcome-binding concepts. They are individual
  submissions or research artifacts—not RFCs, IETF adoption, government endorsement, or a legal
  mandate.
- JavaScript, Python, and Go verifier agreement is same-team cross-language consistency, not a
  clean-room independent implementation claim.
- Formal models and adversarial tests establish only their stated assumptions and properties. They
  do not prove host security, upstream data truth, human comprehension, medical correctness,
  lawfulness, or successful physical effect.
- The Medi-Cal example in this briefing is a policy and integration scenario, not a claim of a
  DHCS deployment or state approval.

## External dependencies before production claims

- **Payment release:** A completely mediated integration with a licensed custodian or payment
  provider, customer-selected policies and trust roots, and production reconciliation evidence.
- **Energy:** A cooperating facility or aggregator, applicable tariff or program rules, production
  control-system integration, and trusted or revenue-grade meter evidence.
- **Medi-Cal:** A state, plan, fiscal-intermediary, or provider workflow owner; lawful access to the
  source systems; agency-selected material fields, identity and provider-authority sources,
  privacy controls, and operational acceptance criteria.
- **Independent assurance:** An authorized external reviewer or clean-room implementation where a
  claim requires independence beyond same-team conformance.
- **Hardware-rooted claims:** Real supported hardware and an accepted attestation policy. A
  software stub is not hardware attestation.

---

# Suggested discussion prompts

1. Which pending California AI policy questions currently rely on the phrase “meaningful human
   oversight” without defining what evidence should exist?
2. Should the trigger be the technology used, or the consequence the automated system can cause?
3. Where would staff most value a technology-neutral evidence test: procurement, impact
   assessment, incident reporting, audit, or a sector-specific control?
4. What privacy or records-retention concerns should constrain a portable oversight record?
5. Would a short staff technical note, neutral model language, or an observe-mode demonstration be
   most useful next?

---

# Sources and factual anchors

## California

- California Department of Health Care Services, [California Stops Major Identity Theft and
  Hospice Fraud Scheme](https://www.dhcs.ca.gov/news/california-stops-major-identity-theft-and-hospice-fraud-scheme/),
  April 9, 2026. DHCS reports 14 fraudulent hospice providers, more than $267 million in improper
  billing, more than $70 million recovered at the time of publication, payment stops and
  suspensions, license revocations, and updated payment safeguards requiring a valid verified
  authorization form for hospice claims.
- California Department of Health Care Services, [Program
  Integrity](https://www.dhcs.ca.gov/program-integrity/). DHCS describes provider screening,
  licensing and ownership checks, site visits, audits, investigations, predictive analytics,
  payment stops, recovery, and coordination with plans and law enforcement.

## Federal context

- Centers for Medicare & Medicaid Services, [Center for Program Integrity: Mission and
  Priorities](https://www.cms.gov/medicare/medicaid-coordination/center-program-integrity). CMS
  describes provider enrollment, medical review and audits, predictive analytics, state
  collaboration, Medicaid managed-care oversight, and technology use to reduce fraud, waste, and
  abuse.

## Repository claim anchors

- `AI_CONTEXT.md`
- `docs/RECEIPT-CLAIMS.md`
- `docs/briefs/ACTION_ESCROW_PRODUCT_BRIEF.md`
- `docs/briefs/GRACE_PROCUREMENT_BRIEF.md`
- `docs/product/GOVERNMENT_PACK.md`
- `examples/indeterminate-effect-reconciliation/`
- `packages/gate/`

---

# Presenter guardrails

- Lead with the public-policy evidence gap, not EMILIA, CAID, standards, formal verification, or
  fundraising.
- Say “can establish” or “can make reviewable,” not “guarantees.”
- Never say a receipt proves comprehension, wisdom, voluntariness, lawfulness, medical correctness,
  or physical success.
- Never imply that California lacks fraud analytics, authorization checks, provider screening,
  audits, payment stops, or law-enforcement tools.
- Never claim the hospice scheme would have been prevented by one control.
- Never describe individual Internet-Drafts as standards, RFCs, IETF adoption, or IETF endorsement.
- Never describe same-team language ports as independent implementations.
- Describe Action Escrow as a reference experience unless and until a licensed, completely
  mediated custodian integration is live.
- Describe GRACE as a runnable reference circuit and non-physical simulation unless and until a
  real facility and trusted meter integration are demonstrated.
- Describe a Medi-Cal use case as a proposed policy/integration profile unless and until an
  authorized California deployment exists.
- Keep the ask modest: staff guidance, a technical note, model language, or a scoped observe-mode
  evaluation—not a statutory endorsement of a vendor.
