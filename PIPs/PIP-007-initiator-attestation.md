# PIP-007: Initiator Escalation Attestation

**Status:** Draft
**Type:** Extension
**Created:** 2026-06-12
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP adds an OPTIONAL `initiator_attestation` object to the
`ep.signoff.v1` Authorization Context (I-D
`standards/draft-schrock-ep-authorization-receipts-00.md`, Section 4).
The object carries the initiator's own stated reason for escalating an
action to a human: a structured `escalation_trigger`, an optional
`policy_basis` rule reference, and an optional length-capped free-text
`statement`. Because the context an approver signs is canonicalized
whole (JCS, RFC 8785; I-D Section 4), the approver's signature
automatically covers the attestation — the resulting authorization
receipt proves the stated reason was part of what the approver signed.
Whether the approver *saw* it is a client-conformance property, not a
cryptographic one (I-D Section 11.3); this PIP therefore requires
conforming signing clients to render the attestation alongside the
Action Object. The field is purely additive: existing verifiers verify
receipts carrying it without modification, and the EP Core v1.0 freeze
(PIP-001) is untouched. The attestation is a
claim by an initiator that is identified but never trusted; it does not
prove anything about the initiator's internal state.

## Motivation

Human-in-the-loop is usually framed one-way: the human checks the agent.
The missing half is the other direction. When a careless or malicious
person causes harm using an AI agent, blame tends to flow to the most
legible target — increasingly the model or its provider, not the human
who made the call. This inverts the classic "moral crumple zone" (M. C.
Elish, *Engaging Science, Technology, and Society* 5, 2019), in which
blame pools on the nearest human operator; Hohenstein & Jung
(*Computers in Human Behavior* 106, 2020) showed experimentally that an
AI can absorb blame in a human's place. With frontier agents, the model
itself becomes the crumple zone — a reputational and political pattern
today more than a settled legal one.

An authorization receipt un-inverts this: it proves a named person
approved this exact action, on their own device, before it ran (see
`docs/essays/why-authorization-is-not-proof.md`). What the receipt does
not yet record is *why the agent asked*. Adjacent work records the
human side but not the agent's judgment: delegation receipts
(`draft-nelson-agent-delegation-receipts-09`) bind a user's delegation,
and CHEQ (`draft-rosenberg-cheq-00`) standardizes server-policy-driven
confirmation — in neither does the initiator attest to its own
escalation decision. This PIP adds that field, so one artifact covers
both the agent's stated reason for escalating and the human's exact
approval.

## Specification

### 1. The `initiator_attestation` object

A producer MAY include an `initiator_attestation` member in any
`ep.signoff.v1` Authorization Context. When present it MUST be a JSON
object with the following members and no others:

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `escalation_trigger` | REQUIRED | string (enum) | Why the initiator escalated. Exactly one of: `irreversibility`, `magnitude`, `uncertainty`, `novelty`, `authority_gap`, `policy_rule`. |
| `policy_basis` | OPTIONAL (REQUIRED whenever a deterministic policy rule fired, including always when `escalation_trigger` is `policy_rule`) | string | Identifier of the policy or rule that fired, e.g. `ep:policy:wires-over-100k@v12/rule:dual-auth`. |
| `statement` | OPTIONAL | string | Short free-text reason the initiator gives the approver. MUST NOT exceed 280 characters. |

Enum semantics:

- `irreversibility` — the action cannot be undone once executed.
- `magnitude` — the amount or scope exceeds what the initiator should
  act on alone.
- `uncertainty` — the initiator's confidence in its own assessment is
  too low to proceed unaided.
- `novelty` — the action or counterparty has no precedent in the
  initiator's history.
- `authority_gap` — the action requires authority the initiator was
  never granted.
- `policy_rule` — a deterministic policy rule required signoff and
  none of the five substantive categories above captures why;
  `policy_basis` names the rule. See the precedence rule below.

Example context (fields as in I-D Section 4, with the new member):

```json
{
  "ep_version": "1.0",
  "context_type": "ep.signoff.v1",
  "action_hash": "sha256:9f2c...",
  "policy_id": "ep:policy:wires-over-100k@v12",
  "policy_hash": "sha256:77ab...",
  "initiator": "ep:entity:agent-recon-7",
  "initiator_attestation": {
    "escalation_trigger": "magnitude",
    "policy_basis": "ep:policy:wires-over-100k@v12/rule:dual-auth",
    "statement": "Wire exceeds my single-action limit and the beneficiary account first appeared 11 days ago."
  },
  "approver": "ep:approver:jchen-controller",
  "approver_index": 1,
  "required_approvals": 2,
  "nonce": "b64u:R9w1...",
  "issued_at": "2026-06-12T15:04:05Z",
  "expires_at": "2026-06-12T15:19:05Z"
}
```

Rules:

- **Trigger/basis precedence.** `escalation_trigger` always carries
  the substantive reason for escalating: when one of the first five
  enum values applies, the producer MUST use it, whether or not a
  deterministic rule also fired; `policy_rule` MUST be used only when
  no substantive category fits. Independently of which trigger is
  chosen, whenever a deterministic policy rule fired, `policy_basis`
  MUST be populated with that rule's identifier. The two fields answer
  different questions — `escalation_trigger`: *why* a human is needed;
  `policy_basis`: *which rule*, if any, made the escalation mandatory
  — so two implementers encoding the same escalation produce the same
  trigger, which is what keeps population-level trigger statistics
  comparable (Trust model, point 3).
- When a receipt contains multiple contexts (m-of-n approvals), the
  `initiator_attestation` object, if present in any context, MUST be
  present in every context of that receipt, and its canonical form —
  `canonicalize(initiator_attestation)` — MUST be identical across all
  of them. Every approver sees the same stated reason.
- Producers MUST NOT add members beyond the three defined above in v1.
- A signing client implementing this PIP MUST render the attestation
  to the approver alongside the faithful human-readable rendering of
  the Action Object that I-D Section 4 already requires, subject to
  the untrusted-content display rules in Security Considerations (a).
  Note the I-D's own rendering rule covers the Action Object only; the
  attestation display requirement is introduced by this PIP.
- A signing client presented with a context whose `statement` exceeds
  280 characters MUST refuse to render it for signing.
- Carriers MUST NOT strip or rewrite the field after context
  construction: the context is immutable once issued, because any
  mutation changes the canonical digest and invalidates the signoff.

### 2. Binding semantics

No new signature, digest, or verification step is introduced. The
binding is inherited from the existing canonicalization:

- The normative rule is the I-D's: "The context is JCS-canonicalized;
  the **context hash** is its SHA-256 digest. The approver signs the
  context hash" (I-D Section 4; JCS is RFC 8785). JCS serializes every
  member present in the object, so any member present in the context —
  including `initiator_attestation` and everything inside it — is part
  of the signed bytes. The reference implementation conforms: the
  recursive sorted-key canonicalizer (`contextDigest()` in
  `packages/issue/index.js`; `canonicalize()` in
  `packages/verify/index.js`) sorts keys at every nesting level and
  carries no field allowlist, so it includes whatever members the
  context holds.
- Therefore the approver's signature automatically covers the
  attestation: the receipt proves the stated reason was part of what
  the approver signed. What the signature alone does not prove is that
  the reason was faithfully displayed — "A signature proves user
  presence and an act of approval toward *whatever was rendered*;
  cryptography cannot prove the rendering was faithful" (I-D Section
  11.3). The I-D's Section 4 rendering rule requires a faithful
  human-readable rendering of the Action Object — "not only the hash"
  — and is silent on other context members; the requirement that
  conforming clients also render the attestation comes from this PIP
  (Specification Section 1). On a conforming client, then, the
  approver was shown why they were being asked and approved anyway —
  or did not.
- Existing verifiers verify these receipts unmodified.
  `verifyTrustReceipt()` in `packages/verify/index.js` recomputes, in
  its per-context step, `sha256(canonicalize(ctx))` for each context
  *as presented* and compares it to the signoff's context hash. A
  context carrying the new field produces a digest that includes it on
  both the issuing and the verifying side; a context without the field
  produces exactly the digest it produces today.
- Verifiers implementing this PIP MUST check the cross-context
  identity rule (Section 1) and flag violations in verification
  reports, and SHOULD likewise flag other Section 1 violations —
  members beyond the three defined, a `statement` over 280 characters,
  `escalation_trigger` of `policy_rule` with `policy_basis` missing —
  and surface the attestation in reports. None of these checks affects
  signature validity: a receipt carrying a malformed attestation still
  verifies cryptographically, by design, on verifiers that predate
  this PIP.

### 3. Issuance

`buildContexts()` in `packages/issue/index.js` constructs one context
per approver from the Action Object and policy inputs. Implementations
supporting this PIP extend the builder with an
optional `initiatorAttestation` argument, validated against Section 1
and copied verbatim into every context. No change to the Action Object,
the action hash, or any Core object is made.

## Trust model

This section is informative and blunt on purpose. Its one binding
requirement — that the attestation is never a trust input — is stated
normatively in Security Considerations (d).

The attestation is a **claim by the initiator**. The I-D's terminology
(Section 2) applies unchanged: "The initiator is identified but never
trusted with approval authority over its own actions." The same stance
extends to the attestation: it is the initiator's stated reason, not a
verified fact. **The attestation does not prove the initiator's
internal state** — not its actual reasoning, not its sincerity, not
that the stated trigger was the real trigger. Nothing in this protocol
treats it as evidence of any of those things, and an initiator must
not be able to buy leniency by declaring the right reason — hence
Security Considerations (d).

What the attestation is worth, exactly:

1. **It is bound into what the human approved.** The receipt proves the
   approver signed a context containing this stated reason. If a
   dispute later turns on "what was the approver told?", the answer is
   in the signed bytes, not in testimony.
2. **It is logged and auditable.** Receipts chain via
   `prev_receipt_hash` (I-D Section 4) into a Merkle-checkpointed log
   (I-D Section 6.2), so stated escalation reasons survive with the
   same tamper evidence as every other receipt field.
3. **Population-level patterns become measurable.** Escalation rates
   per initiator, trigger distributions per policy, and drift over time
   can be computed from receipts. An initiator whose stated triggers
   diverge from what its policy environment fires is itself a signal —
   one that only exists if the claim is recorded.

A receipt carrying an attestation remains what every receipt is:
evidence, not indemnity. It makes the relevant facts provable; it does
not decide what any court or regulator does with them, and nothing in
this PIP is legal advice.

## Rationale

- **Why inside the Authorization Context, not the Action Object.** The
  property this PIP exists to create is "the approver's signature
  covers the stated reason." The context is the document the approver
  signs; the Action Object is the operation the executor recomputes and
  performs. Placing the attestation in the action would entangle
  per-authorization-attempt metadata with operation semantics and force
  executing systems to carry it for hash recomputation. The context is
  also where the initiator's identity already lives (I-D Section 4).
- **Why three fields and nothing else.** v1 is deliberately minimal: a
  structured trigger for measurement, a rule reference for
  deterministic escalations, free text for the human. Confidence
  scores, model identifiers, and chain-of-reasoning fields were
  considered and rejected for v1 — each invites treating the claim as
  more than a claim.
- **Why no initiator signature over the attestation.** An initiator
  signature would prove the initiator's software emitted the claim, not
  that the claim is true, while adding key management for a party the
  protocol never trusts with authority anyway. The binding that matters
  is the approver's. An initiator-signed variant may be proposed as a
  future extension if a use case requires non-repudiation of the
  claim's *emission*.
- **Why OPTIONAL.** Existing issuers remain conformant; the field can
  be adopted policy-by-policy. Absence is meaningful only in the narrow
  sense given in Security Considerations (c).

## Backwards Compatibility

Purely additive; no migration required.

- **PIP-001 core freeze intact.** The frozen Core objects are the Trust
  Receipt, Trust Profile, and Trust Decision (`PIPs/PIP-001-core-freeze.md`).
  This PIP modifies none of them. One disambiguation, because two
  distinct objects share a name: the frozen "Trust Receipt" is the
  EP-RECEIPT-v1 object (`receipt_id` / `issuer` / `subject` / `claim`);
  the I-D Section 6.2 "Trust Receipt" — the artifact that carries the
  contexts this PIP extends — is a different object, not frozen by
  PIP-001. The Authorization Context itself is a signed sub-document
  defined by the I-D (Section 4) and implemented in `packages/issue`
  and `packages/verify`. It is not defined or consumed by the
  Accountable Signoff extension (PIP-003), which specifies a separate,
  handshake-bound signoff mechanism (`lib/signoff/`) and predates the
  I-D. Adding an optional member to the context removes no required
  field, changes no parsing, and alters no frozen verification
  algorithm.
- **Old verifiers, new receipts.** Verify unmodified, per Specification
  Section 2: the digest recomputation includes whatever members the
  context carries.
- **New verifiers, old receipts.** Contexts without the field produce
  byte-identical canonical material to today; digests and signatures
  are unaffected.
- **Caution for intermediaries.** Any component that re-serializes
  contexts through a schema that drops unknown members will corrupt the
  digest and cause valid receipts to fail verification. This is
  existing protocol behavior (contexts are hash-immutable), restated
  here because this PIP is the first to add a member after initial
  deployment.

## Reference Implementation

A reference implementation exists across the issuer, verifier, and the
production escalation path. The PIP remains a Draft; this section records
the implemented touchpoints and their tests. Versions:
`@emilia-protocol/issue` 0.2.0, `@emilia-protocol/verify` 1.4.0.

- **Issuance — `packages/issue/index.js`.** `buildContexts()` (and the
  `issueTrustReceipt()` / `issueFromKeyBundle()` paths that call it) accept
  an optional `initiatorAttestation`. `validateInitiatorAttestation()`
  enforces Specification Section 1: enum membership for
  `escalation_trigger`, the 280-character `statement` cap, `policy_basis`
  required when `escalation_trigger` is `policy_rule`, and rejection of any
  member beyond the three defined. The validated object is copied verbatim
  into every context, so `canonicalize(initiator_attestation)` is identical
  across all of them. The `ep-issue issue` CLI gains an optional
  `--attestation <file.json>`; the `ep-issue demo` subcommand issues a
  receipt carrying a realistic attestation. Tests: `packages/issue/test.js`
  (round-trip with attestation, dual-context canonical-identity,
  no-attestation regression, Section 1 validation, issuer fail-closed).
- **Verification — `packages/verify/index.js`.** `verifyTrustReceipt()`
  returns an ADVISORY `attestation` report — `{ present, consistent,
  issues }` — built by `buildAttestationReport()`. It MUST-flags the
  cross-context identity violation (Specification Section 1) and SHOULD-flags
  malformed attestations (unknown members, over-cap `statement`,
  `policy_rule` without `policy_basis`, bad enum). Per Specification
  Section 2 the report never affects `result.valid` or any member of the
  existing `checks` object: a malformed attestation still verifies
  cryptographically. The CLI prints the advisory for a §6.2 receipt. Tests:
  `packages/verify/trust-receipt.test.js` (advisory present/consistent,
  cross-context mismatch flagged, partial-presence flagged, over-cap and
  malformed SHOULD-flags, no-attestation regression — every existing check
  unchanged).
- **Production escalation path — `lib/guard-policies.js` /
  `lib/guard-adapter.js`.** `buildInitiatorAttestation()` maps a guard
  decision to a Section 1 attestation per the Deployment-guidance table
  below; the adapter carries it on signoff-required decisions into the
  response and audit row (preserved in observe mode), where a caller minting
  §6.2 contexts passes it to the issuer's `initiatorAttestation`. The pilot
  observe-mode report (`app/api/pilot/sandbox/report/route.js`) includes it
  in flagged sample rows. Tests: `tests/guard-policies.test.js` (the full
  trigger map) and `tests/guard-adapter-aml.test.js` (response + audit
  carriage, observe-mode preservation).

## Deployment guidance (non-normative)

**Populating the field from today's escalation path.** In the current
implementation, the escalation decision is produced by
`evaluateGuardPolicy()` and `basePolicy()` in `lib/guard-policies.js`:
hard-deny risk flags fail closed; money-destination field changes,
amount-tiered payment releases, AI-agent-initiated payment actions, and
AML structuring/velocity signals escalate to `ALLOW_WITH_SIGNOFF` with
reasons and a signoff tier. When `lib/guard-adapter.js` sets
`receipt_status = 'pending_signoff'` on a signoff-required decision,
the contexts built for that receipt are where the attestation is
attached. A natural mapping for policy-driven escalations:

| Escalation source (`lib/guard-policies.js`) | `escalation_trigger` | `policy_basis` |
|---|---|---|
| Money-destination field change | `policy_rule` | the destination-change rule id |
| `LARGE_PAYMENT_RELEASE` single/dual tier | `magnitude` | the threshold rule id |
| `AI_AGENT_PAYMENT_ACTION` gate | `authority_gap` | the agent-action rule id |
| AML structuring/velocity escalation | `uncertainty` | the AML rule id |

The table follows the trigger/basis precedence rule of Specification
Section 1: `escalation_trigger` names the substantive reason even
though a deterministic rule fired, and `policy_basis` is populated in
every row precisely because one did. `policy_rule` appears only in the
row where no substantive category fits (the destination-change rule).
When the initiator instead escalates on its own judgment — "I judged
this exceeds what I should do alone," with no deterministic rule
forcing it — the first five enum values still apply, and
`policy_basis` is omitted because there is no rule to name. That
self-escalation is the case this PIP exists for: the agent's stated
judgment becomes part of what the human signs.

**Recording non-escalation.** Decisions where the initiator judged that
no human was needed produce no context and no receipt, so they are out
of wire-format scope for this PIP; recording them is audit-layer
guidance. Deployments that want an escalation-surface map today can run
observe mode (`applyEnforcementMode()` in `lib/guard-policies.js`),
which preserves `signoffRequired` so the record shows what *would* have
required a named human without blocking the caller.

## Security Considerations

**(a) A lying initiator, and the statement as an attack surface.** A
compromised or prompt-injected initiator can state any trigger and any
reason. Injection can change what the initiator *proposes* — including
this field; it cannot change what a human *approves* on their own
hardware, because the device-bound signature (I-D Section 5) is outside
the model context. The residual risk is sharper than lying:
`statement` is attacker-influenceable free text rendered to a human at
the moment of decision — a social-engineering surface aimed at the
approver, adjacent to the presentation attacks of I-D Section 11.3.
Signoff UIs MUST therefore render the statement as untrusted content:
plain text only, with no markup, links, or control characters rendered;
the 280-character cap enforced; and visually distinct styling that
labels it as the initiator's unverified claim, clearly separated from
the operator-rendered Action Object. This is the same discipline
phishing-resistant authentication applies to relying-party-supplied
display strings. A persuasive statement attached to a hostile action is
precisely the scenario the faithful-rendering rules exist for: the
approver's decision input is the rendered Action Object; the statement
is commentary from a party the protocol never trusts. A related
residual vector is divide-and-misinform: because each approver signs
their own context, a malicious orchestrator can show different
approvers of an m-of-n receipt different attestations, and every
individual signature remains valid. The cross-context identity rule
(Specification Section 1) exists for this; verifiers implementing this
PIP MUST flag violations (Specification Section 2), but on verifiers
that predate this PIP such a receipt still verifies — the rule is a
conformance check, not a signature property.

**(b) Privacy.** Statements written by an agent mid-task can leak
sensitive operational context — counterparty details, internal
findings, fragments of prompts — into receipts that are long-lived and
portable by design. Deployments SHOULD prefer `escalation_trigger` plus
`policy_basis` identifiers over free text wherever a rule id captures
the reason, SHOULD constrain or template `statement` generation for
regulated data, and MUST apply the same retention and disclosure
controls to attestation content as to the rest of the receipt.

**(c) Absence is not evidence of non-escalation.** The field is
OPTIONAL. A receipt without an attestation means only that the issuer
did not populate it — not that the initiator judged the action routine,
and not that no escalation reasoning occurred. Verifiers and auditors
MUST NOT infer anything from absence alone. (Separately, and unchanged
by this PIP: for an action a policy gates on signoff, the absence of
any valid receipt at all remains evidence that the control was bypassed
— that property comes from the gate, not from this field.)

**(d) No trust feedback.** Restating the trust-model rule as a security
requirement: policy engines MUST NOT use `initiator_attestation`
content to relax thresholds, skip approvers, or raise any trust score.
The initiator must gain nothing by saying the right words.

## References

- `standards/draft-schrock-ep-authorization-receipts-00.md` — Sections
  2 (Terminology), 4 (Authorization Context), 5 (approver keys),
  6.2 (Trust Receipt and log checkpoint), 11.3 (presentation attacks)
- RFC 8785 — JSON Canonicalization Scheme (JCS); the I-D's normative
  context canonicalization
- `PIPs/PIP-001-core-freeze.md` — frozen Core objects and extension
  mechanism
- `PIPs/PIP-003-signoff.md` — Accountable Signoff extension; a
  separate, handshake-bound signoff mechanism (`lib/signoff/`), cited
  for disambiguation only — it does not define or consume the
  `ep.signoff.v1` Authorization Context
- `packages/issue/index.js` — `buildContexts()`, `contextDigest()`
- `packages/verify/index.js` — `canonicalize()`, `verifyTrustReceipt()`
- `lib/guard-policies.js`, `lib/guard-adapter.js` — current escalation
  path
- `docs/essays/why-authorization-is-not-proof.md` — receipts as
  evidence; the log/receipt distinction
- M. C. Elish, "Moral Crumple Zones: Cautionary Tales in Human-Robot
  Interaction," *Engaging Science, Technology, and Society* 5 (2019),
  doi:10.17351/ests2019.260
- Hohenstein & Jung, "AI as a moral crumple zone," *Computers in Human
  Behavior* 106 (2020)
- `draft-nelson-agent-delegation-receipts-09` (IETF I-D) — user-signed
  delegation receipts; records no initiator escalation judgment
- `draft-rosenberg-cheq-00` (IETF I-D) — server-policy-driven human
  confirmation; escalation lives in server policy, not initiator
  judgment
