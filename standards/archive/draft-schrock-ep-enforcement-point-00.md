# An Enforcement-Point Profile for Authorization Receipts (EP)
## draft-schrock-ep-enforcement-point-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                              28 June 2026
Expires: 30 December 2026
```

### Abstract

This document defines an Enforcement-Point (PEP) profile that composes
on the shared verifier core specified in the referenced
authorization-receipt Internet-Draft
[draft-schrock-ep-authorization-receipts]. The profile gives a Policy Enforcement
Point a small, stable contract for high-risk agent actions: a
registered decision vocabulary (`allow` / `allow_with_signoff` /
`deny`, with an out-of-band `observe` mode), a decision-request and
decision-response schema bound to the exact action under evaluation,
and a requirement that every decision be bound to an offline-verifiable
authorization receipt (the EP-RECEIPT-v1 wire format). It states the
conformance requirements an enforcement point must meet — fail-closed
on uncertainty, honoring of one-time consumption, and receipt emission
— and the central invariant that a rejecting decision must take effect
before any approval-bearing state mutation.

This profile *consumes* a policy decision; it does not define a policy
language. It is complementary to, not a replacement for, the
decision-interface and policy-engine work it sits behind (AuthZEN, OPA,
Cedar), and it does not redefine the verifier core, which is specified
in [draft-schrock-ep-authorization-receipts].

### Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79. Internet-Drafts are working documents
of the IETF. This document is an individual submission and has no
formal standing in the IETF standards process.

---

## 1. Introduction

An AI agent or automated process about to perform an irreversible
operation — releasing a payment, changing a beneficiary, dropping a
table, force-pushing over history — sits in front of a system of record
that will, or will not, let the operation through. The component that
makes that go/no-go call at the moment of execution is a Policy
Enforcement Point (PEP). This document profiles how an EP enforcement
point behaves so that its decisions are interoperable, fail-closed, and
backed by evidence a third party can verify without trusting the
enforcement point itself.

The authorization-receipt work
[draft-schrock-ep-authorization-receipts] defines the shared verifier
core: the canonical Action Object and action hash, the human-signed
Authorization Context, one-time consumption, separation of duties, and
the offline verification algorithm over a signed receipt. This document
does not restate or redefine any of that. It defines the much narrower
thing that sits at the enforcement boundary: the vocabulary an
enforcement point speaks, the request it answers, the response it
returns, and the binding of that response to a receipt the core can
verify.

Two boundaries are deliberate and load-bearing:

1. **The policy boundary.** An enforcement point does not decide policy
   *semantics*. It poses an action in context to a Policy Decision
   Point (PDP) and consumes the decision. Whether the PDP is backed by
   Cedar, OPA/Rego, an AuthZEN exchange, or an in-process rule engine
   is out of scope; this profile defines only the shape and meaning of
   the decision once it crosses back to the enforcement point.

2. **The verifier boundary.** An enforcement point does not invent a
   receipt format or a verification algorithm. It emits receipts in the
   format the shared core verifies, and a relying party verifies them
   with the core's offline algorithm. This profile defines only the
   binding between a decision and the receipt that records it.

The result is a thin, honest contract: an enforcement point is
conformant when it speaks the registered vocabulary, fails closed,
honors one-time consumption, and emits a verifiable receipt for every
decision that reaches an approval-bearing state — and it makes no claim
about deciding policy or about owning the trust core.

### 1.1. Design Goals

- **G1 — Stable vocabulary.** The decision terms are a small,
  registered, stable enum. An enforcement point and a relying party
  MUST agree on their meaning across versions and operators.
- **G2 — Action-bound decisions.** Every decision is bound to one exact
  action via the action hash of the shared core. A decision for action
  A MUST NOT authorize action B.
- **G3 — Fail-closed.** Uncertainty, transport failure to a PDP, an
  unverifiable receipt, or any unrecognized state MUST resolve to a
  non-permissive outcome. The safe default is to withhold, not to
  allow.
- **G4 — Reject-before-mutation.** A rejecting decision MUST take
  effect before any approval-bearing state mutation occurs (Section 7).
  The enforcement point sits in front of the write, never beside it.
- **G5 — Receipt-bound.** Every decision that reaches an
  approval-bearing state (Section 6.2) MUST be bound to an
  offline-verifiable authorization receipt produced in the shared
  core's format.
- **G6 — Consume policy, not author it.** The enforcement point MUST
  NOT embed an authorization-policy language; it consumes a PDP
  decision (Section 9).
- **G7 — Honest enforcement class.** The deployment topology that
  determines whether the gate is bypassable is declared, not implied
  (Section 10); claims MUST NOT overstate it.

### 1.2. Scope

In scope: the decision vocabulary; the decision request (action context
plus presented evidence) and decision response schemas; the binding of
a decision to an EP-RECEIPT-v1 receipt; the reject-before-mutation
invariant at the enforcement point; and conformance requirements for an
enforcement point.

Out of scope, by reference to other work and not restated here:

- The receipt format internals, the canonical Action Object, the
  Authorization Context, the human signoff signature, the Approver
  Directory, and the offline verification algorithm — all defined by
  the shared verifier core [draft-schrock-ep-authorization-receipts].
  This profile references them; it does not redefine them.
- The authorization-policy *language* and decision *semantics* —
  defined by policy engines and decision interfaces (Cedar, OPA/Rego,
  AuthZEN), which this profile consumes (Section 9).
- The human-approval ceremony itself (how a named human is reached and
  how they sign) — defined by the core; the enforcement point only
  observes its result through receipt state.
- Risk signaling and advisory inputs, which may inform a PDP but are
  never the sole gate; an enforcement point MUST NOT treat an advisory
  as a decision.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"MAY" are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals, as shown here.

**Enforcement Point (PEP).** The component that, at the moment of
execution, permits or withholds a high-risk action. It poses the action
to a PDP, consumes the decision, binds the decision to a receipt, and
gates the action accordingly. It is the subject of this profile.

**Policy Decision Point (PDP).** The component that evaluates
authorization policy and returns a decision. Its policy language and
evaluation are out of scope; this profile consumes its output. See
Section 9.

**Action.** A single proposed operation with concrete parameters,
represented by the shared core's canonical Action Object and identified
by its action hash. This profile uses the action hash as the binding
key for a decision; it does not redefine the Action Object.

**Decision.** A member of the registered decision vocabulary (Section
3) returned for one action in one context.

**Decision Request.** The action context and presented evidence an
enforcement point evaluates (Section 4).

**Decision Response.** The decision and its supporting fields the
enforcement point returns (Section 5).

**Authorization Receipt.** The offline-verifiable evidence artifact, in
the EP-RECEIPT-v1 wire format, that records a decision and (where
applicable) its signed human approval. Its structure and verification
are defined by the shared core; this profile defines its binding to a
decision (Section 6).

**EP-RECEIPT-v1.** The wire-format tag of the receipt the shared core
verifies. Used in this document to name the on-the-wire artifact; the
buyer-facing term for the same thing is "authorization receipt."

**Approval-bearing state mutation.** Any write that records, or relies
upon, an authorization having been granted — the state change the
action exists to make. The reject-before-mutation invariant (Section 7)
governs its ordering relative to the decision.

**Enforcement mode.** The operational posture of the enforcement point
for a given decision — `enforce`, `warn`, or `observe` (Section 8) —
distinct from the decision vocabulary itself.

## 3. The Decision Vocabulary

An enforcement point speaks a small, registered, stable vocabulary. The
`decision` value of a Decision Response (Section 5) MUST be exactly one
of the following enum values. Producers MUST NOT emit, and consumers
MUST reject as malformed, any `decision` value outside this set.

| Value | Enforcement outcome | Meaning |
|-------|---------------------|---------|
| `allow` | Proceed | Execute without further gating. No human approval is required by policy for this action in this context. |
| `allow_with_signoff` | Withhold pending approval | The action is permitted by policy but MUST NOT execute until a named, accountable human approves it through the shared core's signoff. The enforcement point withholds execution until a verifiable positive-state receipt (Section 6.2) exists, then proceeds. |
| `deny` | Refuse | The action is blocked and MUST NOT execute. `deny` is terminal for the attempt and has no signoff path: a denied action cannot be rescued by human approval. It is reserved for hard failures (for example sanctions or embargo hits, or device/posture signals an operator designates non-overridable). |

The three values above are the decision vocabulary proper: every
decision an enforcement point makes is one of `allow`,
`allow_with_signoff`, or `deny`. They map to exactly three enforcement
outcomes — proceed, withhold pending approval, and refuse — and that
mapping is stable.

`observe` is not a fourth decision but an enforcement *mode* (Section
8). In `observe` mode a decision that would otherwise withhold or
refuse is recorded but not enforced. To keep the recorded decision
faithful, an enforcement point in `observe` mode MUST report the
decision it would have enforced in a separate field
(`observed_decision`, Section 5) rather than overwriting `decision`
with a permissive value; the `observe` token MAY appear as the
effective `decision` only to signal that no enforcement occurred. This
preserves the invariant that the substantive decision is always one of
the three vocabulary values.

The vocabulary is closed for v1. Future versions MAY register
additional values only through the registry contemplated in Section 12;
an enforcement point that receives an unrecognized value MUST fail
closed (Section 10.1) and MUST NOT treat it as `allow`.

## 4. The Decision Request

A Decision Request poses one action, in its context, with the evidence
the enforcement point presents for evaluation. It is the input to the
enforcement point; the enforcement point in turn poses the
policy-relevant subset to a PDP (Section 9). The request carries two
parts: the **action context** (who is doing what, to what, under which
policy) and the **presented evidence** (the risk and posture signals
offered for the decision).

```json
{
  "ep_version": "1.0",
  "request_type": "ep.decision.request.v1",
  "organization_id": "ep:org:acme",
  "action": {
    "action_type": "wire.release",
    "action_hash": "sha256:9f2c...",
    "target": { "system": "treasury.example", "resource": "wire/8841" },
    "amount": "2400000.00",
    "currency": "USD",
    "target_changed_fields": ["beneficiary_account"]
  },
  "actor": {
    "initiator": "ep:entity:agent-recon-7",
    "actor_role": "treasury-agent",
    "auth_strength": "phishing_resistant_mfa"
  },
  "evidence": {
    "risk_flags": ["new_beneficiary"],
    "advisory_refs": ["ep:advisory:..."]
  },
  "policy_id": "ep:policy:wires-over-100k@v12",
  "enforcement_mode": "enforce",
  "before_state_hash": "sha256:aa01...",
  "after_state_hash": "sha256:bb02..."
}
```

Rules:

- `action.action_hash` REQUIRED. It is the SHA-256 digest of the shared
  core's canonical Action Object and is the sole binding key for the
  decision. The enforcement point MUST recompute the action hash from
  the canonical action it actually presents and MUST reject a request
  whose recomputed hash does not match `action.action_hash`. The fields
  under `action` other than the hash are conveniences for the PDP and
  for rendering; they are not the binding and MUST NOT substitute for
  it.
- `policy_id` REQUIRED. Names the policy whose decision the enforcement
  point will consume. The enforcement point does not interpret the
  policy's rules; it identifies the policy so the PDP and the receipt
  can pin the exact version evaluated.
- `actor.initiator` REQUIRED. Identifies the proposing entity. It is
  carried so the core can enforce separation of duties (an initiator
  must not approve its own action); the enforcement point identifies
  the initiator but grants it no approval authority.
- `evidence` OPTIONAL. Risk flags, advisory references, and posture
  signals offered to the decision. Presented evidence is an *input* to
  a decision and MUST NOT be treated as a decision: an advisory or risk
  signal is never the sole gate (Section 11.1).
- `enforcement_mode` OPTIONAL, default `enforce`. See Section 8.
- `before_state_hash` / `after_state_hash` OPTIONAL. Digests of the
  pre- and post-action state that the receipt records so a relying
  party can later confirm which mutation the decision governed. They
  commit the decision to a specific state transition; they are
  evidence, not policy.
- Producers MUST NOT place an authorization-policy expression (rules,
  conditions, a policy language fragment) anywhere in the request. The
  request poses an action; it does not carry a policy to be evaluated
  inline.

## 5. The Decision Response

A Decision Response returns the decision for one action and the fields
a caller needs to act on it and to locate the bound receipt.

```json
{
  "ep_version": "1.0",
  "response_type": "ep.decision.response.v1",
  "decision": "allow_with_signoff",
  "observed_decision": null,
  "action_hash": "sha256:9f2c...",
  "policy_id": "ep:policy:wires-over-100k@v12",
  "policy_hash": "sha256:77ab...",
  "signoff_required": true,
  "signoff_tier": "single",
  "reasons": ["money_destination_change", "amount_over_threshold"],
  "receipt_id": "ep:receipt:01J...",
  "receipt_status": "pending_signoff",
  "expires_at": "2026-06-09T17:36:05Z",
  "enforcement_class": "EP-Verified-Execution"
}
```

Rules:

- `decision` REQUIRED. Exactly one vocabulary value (Section 3), or the
  `observe` token when, and only when, the request's
  `enforcement_mode` was `observe` and no enforcement occurred.
- `observed_decision` REQUIRED when `decision` is `observe`; otherwise
  OPTIONAL and `null`. When present it MUST be the vocabulary value that
  would have been enforced. In `observe` mode the enforcement point
  MUST still set `signoff_required` to the value the enforced decision
  would have carried, so the record is faithful to what would have been
  required.
- `action_hash` REQUIRED and MUST equal the request's
  `action.action_hash`. This is the response's binding to the exact
  action; a response whose `action_hash` differs from the request MUST
  be rejected.
- `policy_hash` REQUIRED for any non-`deny` decision. It pins the exact
  policy version the PDP evaluated, mirroring the core's requirement
  that an approval bound to one policy version not satisfy another.
- `signoff_required` REQUIRED, boolean. MUST be `true` when `decision`
  (or `observed_decision`) is `allow_with_signoff` and `false` when it
  is `allow` or `deny`.
- `signoff_tier` OPTIONAL. When signoff is required, names the
  accountability tier the approval flow must satisfy (for example a
  single accountable approver, or two independent approvers). The
  enforcement point reports the tier; the shared core enforces
  distinctness of approvers. The tier is a policy output the
  enforcement point relays, not a rule it authored.
- `reasons` REQUIRED, an array of machine-stable reason codes. It MUST
  NOT be empty for any non-`allow` decision. Reasons are explanatory;
  they are not a policy language and carry no executable semantics.
- `receipt_id` REQUIRED for any decision that reaches an
  approval-bearing state (Section 6.2); it identifies the bound
  authorization receipt (Section 6).
- `receipt_status` REQUIRED when `receipt_id` is present. It reflects
  the receipt's lifecycle state as defined by the core (for example
  `issued`, `pending_signoff`, or `denied`).
- `enforcement_class` REQUIRED. The declared conformance class (Section
  10); it MUST NOT state a stronger class than deployed.

## 6. Binding a Decision to an Authorization Receipt

Every decision that reaches an approval-bearing state (Section 6.2)
MUST be bound to an authorization receipt that the shared verifier core
can verify offline. This profile defines the binding; it does not
redefine the receipt, the signature, or the verification algorithm, all
of which are specified by [draft-schrock-ep-authorization-receipts].

### 6.1. The Binding Key

The binding is the canonical action. The enforcement point MUST
preserve, at decision time, the exact canonical Action Object it
evaluated, and the bound receipt MUST carry that same canonical action
and its action hash. The receipt's claim therefore commits to: the
action type, the decision (carried as the receipt's outcome), the
enforcement mode, the canonical action, the action hash, the pre- and
post-state hashes where supplied, and the pinned policy identifier and
policy hash. Because the canonical action signed in the receipt is
byte-for-byte the action the enforcement point decided on, a receipt
for one action cannot be presented to authorize another — this is the
"what was decided is what was signed" property, inherited from the
core, not reinvented here.

A schematic of the bound receipt, whose internals are owned by the
core, is shown for orientation only:

```json
{
  "@version": "EP-RECEIPT-v1",
  "payload": {
    "receipt_id": "ep:receipt:01J...",
    "claim": {
      "action_type": "wire.release",
      "outcome": "allow_with_signoff",
      "enforcement_mode": "enforce",
      "canonical_action": { "...": "exact action decided on" },
      "action_hash": "sha256:9f2c...",
      "before_state_hash": "sha256:aa01...",
      "after_state_hash": "sha256:bb02...",
      "policy_id": "ep:policy:wires-over-100k@v12",
      "policy_hash": "sha256:77ab..."
    },
    "authorization": {
      "status": "approved_pending_consume",
      "signoff_required": true,
      "approver_id": "ep:approver:jchen-controller",
      "approved_at": "2026-06-09T17:24:40Z"
    }
  },
  "signature": { "algorithm": "Ed25519", "...": "owned by the core" }
}
```

The enforcement point populates the claim from the decision it made;
the signature, its algorithm, the signer key material, and the
verification procedure are defined and performed by the core. An
enforcement point MUST NOT define its own signature scheme or its own
canonicalization for the bound receipt.

### 6.2. Positive States and the Honesty Gate

A receipt is bound to a signed, offline-verifiable evidence artifact
only when the decision has reached an approval-bearing positive state —
that is, when an approval has genuinely been granted and is awaiting
consume, or has been consumed. An enforcement point MUST NOT cause a
signed receipt to be emitted for a decision in any non-positive state
(pending, denied, rejected, or expired) or for a decision whose
canonical action was not preserved. Where the shared core would return
no signature for such a state, the enforcement point MUST surface the
unsigned evidence packet rather than synthesize a signature: it MUST
NOT assert, through a signed artifact, an authorization that was never
granted.

Concretely: a `deny` decision is bound to a receipt that records the
refusal but carries no positive-state signature; an
`allow_with_signoff` decision is bound to a pending receipt that
becomes a signed, offline-verifiable artifact only once the named
human's approval reaches a positive state; an `allow` decision is bound
to a receipt recording that no human approval was required. The honesty
gate is a property of the core that the enforcement point MUST respect,
not subvert.

### 6.3. Offline Verifiability of the Bound Receipt

A relying party holding a bound receipt and the signer's pinned public
key material MUST be able to verify it with no network access to the
enforcement point, using the shared core's offline verification
algorithm [draft-schrock-ep-authorization-receipts]. The enforcement
point's role is to produce receipts that pass that algorithm; it adds
no verification step of its own. The signer key MUST be pinned to a
trust root that does not depend on the enforcement point being online
or honest at verification time. As with the core, offline verification
establishes authenticity at decision time, not current revocation
status; a relying party with freshness requirements consults current
key and log state online.

### 6.4. The Post-Execution Receipt
The bound receipt above proves a decision was authorized *before* the action.
To close the loop, once a permitted action actually executes, the enforcement
point SHOULD emit a *post-execution receipt* (an execution attestation):
offline-verifiable proof that the authorized action was carried out, and with
what outcome.

A post-execution receipt MUST commit to the authorization it discharges — it
carries the binding key (Section 6.1) of the decision whose action it executed,
so the authorization and its execution form a single verifiable chain. It
records an outcome (for example `executed` or `failed`). It conveys no new
authority: it attests that an authorized action ran, never that an action was
approved. An enforcement point MUST NOT emit a post-execution receipt for a
decision that never reached a positive, consumed state (Section 6.2).

The post-execution receipt is verifiable offline on the same terms as the bound
receipt (Section 6.3), and MAY be anchored for long-term, tamper-evident
retention (an EP Commit seal; draft-schrock-ep-evidence-record). Together the
bound receipt and the post-execution receipt give a relying party the whole
account: a named human authorized this exact action, and it was carried out —
both checkable without trusting the enforcement point.

## 7. The Reject-Before-Mutation Invariant

This is the central enforcement-point invariant. A rejecting decision —
`deny`, or `allow_with_signoff` for which a positive-state approval
does not yet exist — MUST take effect *before* any approval-bearing
state mutation occurs. Equivalently: the enforcement point sits in
front of the write, and no approval-bearing mutation is reachable
except through a permitting decision.

Requirements:

- An enforcement point MUST evaluate the decision and, for any
  non-permitting outcome, withhold or refuse the action *before* the
  approval-bearing mutation is applied. A design that mutates state and
  then evaluates — or that evaluates beside the write rather than ahead
  of it — does not conform.
- For `allow_with_signoff`, the approval-bearing mutation MUST NOT be
  applied until a verifiable positive-state receipt (Section 6.2)
  exists for the exact action. The enforcement point withholds; it does
  not optimistically apply and later reconcile.
- For `deny`, no approval-bearing mutation is permitted for the attempt
  under any subsequent approval; `deny` is terminal (Section 3).
- If the enforcement point cannot determine, at the moment of the
  write, that a permitting decision is in force for the exact action,
  it MUST fail closed (Section 10.1) and withhold the mutation.

The invariant is what makes an enforcement point an enforcement point
rather than an after-the-fact recorder: the safe state is reached by
refusing, and the refusal precedes the irreversible step. The strength
with which the invariant holds against a party that controls the system
of record is a function of deployment topology, stated honestly in
Section 10.

## 8. Enforcement Modes

Enforcement mode is the enforcement point's posture for a decision and
is orthogonal to the decision vocabulary. Three modes are defined.

**`enforce` (default).** The decision is returned and the enforcement
point MUST honor it: `allow` proceeds, `allow_with_signoff` withholds
until a positive-state receipt exists, `deny` refuses. This is the only
mode in which the reject-before-mutation invariant (Section 7) provides
enforcement.

**`warn`.** The decision is returned verbatim and is advisory: the
caller MAY proceed against a non-permitting decision. An enforcement
point in `warn` mode MUST report the true decision and MUST NOT
represent the action as having been enforced.

**`observe`.** For staged rollout and audit. A decision that would
withhold or refuse is recorded but not enforced. The enforcement point
MUST set the effective `decision` to the `observe` token, carry the
decision that would have been enforced in `observed_decision`, and keep
`signoff_required` at the value the enforced decision would have had
(Section 5). An enforcement point in `observe` mode MUST NOT claim any
enforcement and MUST NOT downgrade a recorded `deny` to `allow`; it
downgrades only the *effect*, never the recorded decision.

Modes change whether a decision is acted upon. They never change what
the decision is: the substantive decision recorded for an action is
always one of `allow`, `allow_with_signoff`, or `deny`.

## 9. Policy Semantics Are Deferred, Not Defined

This profile defines the enforcement point's contract. It does not
define how authorization policy is written, stored, or evaluated. The
enforcement point poses an action in context to a Policy Decision Point
and consumes the decision; the policy language and decision semantics
live entirely in the PDP and the decision interface it speaks.

- An enforcement point MUST NOT embed an authorization-policy language,
  and Decision Requests MUST NOT carry inline policy expressions
  (Section 4). The enforcement point identifies a policy by `policy_id`
  and consumes the PDP's decision and pinned `policy_hash`; it does not
  interpret the policy's rules.
- The decision interface between the enforcement point and the PDP MAY
  be an AuthZEN-style access-evaluation exchange (a
  subject/action/resource/context request to a PDP returning a
  decision) or any equivalent. This profile composes with such an
  interface and does not replace it.
- The PDP MAY be backed by any policy engine — for example Cedar or
  OPA/Rego. The choice of engine and the authoring of policy are
  explicitly out of scope.
- The mapping from a PDP decision to this profile's vocabulary is a
  deployment concern, but it MUST be total and fail-closed: any PDP
  outcome that is not an unambiguous permit MUST map to a
  non-permissive vocabulary value, and a PDP that is unreachable or
  returns an unrecognized result MUST resolve to fail-closed (Section
  10.1), never to `allow`.

The division of labor is deliberate: the PDP decides *whether* policy
permits the action; the enforcement point decides *that the action does
not proceed unless* the decision permits it, binds the decision to
verifiable evidence, and orders the refusal ahead of the write. Only
the latter is profiled here.

## 10. Conformance Requirements and Classes

An enforcement point is conformant with this profile when it meets all
of the following requirements.

### 10.1. Fail-Closed

An enforcement point MUST fail closed. Any of the following MUST
resolve to a non-permissive outcome — withholding the action — and MUST
NOT resolve to `allow`:

- a PDP that is unreachable, errors, or times out (transport failure to
  a decision source is not a policy decision and MUST NOT be
  interpreted as permission);
- a decision value the enforcement point does not recognize (Section
  3);
- an action-hash mismatch between request and response, or between
  either and the recomputed canonical action;
- a required field absent or malformed in a Decision Request or
  Decision Response;
- a bound receipt that fails offline verification, or whose state is
  not a positive state where a positive state is required to proceed;
- any state the enforcement point cannot map to a defined outcome.

Fail-closed is the default for uncertainty of every kind. An
enforcement point SHOULD distinguish, in its `reasons`, a fail-closed
withholding from a policy `deny`, but both withhold the action.

### 10.2. Honoring One-Time Consumption

The shared core makes an authorization consumable at most once,
globally. An enforcement point MUST honor this: it MUST NOT permit an
approval-bearing mutation against a receipt whose authorization has
already been consumed, and it MUST reject a second presentation of a
once-consumed authorization as a replay. An enforcement point MUST NOT
re-use a single positive-state receipt to authorize more than one
execution of the action, and MUST NOT treat a receipt in a consumed
state as re-authorizing. Consume-once enforcement SHOULD be backed by a
durable, atomic record so that concurrent presentations cannot both
succeed; an in-memory replay guard is insufficient for a production
enforcement point.

### 10.3. Receipt Emission

An enforcement point MUST emit a bound authorization receipt (Section
6) for every decision that reaches an approval-bearing state, and
SHOULD record evidence for `deny` and fail-closed outcomes as well, so
that the absence of an expected execution is itself attributable.
Emission MUST respect the honesty gate (Section 6.2): a signed,
offline-verifiable artifact is emitted only for a decision that
genuinely reached a positive state; otherwise the enforcement point
emits the unsigned evidence packet. An enforcement point MUST NOT
suppress receipt emission for a permitted high-risk action: the receipt
is the evidence the profile exists to produce.

### 10.4. Vocabulary and Schema Conformance

An enforcement point MUST emit only the registered decision values
(Section 3), MUST populate the required fields of the Decision Request
and Decision Response (Sections 4, 5), and MUST bind every decision to
the exact action by action hash. A consumer MUST reject a response
whose `action_hash` does not match the request it answers.

### 10.5. Enforcement Classes (declared, not implied)

Whether the gate can be bypassed depends on where it sits. Honesty
about deployment topology is a conformance requirement, mirroring the
shared core. An enforcement point MUST declare its class in the
Decision Response (`enforcement_class`) and in the bound receipt, and
claims MUST NOT state a stronger class than deployed.

**EP-Verified Execution (STRONG).** The system of record itself
evaluates the decision and refuses to perform the approval-bearing
mutation without a permitting, verifiably-bound decision. The gate
cannot be bypassed by a party that does not control the system of
record.

**EP-Gated Middleware (STANDARD).** An interception layer between the
agent and the executing credential enforces the gate. It protects
strongly against agent error and prompt injection; an operator with
code control over the middleware can bypass it. Receipts remain valid
evidence of what was decided.

**EP-Evidence Only (BASIC).** Actions execute independently; the
enforcement point produces decisions and receipts for audit. No
enforcement claim is made; the reject-before-mutation invariant is not
provided.

## 11. Relationship to Other Work

**The shared verifier core
[draft-schrock-ep-authorization-receipts]** defines the receipt, the
canonical action and action hash, the human signoff, separation of
duties, one-time consumption, and the offline verification algorithm.
This profile composes *on* that core by reference: it speaks a
vocabulary, defines a request/response, and binds decisions to receipts
the core verifies. It does not redefine the core, and it does not claim
to own or to be the trust core; the core is the set of shared
properties this and other profiles verify against, not an artifact this
profile owns.

**AuthZEN [AUTHZEN]** standardizes the access-evaluation interface
between a PEP and a PDP — the request/response by which an enforcement
point asks "is this permitted?" This profile is a PEP-side profile: it
MAY use an AuthZEN exchange to obtain the policy decision it consumes,
and it adds the evidence-binding, reject-before-mutation, and
fail-closed requirements that a bare decision interface does not
specify. It does not replace AuthZEN.

**OPA/Rego [OPA]** and **Cedar [CEDAR]** are policy-language engines
that can back the PDP. This profile consumes a decision from such an
engine; it defines no policy language of its own (Section 9).

**Security Event Token (SET) [RFC8417]** and the Shared Signals
Framework with CAEP define an envelope and transport for security
events and session/posture signals. An enforcement point MAY consume
such signals as presented evidence (Section 4); they are inputs to a
decision and never the decision itself (Section 11.1).

**RATS [RFC9334] / EAT [RFC9711]** produce attestation results about an
entity or device's state. An enforcement point MAY consume such results as
posture evidence; this profile does not define attestation.

## 12. Security Considerations

**12.1. An advisory is never the sole gate.** Presented evidence — risk
flags, advisories, posture signals — informs a decision; it is not a
decision. An enforcement point MUST NOT permit or refuse an action
solely because an advisory said so, and MUST NOT let an advisory
substitute for the PDP decision or for a required signoff. The residual
risk if this is violated is twofold: a permissive advisory could wave
through an action policy would gate, and a spoofed or stale advisory
could become an unaccountable gate. Evidence enters only through the
`evidence` block of a Decision Request and is weighed by policy; the
gate remains the decision plus, where required, the human signoff.

**12.2. Fail-open is the failure mode that matters.** The most
dangerous defect in an enforcement point is treating uncertainty as
permission. A PDP timeout, an unparsed response, an unknown decision
value, or an unverifiable receipt MUST withhold the action (Section
10.1). Designs that "allow on error to preserve availability" convert
every transient fault into an authorization bypass and do not conform.
Where availability genuinely outranks safety for a class of actions,
that class does not belong behind this profile.

**12.3. Mutation ordering and time-of-check/time-of-use.** The
reject-before-mutation invariant (Section 7) is only as strong as the
atomicity between the check and the write. An enforcement point MUST
ensure that the permitting decision in force at the moment of the write
is the decision for the exact action being written — same action hash,
unexpired, not already consumed. A gap between checking a decision and
applying the mutation is a time-of-check/time-of-use vulnerability: an
attacker who can alter the action between check and write defeats the
binding. Consume-once (Section 10.2) and action-hash binding together
close this only if the check-and-consume is atomic with respect to the
mutation.

**12.4. Observe-mode misrepresentation.** Because `observe` mode
records a decision without enforcing it, an operator could present an
`observe`-mode deployment as if it enforced. An enforcement point in
`observe` or `warn` mode MUST NOT claim enforcement and MUST mark the
effective decision honestly (Section 8). A relying party MUST NOT treat
an `observe`-mode record as evidence that an action was gated; it is
evidence only of what would have been decided.

**12.5. The enforcement point trusts the PDP's decision, not its
inputs.** This profile binds and orders a decision; it does not vouch
for the policy that produced it. A compromised or misconfigured PDP can
return `allow` for an action that should be gated, and the enforcement
point will faithfully permit it. The enforcement point's guarantees are
conditional on the PDP being sound: it guarantees that *no action
proceeds except under a permitting decision, bound to verifiable
evidence, with refusal ordered ahead of the write* — not that the
decision was correct. Soundness of policy is the PDP's responsibility
(Section 9) and is out of scope.

**12.6. What this profile does and does not establish.** A bound
receipt establishes that a specific decision was made for a specific
action and, for `allow_with_signoff`, that a named human approved it —
verifiable offline. It does not, by itself, establish that the
deployment was unbypassable; that depends on the declared enforcement
class (Section 10). It does not establish that the policy was correct
(Section 12.5). And it does not establish anything about an AI model's
behavior. Where the shared core's safety properties are
machine-checked, those proofs cover the core's authorization state
machine, not this profile's deployment topology or the PDP;
implementations MUST NOT represent core proofs as covering the
enforcement point's deployment. This profile is experimental and has
not been independently audited; conformance claims should be stated as
such.

## 13. IANA Considerations

This document has no IANA actions. A future version may request a
registry for the decision vocabulary (Section 3) so that additional
decision values, if ever needed, are added under a stable,
backward-compatible policy in which an unrecognized value MUST fail
closed.

## 14. References

[RFC2119] Bradner, S., "Key words for use in RFCs", BCP 14.
[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase", BCP 14.
[RFC8417] Hunt, P., et al., "Security Event Token (SET)".
[RFC9334] Birkholz, H., et al., "Remote ATtestation procedureS (RATS)
   Architecture".
[RFC9711] Lundblade, L., et al., "The Entity Attestation Token (EAT)".
[draft-schrock-ep-authorization-receipts] Schrock, I., "Authorization
   Receipts for High-Risk Agent Actions", individual Internet-Draft
   (work in progress).
[AUTHZEN] OpenID Foundation (AuthZEN WG), "Authorization API 1.0".
[OPA] Open Policy Agent project, "The Rego Policy Language".
[CEDAR] Cedar project, "Cedar Policy Language".

## Author's Address

Iman Schrock
EMILIA Protocol, Inc.
United States
Email: team@emiliaprotocol.ai
