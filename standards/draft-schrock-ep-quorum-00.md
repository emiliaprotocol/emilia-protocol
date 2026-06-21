# Multi-Party Quorum Authorization for High-Risk Agent Actions (EP-QUORUM)
## draft-schrock-ep-quorum-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                              20 June 2026
Expires: 22 December 2026
```

### Abstract

This document defines EP-QUORUM, a multi-party authorization profile for
the EMILIA Protocol (EP) authorization receipt
[draft-schrock-ep-authorization-receipts]. Where the base receipt binds a
single accountable human to one exact high-risk action, EP-QUORUM binds a
*set* of distinct accountable humans — the "two-person rule," generalized
to M-of-N and to ordered approval trails — to one exact action, such that
no action is authorized until the full quorum holds. The profile is purely
additive: each quorum member is an unmodified EP signoff over the same
action hash, and a single-approver policy is the degenerate one-member
case. EP-QUORUM specifies a fail-closed quorum predicate (all member
signatures valid, every member bound to the exact action, approvers
pairwise distinct, every approver admitted by role, the threshold met, the
declared order respected, and all signatures within a bounded time window),
an incremental server-side admission rule that rejects a non-conforming
signer before it enters the trail, and a set of adversarial conformance
vectors. The predicate is offline-verifiable under the base draft's
verification model and is maintained as cross-language conformance vectors
that three independent implementations (JavaScript, Python, Go) are
required to agree on.

### Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions
of BCP 78 and BCP 79. Internet-Drafts are working documents of the IETF.
This document is an individual submission and has no formal standing in the
IETF standards process.

This document depends normatively on
[draft-schrock-ep-authorization-receipts] and uses its terminology without
restating it.

---

## 1. Introduction

The base EP authorization receipt closes the gap between "is this actor
authorized in general?" and "should this exact action happen, and which
accountable human said yes?" by binding one named approver's device-held
signature to one exact action (see [draft-schrock-ep-authorization-receipts],
Section 1). For the highest-consequence actions, one approver is not the
right control. The discipline that governs nuclear release, large-value
treasury movement, and production-credential change is the *two-person
rule*: no single human — however well-authenticated, however senior — can
unilaterally cause the action. Two or more distinct, accountable humans
must each independently authorize, and the action proceeds only when all of
them have.

As autonomous agents acquire credentials sufficient for irreversible
operations, the two-person rule is exactly the control that lets an
organization grant an agent real authority without creating a single point
of failure: a compromised, misaligned, or prompt-injected agent cannot act
alone, and neither can a single compromised or coerced approver. EP-QUORUM
specifies how to express that control as a cryptographic predicate over EP
signoffs and how to enforce it both at the moment each approver signs and
at the moment the action would execute.

The base draft already contemplates multi-approver policies
([draft-schrock-ep-authorization-receipts], Section 7): each approver signs
an individual Authorization Context sharing the same action hash, and
commitment occurs only when *k* valid, distinct signoffs exist before
expiry. This document makes that sketch normative and testable. It adds:
ordered approval trails (Section 4); an explicit role roster and admission
semantics (Section 3); a bounded approval window with a monotonic-time
constraint for ordered mode (Section 4); an incremental server-side
admission rule, `canAccept`, that keeps a non-conforming signer out of the
trail in the first place (Section 6); the consolidated fail-closed quorum
predicate, `quorumGate` (Section 5); and an adversarial conformance suite
(Section 8).

### 1.1. Design Goals

EP-QUORUM inherits design goals G1–G7 of the base draft and adds:

- **Q1 — Additivity.** A quorum is a set of unmodified EP signoffs over the
  same action hash. No new signature type, no new signing ceremony, and no
  change to the receipt verifier are introduced. A single-approver policy
  is the one-member quorum.
- **Q2 — Fail-closed.** Authorization is denied unless *every* element of
  the quorum predicate holds. Absence of evidence, an unparseable member, a
  malformed policy, or any single failed check yields "not satisfied," never
  "satisfied."
- **Q3 — Distinctness (separation of duties at the human level).** A quorum
  of size *k* requires *k* pairwise-distinct human approvers, each distinct
  from the initiator. One human MUST NOT fill two slots.
- **Q4 — Incremental enforcement.** The protocol enforces conformance as
  each approver signs, not only at consume time, so that a wrong-action,
  wrong-role, duplicate, out-of-order, stale, or invalid signature never
  becomes part of the trail.
- **Q5 — Offline-verifiable quorum.** The satisfied/not-satisfied judgment
  is computable from the receipt's members and the policy alone, under the
  same offline verification model as the base draft
  ([draft-schrock-ep-authorization-receipts], Section 6.3).

## 2. Terminology

In addition to the terminology of [draft-schrock-ep-authorization-receipts]:

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "MAY" are
to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only
when, they appear in all capitals.

**Quorum.** The set of distinct approver signoffs required to authorize one
action under a Quorum Policy.

**Quorum Policy.** A named, versioned rule set declaring the approval mode,
the required count, the roster of eligible (role, approver) slots, the
distinct-humans rule, and the approval window. Carried in the policy that
governs the action; see Section 3.

**Member.** One element of a candidate quorum: a (role, approver public
key, signoff) triple, where the signoff is an unmodified EP signoff
([draft-schrock-ep-authorization-receipts], Section 5.3) over the
Authorization Context the approver signed.

**Trail.** The ordered sequence of members admitted so far for one
action — the partial quorum under construction.

**Quorum Gate.** The fail-closed predicate (Section 5) that decides whether
a trail is a satisfied quorum. The Verifying Executor
([draft-schrock-ep-authorization-receipts], Section 9) MUST consult it
before performing the action.

## 3. The Quorum Policy

A Quorum Policy is a JSON object:

```json
{
  "mode": "ordered",
  "required": 3,
  "approvers": [
    { "role": "program_officer",       "approver": "ep:approver:po_rivera" },
    { "role": "authorizing_official",  "approver": "ep:approver:ao_chen"   },
    { "role": "inspector_general",     "approver": "ep:approver:ig_okafor" }
  ],
  "distinct_humans": true,
  "window_sec": 900
}
```

Members:

| Field | Required | Type | Meaning |
|-------|----------|------|---------|
| `mode` | REQUIRED | string (enum) | `threshold` or `ordered` (Section 4). |
| `required` | REQUIRED | integer ≥ 1 | The quorum size *k*. |
| `approvers` | REQUIRED | array | The roster of eligible `{ role, approver }` slots. MUST be non-empty. |
| `distinct_humans` | OPTIONAL (default `true`) | boolean | When true, no approver identifier may fill more than one slot. Implementations MUST treat a missing value as `true`. |
| `window_sec` | OPTIONAL (default `900`) | integer > 0 | Maximum span, in seconds, between the first and any later admitted signature. |

Rules:

- An `approver` slot identifies an eligible approver in the Approver
  Directory ([draft-schrock-ep-authorization-receipts], Section 5.2). The
  `role` is the organizational role under which that approver is admitted to
  this quorum; it is the unit of role eligibility (Section 5, check 4).
- A member is admitted only if its `(role, approver)` pair is present in the
  roster. A correct signature by a real, enrolled approver who is not on the
  roster for this action MUST be rejected (`wrong_role`).
- `required` MUST NOT exceed the number of distinct human approvers the
  roster can supply under `distinct_humans`. A policy that cannot be
  satisfied is a misconfiguration; verifiers treat an unsatisfiable trail as
  not satisfied, as always.
- The Quorum Policy is part of the action's governing policy and is
  therefore committed by the `policy_hash` of every member's Authorization
  Context ([draft-schrock-ep-authorization-receipts], Section 4). A
  signature collected under one Quorum Policy version MUST NOT satisfy a
  requirement evaluated under another.

## 4. Approval Modes

**Threshold mode (`"threshold"`).** Any `required` distinct approvers drawn
from the roster, in any order, satisfy the quorum. This is the classic
M-of-N rule.

**Ordered mode (`"ordered"`).** Approvals MUST occur in the roster's listed
order: the *i*-th admitted member MUST match `approvers[i-1]` in both role
and approver. In addition, signature times MUST be strictly increasing —
each member's `issued_at` MUST be later than the previous admitted member's
`issued_at` (`non_increasing_time`). Ordered mode expresses escalation
chains in which a later authority signs *after, and in knowledge of,* an
earlier one (e.g., Program Officer → Authorizing Official → Inspector
General).

In both modes, every admitted member's `issued_at` MUST fall within
`window_sec` of the first admitted member's `issued_at` (`window_exceeded`).
The window bounds the lifetime of a partial quorum so that a long-dormant
partial trail cannot be completed much later by an attacker who has since
compromised a remaining approver.

## 5. The Quorum Gate (fail-closed predicate)

A trail is a **satisfied quorum** for an action with hash `H` under policy
`P` if and only if ALL of the following hold. A verifier MUST return
"satisfied" only when every check passes, and MUST return "not satisfied"
on the first failure, on a malformed policy or member, or on any
unrecognized condition (Q2):

1. **Well-formed policy.** `P` has a recognized `mode`, an integer
   `required ≥ 1`, and a non-empty `approvers` roster. Otherwise: not
   satisfied.
2. **All signatures valid.** For every member, the EP signoff verifies under
   [draft-schrock-ep-authorization-receipts], Section 5.3 / 6.3 — the
   WebAuthn assertion (Class A) verifies against the member's
   `approver_public_key`, with the assertion challenge equal to the member's
   context hash and user verification asserted. One invalid signature
   (`one_bad_signature`) fails the whole quorum.
3. **Action binding.** Every member's Authorization Context carries
   `action_hash == H` (`action_mismatch`). A member bound to any other
   action does not count.
4. **Role admission.** Every member's `(role, approver)` pair is present in
   the roster (`wrong_role`).
5. **Distinct humans.** When `distinct_humans` is true (the default),
   approvers are pairwise distinct and (per the base draft's
   SelfApprovalImpossible) distinct from the initiator (`duplicate_human`).
6. **Threshold.** At least `required` admitted members exist
   (`under_threshold`).
7. **Order (ordered mode only).** The *i*-th admitted member matches
   `approvers[i-1]`; signature times are strictly increasing
   (`out_of_order`, `non_increasing_time`).
8. **Window.** Every admitted member's `issued_at` is within `window_sec` of
   the first member's `issued_at` (`window_exceeded`).

The predicate is the same whether computed by the orchestrating operator
before consumption or by an independent Verifying Executor or auditor
offline (Q5): it is a pure function of `(P, H, members)`. Because each
member is an unmodified EP signoff, check 2 is exactly the base draft's
verifier invoked per member; EP-QUORUM adds the set-level checks 1, 3–8 on
top.

## 6. Incremental Admission (`canAccept`)

To keep a non-conforming signer out of the trail rather than discovering it
only at consume time (Q4), an orchestrator MUST evaluate an incremental
admission rule before recording each new signoff. Given the policy `P`, the
action hash `H`, the already-admitted trail, and one incoming candidate
member, the rule ADMITS the candidate only if all of the following hold,
and otherwise REJECTS it with the named reason:

1. `P` is well-formed and its roster is non-empty (else `no_policy` /
   `no_eligible_approvers`).
2. The candidate's context carries `action_hash == H` (else
   `action_mismatch`).
3. The candidate's `(role, approver)` is on the roster (else
   `ineligible_role`).
4. When `distinct_humans` is true, no already-admitted member shares the
   candidate's approver (else `duplicate_human`).
5. In ordered mode, the candidate matches the next unfilled roster slot
   (`approvers[len(trail)]`) in both role and approver (else
   `out_of_order`).
6. If the trail is non-empty, the candidate's `issued_at` is within
   `window_sec` of the first member's `issued_at` (else `window_exceeded`);
   and in ordered mode it is strictly greater than the last admitted
   member's `issued_at` (else `non_increasing_time`).
7. The candidate's signature verifies (else `invalid_signature`).

A rejected candidate MUST NOT be written into the trail. Incremental
admission is an enforcement convenience and an early-rejection UX; it is not
a substitute for the Quorum Gate. A conforming Verifying Executor MUST
re-evaluate the full Quorum Gate (Section 5) over the assembled trail before
performing the action, regardless of incremental admission, because the
executor does not trust the orchestrator to have applied admission honestly
(this mirrors the base draft's execution-side enforcement, Section 9).

## 7. Member Representation in the Receipt

A quorum receipt is an ordinary EP Trust Receipt
([draft-schrock-ep-authorization-receipts], Section 6.2) whose `contexts`
and `signoffs` arrays carry one entry per admitted member, plus the Quorum
Policy (by reference via `policy_hash`, and OPTIONALLY inline for
convenience). For the offline quorum computation, each member is the triple:

```json
{
  "role": "program_officer",
  "approver_public_key": "<SPKI of the approver's enrolled key>",
  "signoff": {
    "@type": "ep.signoff",
    "context": { "context_type": "ep.signoff.v1", "action_hash": "...", "approver": "...", "issued_at": "...", "...": "..." },
    "webauthn": { "authenticator_data": "...", "client_data_json": "...", "signature": "..." }
  }
}
```

The `context` and `webauthn` members are exactly as defined by the base
draft; EP-QUORUM does not alter their canonicalization, hashing, or
signature verification. The `role` and `approver_public_key` are the
join keys against the Quorum Policy roster and the Approver Directory.

## 8. Conformance

An implementation conforms to EP-QUORUM if, for the published adversarial
conformance vectors, it returns the expected satisfied/not-satisfied verdict
for every vector and rejects every non-conforming candidate at incremental
admission with the expected reason. The reference suite (`EP-QUORUM-v1`)
comprises the following vectors, each carrying real Class-A WebAuthn
assertions:

| Vector | Expect | Exercises |
|--------|--------|-----------|
| `accept_ordered_3of3` | satisfied | Ordered PO → AO → IG, distinct, increasing time, all action-bound |
| `accept_threshold_2of3` | satisfied | Any 2 distinct approvers from a 3-slot roster |
| `reject_under_threshold` | not satisfied | Fewer than `required` valid members |
| `reject_duplicate_human` | not satisfied | One human filling two slots |
| `reject_out_of_order` | not satisfied | Ordered mode, members out of roster order |
| `reject_action_mismatch` | not satisfied | A member bound to a different action hash |
| `reject_expired_window` | not satisfied | A member outside `window_sec` |
| `reject_one_bad_signature` | not satisfied | One invalid member signature |
| `reject_wrong_role` | not satisfied | A correct signature by an off-roster approver |

The reference suite is maintained such that three independent
implementations (JavaScript, Python, Go) MUST agree on every vector;
divergence is a conformance defect in at least one implementation. The
"accept" vectors guard against a verifier that is too strict (denying valid
quorums); the "reject" vectors guard against a verifier that is too lenient
(the security-critical direction).

## 9. Security Considerations

EP-QUORUM inherits all Security Considerations of
[draft-schrock-ep-authorization-receipts] and adds the following. Several
restate, honestly, what a quorum does *not* buy.

**9.1. What multi-party authorization does and does not prevent.** A
satisfied quorum proves that `k` pairwise-distinct enrolled approvers each
produced a valid, action-bound, in-window, in-order (where required)
signature with their own device-held keys, and that the orchestrator could
not have forged any of them ([draft-schrock-ep-authorization-receipts],
Section 11.1). It raises the cost of unilateral action: a single compromised
agent, a single stolen key, a single coerced or malicious approver is
insufficient. It does NOT defeat collusion among the required number of
distinct humans, nor one human who controls multiple enrolled identities (an
enrollment control — base draft Section 5.2), nor simultaneous coercion of a
full quorum. As in the base draft, EP-QUORUM makes such events
*attributable* — named, signed, and evidenced for every member — which is a
deterrent and an audit primitive, not an impossibility proof. Implementations
MUST NOT claim a quorum is collusion-proof.

**9.2. Fail-closed is the only safe default.** The dangerous error in a
multi-party gate is to treat ambiguity as approval. EP-QUORUM is specified so
that a malformed policy, a missing or unparseable member, a partial trail, or
any single failed check yields "not satisfied." A verifier MUST NOT default
to satisfied on any unrecognized condition. The "reject" conformance vectors
exist to catch a regression in this direction.

**9.3. Partial trails confer no authority.** A trail short of the threshold,
or one in which incremental admission has accepted some but not all required
slots, authorizes nothing. A Verifying Executor presented with a partial
trail MUST refuse, exactly as it refuses a missing single signoff. This is
the multi-party form of the base draft's NoBypassWrite invariant.

**9.4. Window and replay.** The approval window (`window_sec`) bounds how
long a partial quorum remains completable, limiting the value to an attacker
of compromising a *remaining* approver after some approvals already exist.
Each member's signoff retains the base draft's one-time-consumption nonce
(G3); the window is an additional, quorum-level constraint, not a substitute
for per-signoff replay protection. The monotonic-time rule in ordered mode
additionally prevents back-dating a later authority's signature to appear to
precede an earlier one.

**9.5. Divide-and-misinform across members.** Because each approver signs
their own Authorization Context, a malicious orchestrator can attempt to show
different approvers different renderings or different initiator attestations
([draft-schrock-ep-authorization-receipts], Section 11.9) while each
individual signature remains valid. EP-QUORUM does not change the base
draft's cross-context consistency requirement; verifiers SHOULD surface
per-member context differences, and high-value ordered policies SHOULD render
the prior approvers' decisions to each subsequent approver so that the trail
is a chain of informed approvals rather than parallel ones. The
presentation-attack mitigations of base draft Section 11.3 apply per member.

**9.6. Approver fatigue, at quorum scale.** Requiring more humans does not
help if each rubber-stamps; it can hurt, by diffusing responsibility across a
group in which no member feels decisive (base draft Section 11.8). Quorum
policies MUST be scoped to genuinely high-consequence, low-frequency actions,
and deployments SHOULD monitor per-role time-to-sign and deny rates rather
than assume that more signers means more scrutiny.

## 10. IANA Considerations

This document has no IANA actions.

## 11. References

### 11.1. Normative References

[draft-schrock-ep-authorization-receipts] Schrock, I., "Authorization
   Receipts for High-Risk Agent Actions (EP)", Internet-Draft
   draft-schrock-ep-authorization-receipts (work in progress).
[RFC2119] Bradner, S., "Key words for use in RFCs", BCP 14.
[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase", BCP 14.
[RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)".
[WEBAUTHN] W3C, "Web Authentication: An API for accessing Public Key
   Credentials, Level 2".

## Author's Address

Iman Schrock
EMILIA Protocol, Inc.
United States
Email: team@emiliaprotocol.ai
