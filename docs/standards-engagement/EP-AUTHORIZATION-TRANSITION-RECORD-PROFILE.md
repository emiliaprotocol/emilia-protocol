<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP profile of the Authorization Transition Record (draft-kuehlewind-audit-architecture)

**Status:** individual profile, offered as input to the Agent Auditing Architecture
(`draft-kuehlewind-audit-architecture`, Kühlewind & Birkholz). It maps EP receipts onto
the one transition type the architecture leaves as a placeholder: an authorization change
whose triggering event is a named human's approval. EP is the verifiable evidence behind
that transition; the architecture keeps the record, the store, and the log. This profile
is referenced by the AUDIT engagement, not copied into the architecture.

**Anchors (against the current draft).** Section 7.4 defines the Authorization Transition
Record: authorization treated as a time-evolving state, whose ordered sequence
reconstructs the authorization in force at any timestamp. WI-8 (Authorization Transition
Encoding) carries **previous state, new state, triggering event, and responsible actor**.
WI-5 is HITL escalation signalling (step-up requests and the User's response: approval,
refusal, timeout). The draft states the Section 7 field names are placeholders pending
SC-1 through SC-11, which is why this mapping is offered now.

**Grounded in running code.** Every EP claim below is the behavior of the filed drafts and
their reference verifiers: `draft-schrock-ep-authorization-receipts`,
`draft-schrock-ep-quorum`, `draft-schrock-ep-revocation-statement`, verified offline in
`packages/verify/` (JavaScript, Python, Go) with public accept/refuse vectors.

## The transition EP fills

Section 7.4 lists the permission-state changes an Authorization Transition Record captures:
initial grants, step-up approvals, scope narrowing on exchange, revocation, and expiry. EP
does not author most of these. It authors exactly one, and it is the one with no
verifiable primitive today: **the step-up approval whose triggering event is a named,
accountable human authorizing a specific action.**

| WI-8 field | EP contribution for the human-approval transition | Honest scope |
|---|---|---|
| **triggering event** | An EP receipt: a named human's device-bound signature over the exact action, offline-verifiable against a pinned key with no call back to the issuer, bound to the action by a canonical action digest (JCS/SHA-256). The record references the receipt by that digest; the receipt is not embedded. | EP proves a human approved *this exact action*. It does not prove the human understood the surface shown to them; that is a display-integrity concern outside the receipt. |
| **responsible actor** | The `approver` named in the receipt, resolvable to a natural person through the Approver Directory at a stated identity-proofing grade. Maps to the draft's **User** actor type. | The key-to-person binding is only as strong as the enrollment ceremony's proofing. EP states that grade; it does not manufacture it. |
| **previous state / new state** | EP does not define the authorization state model; WI-8 does (reusing token-status-list where the state is token-status). EP supplies the *evidence that justifies* the transition, not the state encoding. | Deliberate: EP stays the evidence artifact, the architecture stays the record. |
| **refusal / not-escalated case (WI-5)** | A signed, terminal EP denial is a first-class outcome, and a missing approval is a fail-closed refusal with a reason, not an absence. So "an action that should have been escalated but was not" is a detectable refused-state, not silence. | EP records the refusal as evidence; whether the executor honored it is the executor's trusted computing base, not the receipt's. |

## Why the join is by digest, not by ingestion

The Authorization Transition Record references the EP receipt by its action digest. The
receipt stays inside EP's own trust boundary and is verified there. An Auditor (the
draft's WI-9 consumer) verifies the human approval **independently of the Transparency
Service that logged the transition**: it recomputes the action digest, checks the receipt
signature against the pinned approver key, and checks revocation state against a pinned
revoker snapshot. No leg ingests another leg's evidence into its trust boundary; they meet
only at the shared digest. This is the same composition rule EP uses everywhere.

## Serialization and registration fit

The profile fits the architecture's model as written. EP receipts are JSON/JWS today and
COSE/CBOR-expressible, register cleanly as SCITT Signed Statements (RFC 9943, see
`docs/EP-RECEIPT-SCITT-PROFILE.md`), and support detached payloads. So an implementer can
carry the human-approval triggering evidence in the same substrate the draft already
requires for the other three record classes, without a new transport.

## What this profile deliberately leaves to the architecture

- The Interaction, Action, and Delegation Records (Sections 7.1 to 7.3). EP composes with
  them through the shared action digest; it does not replace them.
- The Audit Store, the Transparency Log, and non-equivocation. EP produces the statement
  the log ingests; it does not run the log, and transparency-log inclusion proves logging
  per the log's policy, never that a human authorized the action.
- The delegation-chain semantics (WI-2). EP is human authorization, not delegation; a
  receipt verifies identically whichever agent presents it.

## Offered as WI-8 input

If the group finds it useful, EP receipts are a ready candidate encoding for the
human-approval Authorization Transition Record: filed Internet-Drafts, three-language
verifiers, and public accept/refuse vectors already exist to test the mapping against,
including the refuse case where the wrong action is presented under a valid signature.
