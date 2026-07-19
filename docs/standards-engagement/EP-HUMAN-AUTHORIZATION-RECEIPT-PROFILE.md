<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA as a Human Authorization Receipt Profile for SCITT Agent-Action Work

**Status:** engagement document · 2026-07-01
**Audience:** SCITT WG participants and authors of the agent-action evidence drafts
**Runnable companions:** [`examples/scitt/ep-receipt-scitt-end-to-end.mjs`](../../examples/scitt/ep-receipt-scitt-end-to-end.mjs) · [`examples/scitt/capsule-seam-vector.mjs`](../../examples/scitt/capsule-seam-vector.mjs) · [`docs/EP-RECEIPT-SCITT-PROFILE.md`](../EP-RECEIPT-SCITT-PROFILE.md)

## The one-sentence position

> SCITT proves a statement was **logged**. WIMSE and OAuth prove **which workload
> or token** acted. Permit/AgentROA prove **what policy allowed**. HDP/IPP carry
> **delegated intent**. EMILIA proves **a named human or quorum authorized this
> exact irreversible action before it ran** — offline-verifiable, independent of
> the operator, runtime, or transparency service.

EMILIA (EP) is **not** another transparency log, action envelope, agent-identity
scheme, or telemetry record. It is an **authorization-evidence profile**: a
compact signed artifact answering exactly one question —

> *Did the right human (or quorum), holding their own key, authorize this exact
> canonical action, before execution?*

Because it answers only that question, it is designed to be **embedded in or
referenced by** the other profiles rather than competing with them.

## Why this primitive is still missing

The agent-evidence space is no longer empty: RFC 9943 gives the transparency
architecture, SCRAPI the registration API, and multiple drafts now cover action
receipts, capsules, permits, refusal events, workload identity, and delegated
intent. What none of them produce is a **portable human-authorization
artifact**:

- named (or quorum) **accountable human**, key held by the human, not the
  operator;
- bound to the **exact canonical action bytes** (I-JSON/JCS + SHA-256 digest),
  not a session, scope, or intent description;
- **pre-execution** (the gate consumes it once; replay is refused);
- **verdict-complete** (a refusal is itself a signed event);
- verifiable **offline**, with no trust in the operator, the agent runtime, or
  the transparency service that later logs it.

The emerging gap is not lack of agent logs. It is lack of a portable human
authorization artifact that can be verified independently of the operator,
runtime, or transparency service. That artifact is what EP supplies; every
profile below gains a slot for it without changing its own scope.

## Composition map

| Draft / WG artifact | What it covers | EMILIA slot |
| --- | --- | --- |
| SCITT Architecture (RFC 9943) | transparent, logged signed statements | EP receipts are registered as Signed Statements ([profile](../EP-RECEIPT-SCITT-PROFILE.md)) |
| SCRAPI | register / retrieve Signed Statements | transport for EP receipts; runnable end-to-end demo below |
| Permit Profile (Muñoz) | pre-execution allow / deny / challenge | EP receipt as the `human_authorization_evidence` a Permit carries when policy demands a human |
| AI-Agent Action Receipts (Noa / Toraman) | per-action receipt envelope | EP as the **human-authorization subreceipt** inside the action receipt |
| Agent Action Capsule (Mih) | canonical record of WHAT was done | Capsule's opaque authority reference carries the EP receipt digest ([seam vector](../EP-CAPSULE-SEAM.md)) |
| AI Agent Execution Profile / AIR (Emirdag) | post-execution action evidence | AIR links back to the **prior** EP authorization by digest — pre/post pair |
| Verifiable AI Refusal Events | safety refusals as evidence | EP denied-receipts are the *authorization-layer* refusal (signed "no human authorized this") |
| WIMSE | workload identity | bind the human-approval receipt hash into the workload's action context |
| OAuth Transaction Tokens | transaction authorization context | claim carrying the EP receipt digest → txn provably backed by named-human approval |
| EU AI Act Article 50 profile (Dawkins) | regulatory transparency / human review | where Article 50 calls for human review, EP can supply the **named accountable reviewer/quorum evidence** behind it |
| HDP / IPP | delegated human intent provenance | intent explains *why*; the EP receipt proves *who said yes to exactly this* at the edge |

**Composition rule (uniform across all rows):** compose **by digest, not
containment**. A host profile embeds either `receipt_payload_digest =
SHA-256(JCS(receipt.payload))` (offline composition) or `statement_digest =
SHA-256(COSE_Sign1 bytes)` (when the receipt is registered in a transparency
service). Both are byte-reproducible in any language; the host record never
restates the approval, it commits to it.

## Verified sockets in adjacent receipt drafts

Checked against the posted revisions on 2026-07-11. Each of these documents
covers an adjacent layer well, and none of them defines EP's property bundle —
named accountable human bound to organizational authority, initiator
exclusion, distinct-human m-of-n quorum, mandatory single consumption,
offline verification. Three leave the human authorization artifact undefined
or out of scope; DRP defines a user-signed per-action confirmation and is the
nearest neighbor, which is exactly why the precise difference matters. The
open slots are the sockets this profile fills; none of the rows below is a
competing definition. Every characterization here quotes or paraphrases the
cited revision; re-verify against the current revision before external use.

| Draft (revision read) | What it owns, in its own words | The socket, in its own words | EP fill |
| --- | --- | --- | --- |
| `draft-lee-orprg-permit-receipts-00` | "requirements and an abstract data model for PermitReceipts used in permit-before-commit authorization" evaluated "at an effect boundary" | the model is deliberately principal-agnostic and abstract: it "does not define a complete policy language, does not select a mandatory wire format," and asks for "at least one concrete wire profile" — so it neither defines nor precludes a human-approver artifact | EP-RECEIPT-v1 as a concrete issuer-evidence artifact and wire profile for permits whose policy calls for a named human; joined by the action digest the verifier already evaluates |
| `draft-nelson-agent-delegation-receipts-10` (DRP) | user-to-agent session delegation, with a Micro-Receipt ("a minimal Delegation Receipt covering a single action") and its own replay-detection check, so "every approval [is] a signed, auditable artifact" | DRP is built around the *delegating user's* own consent within a session; it does not model *organizational* authorization — an approver acting under enrolled institutional authority, a distinct-human m-of-n quorum, or initiator exclusion | complementary layer, not overlap: DRP evidences the user's session delegation; EP evidences organizational accountable approval of one exact action (named approver under enrolled authority, EP-QUORUM-v1 distinct-human m-of-n, EP-INITIATOR-ATTESTATION-v1 initiator exclusion). A delegated agent that reaches a receipt-required effect boundary presents the EP receipt; the shared action digest joins the two records |
| `draft-farley-acta-signed-receipts-02` (ACTA) | a "format for recording machine-to-machine access control decisions" — Ed25519 (RFC 8032) over RFC 8785 canonical JSON, minimal disclosure, covering both synchronous policy checks and post-execution receipts (`tool_duration_ms` is "present only in post-execution receipts") | ACTA records the decision itself; by its own text receipts "do not include a nonce" (an "implementation MAY add" one), so the format does not define an accountable-human approval ceremony bound single-use to the action | same substrate, different claim: ACTA records *what a policy engine decided* (before or after the tool runs); EP evidences *a named accountable human's* approval of the exact action. An ACTA record for a decision escalated to a human can carry the EP receipt digest as payload metadata; a consumed EP receipt plus the ACTA decision record is a clean pre/post pair |
| `draft-nivalto-agentroa-route-authorization-01` (AgentROA) | agent capability envelopes, delegation chains, and gateway execution receipts, with `approval_state` (`pending` / `granted` / `not_required`) and an `approval_artifact_ref: String, OPTIONAL. Reference to the signed approval artifact` | the referenced approval artifact is left to a companion spec — the field is defined, the artifact it points to is not | EP-RECEIPT-v1 is a concrete artifact for that optional `approval_artifact_ref` (carrying `receipt_payload_digest` per the uniform composition rule above), so a relying party can offline-verify the human approval behind `approval_state: granted` |

Shared building blocks are not shared semantics. Ed25519 and canonical JSON are
substrate; these drafts use them for genuinely different claims — a decision
record, a permit, a delegation, a route authorization — much as many protocols
share TLS without becoming the same protocol. The property bundle EP defines —
named accountable human, key held by the human, exact canonical action bytes,
initiator exclusion, m-of-n quorum, single consumption, offline verification —
appears in none of the four documents above, and each of them has a place to
reference it.

## What EP deliberately does not do

- It is **not a log** — SCITT provides inclusion; EP provides authorization.
  The two receipts answer different questions and compose.
- It is **not agent identity** — WIMSE/OAuth say who acted; EP says who
  *approved*.
- It is **not policy** — Permit/AgentROA say what was allowed; EP evidences the
  human step those policies can demand.
- It is **not intent** — HDP/IPP carry what the user asked for; EP proves the
  named authorization of the exact final action.
- It does **not** claim a real-time human in the execution path: the honest
  latency story is pre-authorization, bounded delegation, and post-hoc
  evidence.

## Runnable proof, today

```bash
# EP receipt → COSE_Sign1 Signed Statement → SCRAPI (mock TS) → SCITT receipt
# → offline verify BOTH the authorization and the inclusion:
node examples/scitt/ep-receipt-scitt-end-to-end.mjs

# The who→what seam with an Agent Action Capsule, by shared digest,
# including five MUST-reject negative vectors:
node examples/scitt/capsule-seam-vector.mjs

# Cross-language conformance (JS / Python / Go agree on every vector):
npm run conformance
```

## Engagement order

1. **SCITT WG / SCRAPI / RFC 9943** — confirm the Signed-Statement profile
   composes cleanly (interop ask already sent; see
   [`SCITT-INTEROP-ASK.md`](./SCITT-INTEROP-ASK.md)).
2. **Permit Profile (Muñoz)** — highest leverage: EP as the
   `human_authorization_evidence` a Permit carries.
3. **Agent Action Capsule (Mih)** — optional EP authorization-receipt reference
   for material actions (seam vector already shipped and shared).
4. **AI-Agent Action Receipts (Noa / Toraman)** — their action-receipt envelope
   can carry an EP receipt as the human-authorization subreceipt; the two
   compose by digest rather than competing.
5. **AIR / Execution Profile (Emirdag)** — clean pre/post complement.
6. **WIMSE / OAuth Transaction Tokens** — receipt-hash binding claims.
7. **Article 50 profile (Dawkins)** — EU bridge: named accountable reviewer.
8. **AgentROA (Nivalto)** — the most literal socket: a concrete profile for
   `approval_artifact_ref`, making `approval_state: granted` verifiable.
9. **ORPRG PermitReceipts (Lee)** — answer its open wire-profile question: EP
   as a concrete issuer-evidence wire profile for human-required permits.
10. **ACTA (Farley)** — pre/post pair: EP consumed receipt before the effect,
    ACTA decision record after; EP digest as payload metadata on escalated
    decisions.
11. **DRP (Nelson)** — composition note: user-side delegation plus
    organizational approval joined by the shared action digest (engagement
    already active via the joint composition work).

## Relationship to the EP Internet-Drafts

- **`draft-schrock-human-authorization-binding`** (SCITT expression section; absorbed the former scitt-authorization-evidence draft 2026-07-03) — **the citable form of this
  document**: the normative profile defining how a SCITT-family agent-action
  statement references a named-human authorization receipt by digest, and how a
  relying party verifies the linkage. This is the artifact the Permit / Capsule /
  Action-Receipt drafts can normatively reference for their human-authorization
  slot. Source: [`standards/draft-schrock-human-authorization-binding-00.xml`](../../standards/draft-schrock-human-authorization-binding-00.xml).
- `draft-schrock-ep-authorization-receipts` — the receipt primitive this
  profile transports (rev -05 sharpens the composition framing).
- `draft-schrock-ep-quorum` — the quorum (two-person rule) variant of the same
  evidence.
- The SCITT Signed-Statement encoding is specified in
  [`docs/EP-RECEIPT-SCITT-PROFILE.md`](../EP-RECEIPT-SCITT-PROFILE.md) and
  exercised by the conformance vectors in `examples/scitt/`.
