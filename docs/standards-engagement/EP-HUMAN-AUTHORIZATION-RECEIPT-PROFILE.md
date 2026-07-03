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
| EU AI Act Article 50 profile (Dawkins) | regulatory transparency / human review | EP upgrades "a human reviewed" into **named accountable reviewer/quorum evidence** |
| HDP / IPP | delegated human intent provenance | intent explains *why*; the EP receipt proves *who said yes to exactly this* at the edge |

**Composition rule (uniform across all rows):** compose **by digest, not
containment**. A host profile embeds either `receipt_payload_digest =
SHA-256(JCS(receipt.payload))` (offline composition) or `statement_digest =
SHA-256(COSE_Sign1 bytes)` (when the receipt is registered in a transparency
service). Both are byte-reproducible in any language; the host record never
restates the approval, it commits to it.

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
4. **AI-Agent Action Receipts (Noa / Toraman)** — closest naming overlap; do
   not fight: their envelope carries EP as the human-authorization subreceipt.
5. **AIR / Execution Profile (Emirdag)** — clean pre/post complement.
6. **WIMSE / OAuth Transaction Tokens** — receipt-hash binding claims.
7. **Article 50 profile (Dawkins)** — EU bridge: named accountable reviewer.

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
