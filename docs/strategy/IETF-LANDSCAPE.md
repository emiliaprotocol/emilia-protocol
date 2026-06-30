<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA in the IETF landscape — a complement, not a competitor

EMILIA Protocol is the **human-authorization-receipt layer**. It composes with the
accepted standards the ecosystem already runs — it rides inside them, sits beside
them, and is logged by them — rather than replacing any of them. The receipt EMILIA
produces is the one durable artifact none of these standards emit on their own:
portable, offline-verifiable proof that a named human authorized one exact
irreversible action.

This is the public companion to `/standards`. It is a reference doc; the content is
verified IETF research presented cleanly.

## The three-pillar story (lead)

> EMILIA is the human-authorization receipt that **Step-Up triggers**,
> **RATS/EAT sits beside**, and **SCITT logs**.

### 1. TRIGGER (deployed) — OAuth Step-Up Authentication, RFC 9470 (Proposed Standard)
Step-Up demands a fresh human challenge for a sensitive action, but produces **no
durable artifact**. EMILIA is the offline, verifiable receipt of that step-up — the
proof that survives after the challenge passes.

### 2. ORTHOGONAL TRUST ROOT (deployed) — machine attestation
RATS (RFC 9334) + EAT (RFC 9711), SPIFFE/SPIRE, and WIMSE answer *"is this agent's
platform trustworthy / which workload is this."* EMILIA answers the **orthogonal**
question: *"did a NAMED HUMAN authorize THIS exact irreversible action."* Same
evidence bundle, different trust root.

### 3. ACCOUNTABILITY RAIL (standardizing now) — SCITT, draft-ietf-scitt-architecture
A SCITT **"Receipt"** is a transparency / **inclusion** proof: it proves a statement
was logged in an append-only ledger. SCITT is deliberately **agnostic about who
authorized anything** — that delegated-away question is exactly EMILIA's payload. So
an EMILIA **authorization** receipt rides **as** a SCITT Signed Statement, and SCITT
returns a **transparency** receipt that it was logged.

**Defuse the shared word:** *"authorization receipt"* (EMILIA) vs *"transparency /
inclusion receipt"* (SCITT). They are different artifacts that compose.

## A tiered complement table

### Tier 1 — published RFCs / deployed (anchor here)

| Standard | Status | How EMILIA complements it |
| --- | --- | --- |
| OAuth 2.0 / OIDC — RFC 6749 | Published · ubiquitous | Grants access. EMILIA proves a named human authorized the exact act. |
| Step-Up Authentication — RFC 9470 | Proposed Standard | The trigger. EMILIA is the durable proof that the step-up happened. |
| Rich Authorization Requests (RAR) — RFC 9396 | Proposed Standard | EMILIA signs the human approval of the same `authorization_details`. Note: RAR = request schema; EMILIA = evidence over it. |
| RATS — RFC 9334 + EAT — RFC 9711 | Published | Machine attestation (platform / workload). EMILIA = human authorization. Orthogonal trust roots, same bundle. |
| HTTP Message Signatures — RFC 9421 | Proposed Standard | EMILIA rides inside a signed request. |
| JWS — RFC 7515 / COSE — RFC 9052 / CWT — RFC 8392 | Published | Interop serializations EMILIA receipts express in. |
| Token Exchange — RFC 8693 | Proposed Standard | Delegates authority between services. EMILIA proves the human authorized the irreversible act at the chain's end. |
| SPIFFE / SPIRE | CNCF graduated | Agent identity. EMILIA adds who approved what it does. |
| Trusted timestamp — RFC 3161 | Published | Trusted time source for receipt freshness. |
| Evidence Record Syntax (ERS) — RFC 4998 | Published | Lineage for EMILIA's evidence-record renewal chain. |
| JSON Canonicalization Scheme (JCS) — RFC 8785 | Published | EMILIA's canonical base. |

### Tier 2 — position relative to, don't anchor (active drafts)

| Standard | Status | How EMILIA complements it |
| --- | --- | --- |
| SCITT — architecture + SCRAPI + COSE Receipts | Active drafts | EMILIA authorization receipts ride as SCITT Signed Statements; SCITT logs them and returns transparency receipts. |
| OAuth Transaction Tokens (Txn-Tokens) | Active draft | Short-lived call-chain context. EMILIA is the human-authorization evidence over the irreversible act, not the transport token. |
| WIMSE (Workload Identity in Multi-System Environments) | Active drafts | Workload identity. EMILIA adds the human-authorization layer above the workload trust root. |
| SD-JWT-VC / EUDI | Active drafts | Selective-disclosure credentials. EMILIA receipts can be carried / referenced; the authorization claim is EMILIA's. |

## Interop note

EMILIA keeps **JCS (RFC 8785)** as its canonical base and offers receipts as:

- **JWS (RFC 7515)** — universal web reach.
- **COSE_Sign1 / CWT (RFC 9052 / RFC 8392)** — CBOR-native, for SCITT interop.

The same authorization claim travels across all three — no lock-in to a wire format.

See also: the receipt on a real action at `/fire-drill/rr-1`, and the spec at
`/spec` (`draft-schrock-ep-authorization-receipts`).

## Honest framing

EMILIA is an active **individual Internet-Draft**,
`draft-schrock-ep-authorization-receipts`, licensed **Apache-2.0**. It is **not** an
IETF standard and **not** an endorsement by any working group. The relationships
above are **complement relationships** — how EMILIA composes with these standards —
**not** claims of adoption by the OAuth, RATS, SCITT, WIMSE, or any other WG.
