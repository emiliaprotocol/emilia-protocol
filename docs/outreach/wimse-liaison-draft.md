<!-- SPDX-License-Identifier: Apache-2.0 -->
# WIMSE liaison — staged outreach (DO NOT SEND without Iman's approval)

**Status:** STAGED. Sending to a public IETF mailing list is an outward, irreversible act — hold for explicit approval. Send from `team@emiliaprotocol.ai`, not gmail.

**Why now (the seam):** WIMSE (Workload Identity in Multi-System Environments) standardizes *machine/workload* identity and token exchange/translation across system boundaries — and is explicitly scoped to stop at workload-to-workload. That leaves the human-authorization layer above it unowned. The risk: someone bolts a half-baked "human approved this" claim into a WIMSE token-exchange draft. The move: get EP framed, collegially and early, as the complementary human-authorization layer that composes with WIMSE — without trying to expand WIMSE's scope (stay Switzerland).

**Best venue (pick one, lowest-friction first):**
1. A short note on the **WIMSE WG list** (`wimse@ietf.org`) in reply to a token-exchange / architecture thread — lightest touch, most visible.
2. A focused comment to the authors of **draft-saxe-wimse-token-exchange-and-translation** (individual draft, the natural seam) — more targeted, less public.

**Hard rules:** credit their scope; do NOT propose expanding WIMSE; do NOT ask them to adopt EP; offer the complement + a pointer, nothing more. One short message. No attachments.

---

## Draft (list note / author email)

**Subject:** Workload identity ↔ human authorization — a complementary layer above WIMSE token-exchange

Hi all —

Following the WIMSE work on workload identity and token exchange/translation with interest. The model is clean: it establishes *which workload* is calling and lets that identity propagate and be exchanged across boundaries.

One adjacent question the charter (rightly) doesn't take on: when a workload's action is **irreversible** — a payment, a deletion, a production change — what proves that a **named human** authorized *that exact action*? That's a different trust root (a person, not a workload) and a different artifact (a durable, offline-verifiable authorization receipt, not a bearer/exchange token).

We've been working on exactly that layer as an individual Internet-Draft, `draft-schrock-ep-authorization-receipts` (Apache-2.0, reference verifiers in JS/Python/Go): an Ed25519-over-RFC 8785 receipt binding a named human to a specific action, verifiable offline. It's designed to **compose with** workload identity, not replace it — a WIMSE-identified workload carries the receipt as evidence that a human authorized what it's about to do. It expresses naturally as JWS (RFC 7515) and can ride inside an RFC 9421-signed request or a token-exchange (RFC 8693) actor chain.

Not proposing any change to WIMSE's scope — just flagging the seam in case it's useful as you think about token exchange/translation, and happy to share the binding model if there's interest.

Best,
Iman Schrock
EMILIA Protocol · team@emiliaprotocol.ai
`draft-schrock-ep-authorization-receipts`

---

**One-line framing to keep consistent everywhere:** *WIMSE gives the agent an identity; EMILIA gives the agent a named human's authorization to act.*
