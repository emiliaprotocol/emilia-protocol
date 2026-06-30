<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA as RATS + SCITT profiles — vocabulary mapping

**Status:** working artifact for WG engagement. Not yet posted to any IETF list. Refine before posting.

## The principle

The IETF rewards **narrow profiles on accepted work, backed by running code** — and is allergic to monolithic frameworks that re-invent vocabulary and don't integrate with existing standards. So EMILIA (and the COSA attest loop) should be expressed as **lightweight usage profiles of RATS and SCITT**, not as a new lifecycle protocol. We are not inventing object physics; we are filling one named gap — *did a person authorize this exact irreversible action* — and logging it on the substrate the supply-chain world already runs.

Concrete demand (the interop reason a WG will accept): **EU AI Act Article 14** human-oversight obligations (Annex III, enforcement Dec 2 2027) require demonstrable, durable human authorization of high-risk agent actions. RATS attests the machine; SCITT logs the statement; **EMILIA is the human-authorization artifact in between.**

## Two layers, two questions, one decision point

| | Question it answers | Trust root |
|---|---|---|
| **RATS** (machine attestation) | Is the agent's *platform / compute context* trustworthy? | hardware / firmware / TEE root of trust |
| **EMILIA** (human authorization) | Did a *named human* authorize *this exact action*? | the human's device key (WebAuthn / passkey) |

They are **orthogonal and composable**: the Relying Party requires *both*. RATS does not model human approval; EMILIA does not attest platforms. Keeping them separate is the whole point — collapsing the human receipt into RATS would lose the differentiator and (correctly) draw "RATS doesn't do humans" from the WG.

## A. The attest loop as a RATS profile (RFC 9334)

The COSA / `@emilia-protocol/attest` machine-attestation loop maps cleanly onto the RATS architecture:

| RATS role (RFC 9334) | EMILIA / COSA component | Produces |
|---|---|---|
| **Attester** | the agent / host | **Evidence**: claims about its identity + compute context |
| **Verifier** | the "God Terminal" | appraises Evidence vs Reference Values → **Attestation Result** |
| **Relying Party** | the gateway / substrate | consumes the Attestation Result **and** the EMILIA authorization receipt to authorize execution |

**Precision (do not skip):** the **EMILIA authorization receipt is NOT a RATS role or RATS Evidence.** RATS Evidence is about the attesting *environment's* trustworthiness. The EMILIA receipt is a distinct artifact — a named human's signoff over the exact action — that the **Relying Party evaluates alongside** the Attestation Result. Its trust root is the human's device key, not the platform RoT. (Evidence/Results can be carried as **EAT, RFC 9711**; an EMILIA receipt can ride in the same bundle as a separate claim, but it is not platform Evidence.)

**"Decay" → freshness, in standard terms.** Replay/staleness control is *freshness*, not physics: RATS freshness (nonce / epoch) for the attestation, plus EMILIA's validity window + observed-evidence freshness for the authorization. Don't ship the word "decay" to the list.

## B. Packing Slip / Bill of Lading / lineage as SCITT Signed Statements (draft-ietf-scitt-architecture)

| SCITT term | EMILIA / COSA component |
|---|---|
| **Signed Statement** (COSE_Sign1: an Issuer's signed assertion about an Artifact) | an **EMILIA authorization receipt** (issuer = the authorizing authority; Artifact = the exact action / action_digest); a COSA **Packing Slip / Bill of Lading** (signed assertion about a digital object's state + execution) |
| **Transparency Service** (append-only verifiable log) | the registry that ingests these statements and orders them non-equivocally |
| **Receipt** (inclusion proof the statement was registered) | returned by the Transparency Service — proof the EMILIA/COSA statement was logged |
| **Transparent Statement** (Signed Statement + Receipt) | a logged EMILIA receipt |
| **SCRAPI** (register/retrieve REST API) | how EMILIA/COSA register statements with any conforming Transparency Service |

**Precision (do not skip):** SCITT provides the **append-only, tamper-evident, non-equivocating log + inclusion proofs**. It is *agnostic about who authorized anything.* The **execution lineage chain is EMILIA/COSA content, not a SCITT feature**: each hop is a Signed Statement that **carries a prev-state hash binding it to the prior hop** (EMILIA evidence-chain / AEC); registering each hop with the Transparency Service gives you tamper-evident *ordering + inclusion* on top of *our* linking. SCITT doesn't give you the chain — **we** give the chain; SCITT gives the log.

**Vocabulary discipline — the single most important rule:** never let the two "receipts" blur.
- **"authorization receipt"** = EMILIA = *who authorized what* (semantic).
- **"transparency / inclusion receipt"** = SCITT = *proof it was logged* (structural).

## Serialization

EMILIA's canonical base is RFC 8785 (JCS). For interop it serializes as **JWS (RFC 7515, EdDSA)** — shipped, `EP-RECEIPT-JWS-PROFILE-v1` — for universal reach, and as **COSE_Sign1 / CWT (RFC 9052 / 8392)** for SCITT-native ingestion (SCITT Signed Statements *are* COSE). Same Ed25519 key; same canonical receipt material.

## Status (cite accurately)

- **RATS architecture — RFC 9334** (Informational, published). **EAT — RFC 9711** (Proposed Standard, published).
- **SCITT — `draft-ietf-scitt-architecture` + `draft-ietf-scitt-scrapi` + COSE Receipts (`draft-ietf-cose-merkle-tree-proofs`)** — active WG drafts, not yet RFCs. Real deployment exists (Microsoft Signing Transparency is GA), so the substrate is not theoretical.
- **EMILIA — `draft-schrock-ep-authorization-receipts`** — individual Internet-Draft, Apache-2.0. *Not* an IETF standard and *not* endorsed by the RATS or SCITT WGs. These are complement relationships, not adoption claims.

## Why this dodges the three objections that stalled monolithic proposals

1. **"Very large effort / monolith."** → Two narrow profiles on existing RFCs + WG drafts, with conformance vectors (JS/Python/Go) already passing. Running code in approved slots, not a new framework.
2. **"Doesn't integrate with RATS / SCITT / identity."** → It *is* a RATS profile and a SCITT statement profile, and it references the identity/delegation layer (OAuth Step-Up RFC 9470, RAR RFC 9396, WIMSE) rather than re-inventing it.
3. **"Looks like a commercial token / DRM / NFT."** → An EMILIA receipt is **accountability evidence the operator keeps for its own liability** — not a transferable asset, not a license, no phone-home. Apache-2.0, offline-verifiable, *necessary-not-sufficient*. The interop demand is a regulatory mandate (Art. 14), not a market for trading objects.

## What to bring to the WGs

Engage **RATS** (the attest profile) and **SCITT** (the statement/transparency profile) **separately, peer-to-peer, with running code** — the same motion as the WIMSE engagement. A short profile + conformance vectors, not a `draft-cosa-everything`. Scrub all "object physics / lineage / decay" language into RATS/SCITT/Art.14 vocabulary first.

> Necessary, not sufficient: a receipt proves a named human authorized the exact action; it does not prove the decision was wise or lawful. This is engineering/standards material, not legal advice.
