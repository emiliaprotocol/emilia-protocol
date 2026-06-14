<!-- SPDX-License-Identifier: Apache-2.0 -->

# EP Commit ⇄ SCITT — Binding / Applicability Sketch

**Status:** Experimental, non-normative. This is an **applicability/binding sketch**, not an Internet-Draft and not a chartered deliverable. It expresses the EMILIA Commit (seal / anchor) layer in terms of the primitives defined by the IETF **SCITT** Working Group. It claims no SCITT conformance that the code does not already demonstrate, and it claims no IETF adoption. Companion to `EP-ENFORCEMENT-POINT-SPEC.md` (see §4, "Composition with SCITT") and the EP authorization-receipt draft (`standards/draft-schrock-ep-authorization-receipts-01.md`).

This document **composes over** SCITT; it does not define a new transparency standard. EMILIA does not own a transparency log format, a Verifiable Data Structure, or a notarization standard. SCITT — **Supply Chain Integrity, Transparency, and Trust**, an active IETF Working Group in the Security Area — already defines those primitives, reusing COSE (RFC 9052) and CWT Claims (RFC 9597) rather than inventing new envelopes. The contribution here is narrow and honest: it shows how an EP Commit seal and its anchor proof **map onto** SCITT's Signed Statement, Transparency Service, and Receipt, what part of that mapping is already true in the EMILIA codebase today, and what a SCITT integration would *add*.

The framing rule for the whole document: **EP Commit is expressible as SCITT primitives.** It is not currently SCITT, and EP does not assert that it is. Where the code does not yet implement a SCITT-shaped path, that gap is stated plainly rather than glossed.

---

## 1. Why this is reuse, not a new standard

SCITT standardizes how a verifiable claim about an artifact is signed, registered into an append-only transparent log, and later checked offline by a relying party. That is precisely the shape of the problem an EP Commit seal already solves in EMILIA's own way: a pre-action authorization is signed (Ed25519 over canonical JSON), then a corresponding post-action receipt is batched into a Merkle tree and (optionally) anchored on-chain.

Rather than promote the EMILIA-specific mechanism to a "standard," this sketch lines it up against the primitives SCITT already defines, so that a SCITT-aware verifier — or a future SCITT Transparency Service — could consume EP artifacts without EMILIA having to publish a competing transparency format. The EP-EP spec already records this intent in its composition table: the transparency-anchor layer **reuses** "SCITT Signed Statement + Merkle-log inclusion Receipt" and **adds** nothing to it; Commit seals register as Signed Statements.

The only normative SCITT sources this sketch leans on:

- **`draft-ietf-scitt-architecture`** — *"An Architecture for Trustworthy and Transparent Digital Supply Chains."* The source for the three primitives below. Verified current revision **`-22`** (Oct 2025) on the IETF Datatracker as of writing; SCITT drafts revise frequently, so a binding doc MUST re-check the revision and bind to registered IANA values / draft section numbers at the moment of publication, not to label integers quoted in any snapshot.
- **`draft-ietf-scitt-scrapi`** — *"SCITT Reference APIs"* (verified current revision **`-09`**, Apr 2026). Defines the HTTP operations to register Signed Statements and retrieve Receipts.
- **`draft-ietf-cose-merkle-tree-proofs`** — *"COSE Receipts"* (verified current revision **`-18`**, in the RFC Editor queue). Defines the inclusion-proof machinery and registers `RFC9162_SHA256` (a SHA-256 binary Merkle tree, built on RFC 9162 Certificate Transparency 2.0) as a Verifiable Data Structure.

A note on precision, as the house rules require: the exact COSE header labels (e.g. the inclusion-proof label, the VDS-identifier label) have shifted across architecture revisions. A real binding document must cite the registered values at write time. This sketch deliberately cites by **draft name and primitive name**, not by label integer.

---

## 2. The three SCITT primitives, briefly

| SCITT primitive | Definition (per `draft-ietf-scitt-architecture`) | Encoding |
|---|---|---|
| **Signed Statement** | "An identifiable and non-repudiable Statement about an Artifact signed by an Issuer." | A `COSE_Sign1` message (RFC 9052). The protected header carries `CWT_Claims` (RFC 9597), which MUST include the Issuer claim `iss` and Subject claim `sub`. |
| **Transparency Service (TS)** | "An entity that maintains and extends the Verifiable Data Structure and endorses its state." | An append-only, Merkle-verifiable log with three required properties: **append-only**, **non-equivocation**, **replayability**. Registration is "akin to a notarization procedure." |
| **Receipt** | "A cryptographic proof that a Signed Statement is included in the Verifiable Data Structure." | A `COSE_Sign1` signed by the **Transparency Service**, with the Merkle inclusion proof in its unprotected header. |

A derived object — a **Transparent Statement** = a Signed Statement with one or more Receipts embedded — is what a relying party ultimately verifies offline. SCITT is explicitly a generalization of Certificate Transparency: Issuers ↔ CAs, Signed Statements ↔ X.509 certs, Transparency Services ↔ CT logs, Receipts ↔ SCTs.

---

## 3. Mapping table: EP Commit layer ⇄ SCITT

The alignment is strong on all three rows. The annotations flag exactly where a binding must be precise and where the EMILIA codebase does **not** yet implement the SCITT-shaped path.

| EMILIA Protocol (EP) | SCITT primitive | Fit and binding notes |
|---|---|---|
| **EP authorization receipt** (wire tag `EP-RECEIPT-v1`) — the signed, post-action artifact; and the EP **Commit seal** (the Ed25519 signature over the canonical Commit payload) | **Signed Statement** (`COSE_Sign1`, RFC 9052) | Clean conceptual fit. Both EP artifacts are signed, non-repudiable assertions over a specific subject. To bind: encode the EP assertion as the COSE payload and populate `CWT_Claims` with `iss` (the EP operator / authorizing party) and `sub` (the action or Commit being attested). **Today** the EP signature is Ed25519 over canonical JSON (sorted keys), *not* a `COSE_Sign1` with CWT claims — so this row is a re-encoding, not a drop-in. The EP signer becomes the SCITT **Issuer**; key authority stays pinned to the EP trusted key registry by `kid`, not to any inline key in the statement. |
| **EP Commit anchor / Merkle log** — the receipt Merkle tree (`buildMerkleTree`) and its optional Base L2 anchor | **Transparency Service** (append-only Verifiable Data Structure) | Clean fit *provided* the EP log demonstrably satisfies the TS triad: append-only, non-equivocation, replayability. EMILIA's receipt tree is a SHA-256 binary Merkle tree, which maps directly to VDS id `RFC9162_SHA256`. A binding doc must state which VDS profile EP claims. **Important asymmetry:** the EP Merkle log today contains **receipts** (post-action), not **Commits** (pre-action). Commits are not in any tree; they are signed DB records only. |
| **EP anchor / inclusion proof** — `merkle_proof` + `merkle_root` carried on an anchored receipt | **Receipt** (`COSE_Sign1` signed by the TS, inclusion proof in unprotected header) | Clean fit. Binding requirement: re-express the EP inclusion proof as a COSE Receipt per `draft-ietf-cose-merkle-tree-proofs`, signed by the TS (the EP anchor authority), and the proof MUST pin the **tree-size / root** it was generated against (the RFC 9162 rule). **Today** the EP proof is a JSON array of `{hash, position}` steps verified by re-deriving the root (`verifyMerkleProof`), not a COSE-wrapped, TS-signed Receipt. |

**Granularity note.** If EP delivers "authorization receipt + anchor proof" to a relying party as one bundle, that bundle maps to a SCITT **Transparent Statement**; the two EP components map individually to **Signed Statement** and **Receipt** as in the table above. A binding doc should state which granularity it operates at.

---

## 4. What exists today vs what a SCITT integration adds

This section is grounded in the Commit/anchor recon and is deliberately conservative. The EMILIA codebase has SCITT-*shaped* behavior for receipts and a thinner, signature-only story for Commits.

### Exists today (real in code)

- **Commit seal (real).** Ed25519 signature over the canonical Commit payload (sorted keys), covering `commit_id`, `entity_id`, `action_type`, `decision`, `nonce`, `expires_at`, `created_at`, and the rest of the record. Signatures verify against a **trusted key registry keyed by `kid`** — *not* against `commit.public_key`, which is metadata only. (`lib/commit.js`.)
- **Commit lifecycle (real).** A state machine `active → (fulfilled | revoked | expired)` with immutable terminal states, globally unique `nonce` (DB `UNIQUE` constraint + hot-path cache) for replay protection, and auto-expiry. (`lib/commit.js`, `supabase/migrations/029_commits.sql`.)
- **Commit ⇄ receipt binding (real).** A Commit is "sealed" to a post-action receipt via `receipt_id`; `bindReceiptToCommit()` + `fulfillCommit()` transition the Commit to `fulfilled`. The WYSIWYS rule ("What You See Is What You Signed") ensures the receipt's `action_hash = sha256(canonicalize(canonical_action))` is bound to what was signed. (`lib/commit.js`, `EP-ENFORCEMENT-POINT-SPEC.md` §4.)
- **Receipt Merkle batching (real).** `EP-RECEIPT-v1` documents are hashed and batched into a Merkle tree; per-leaf inclusion proofs are generated and verified by re-deriving the root with order-independent `hashPair`. (`lib/blockchain.js`.)
- **Optional on-chain anchor (real, optional).** The Merkle root is published to Base L2 as a data-only transaction (`EP:v1:{batchId}:{merkleRoot}`). Mandatory in production (`EP_WALLET_PRIVATE_KEY` MUST be set), optional in dev (logs `skipped_onchain=true`). (`lib/blockchain.js`.)
- **Offline receipt verification (real).** `@emilia-protocol/verify` checks the Ed25519 signature and re-derives the Merkle root in Web Crypto, no server round-trip. (`lib/verify-web.js`.)

### What a SCITT integration would add (not in code today)

- **Commit-as-Signed-Statement registration.** `EP-ENFORCEMENT-POINT-SPEC.md` §4 says a Commit seal **MAY** be registered as a SCITT Signed Statement, and the returned Merkle-inclusion Receipt **would** become the Commit's transparency anchor. The registration path does not exist in the codebase. There is no `POST /scitt/register-statement`, no `commit.scitt_anchor_receipt_id`, no COSE encoding.
- **Commits in a Verifiable Data Structure.** Today only receipts are Merkle-batched. Commits are not in any tree, so a Commit currently has **no chain of custody** to an anchored root. A SCITT integration would either register each Commit separately as a Signed Statement (yielding its own Receipt) or add a Commit-side log. A Commit cannot inherit a receipt's proof, because it is not in the receipt batch.
- **COSE / CWT envelope.** EP artifacts are Ed25519-over-canonical-JSON today, not `COSE_Sign1` with `CWT_Claims` (`iss`, `sub`). Full SCITT parity requires the COSE re-encoding.
- **TS-signed Receipts.** EP inclusion proofs are self-verifying JSON, not COSE Receipts signed by a Transparency Service. A SCITT integration adds the TS signature and the tree-size pinning.
- **Offline Commit verification.** Receipts verify offline because the issuer key material is discoverable. Commit verification today requires a DB round-trip against the trusted registry. Offline Commit parity needs either an embedded/discoverable key (e.g. a `kid` + `/.well-known/ep-keys.json` endpoint) or SCITT-side key pinning.
- **An explicit append-only event log.** Commit status transitions are `UPDATE`s on the `commits` row, not append-only events. SCITT-style transparency favors one immutable row per state transition; EMILIA does not have this for Commits today.

Honest summary, by layer: the **seal layer** is real (signed, verifiable against the registry) but **not anchored** to any tree or chain. The **binding layer** is real. The **transparency-anchor layer** is real for receipts and **absent for Commits**. In SCITT terms, EMILIA's receipts are substantially SCITT-shaped (Merkle tree, optional chain anchor, offline verification); EMILIA's Commits are signed and verifiable but have no transparent registration, no Merkle inclusion, and no anchor. The SCITT integration is what closes the Commit-side gap — and it is reuse, not new standardization.

---

## 5. Verification walkthrough — relying party verifies an EP Commit via a SCITT Receipt, offline

This is the **target** flow once the SCITT integration exists. It is written as a walkthrough, not as a claim that the code does this today. Steps that are already real for the receipt path are marked; steps that the SCITT integration would add are marked.

Assume a Commit seal was registered as a SCITT Signed Statement and the Transparency Service returned a Receipt (an inclusion proof against tree-size *N*), delivered to the relying party as a Transparent Statement (Signed Statement + embedded Receipt). The relying party holds only that artifact, the issuer/TS public key material, and a published log checkpoint — no network access.

1. **Parse the Transparent Statement.** Separate the Signed Statement (the EP Commit seal, re-encoded as `COSE_Sign1`) from the embedded Receipt. *(SCITT integration adds the COSE encoding; the underlying Commit fields are real today.)*
2. **Verify the Issuer signature on the Signed Statement.** Check the `COSE_Sign1` signature over the Commit payload. Confirm `CWT_Claims` carries `iss` (the EP operator) and `sub` (the Commit / action). **Pin the signer to the trusted key registry by `kid` — never trust an inline key.** *(Signature-over-canonical-payload and `kid`-registry pinning are real today in `lib/commit.js`; the COSE/CWT wrapper is added.)*
3. **Recompute the action binding (WYSIWYS).** If a bound receipt is present, recompute `action_hash = sha256(canonicalize(canonical_action))` and confirm it matches the signed claim. Tampering with the action cannot produce a valid signature; a receipt issued for $1 cannot authorize $82,000. *(Real today — `EP-ENFORCEMENT-POINT-SPEC.md` §4, `lib/guard-evidence-receipt.js`.)*
4. **Verify the TS Receipt's inclusion proof.** Re-derive the Merkle root from the leaf hash and the proof steps, in sorted/order-independent pairing, and confirm it equals the root the TS endorsed. The proof is only valid against the **tree root for the tree-size at which it was generated** (RFC 9162) — confirm the proof pins that tree-size. *(Merkle re-derivation is real today via `verifyMerkleProof` / `verifyMerkleAnchor`; the TS signature over the Receipt and the tree-size pinning are added by the SCITT integration.)*
5. **Verify the TS endorsement / checkpoint.** Check the Transparency Service's signature over the Receipt (or over the checkpoint root) against the trusted log key. This is the step that upgrades a self-asserted Merkle proof into a notarized, non-equivocating one. *(Added by the SCITT integration; the on-chain Base L2 anchor is the EMILIA-native analogue that exists today for receipts.)*
6. **Decide.** If steps 2–5 all pass, the relying party has established offline, by mathematics alone: a registry-pinned EP key signed this exact Commit; the bound action matches what was signed; and the Commit is included, at a pinned log position, in an append-only structure the TS endorsed. No EP operator, log, or API was contacted.

What this still does **not** prove (carried from `RECEIPT-CLAIMS.md`): that the decision was wise, that the policy was adequate, that the human was not coerced, or that the signing surface rendered the action faithfully. Transparency proves inclusion and integrity, not correctness of judgment.

---

## 6. Path to IETF

This document is an **applicability / binding sketch**, deliberately and explicitly **not** a new Internet-Draft. It exists to demonstrate that the EMILIA Commit layer is expressible in SCITT terms and to record honestly the delta between today's code and a SCITT-conformant integration.

The order of operations matters and is stated plainly:

1. **First, the EP verifier core dispatches.** The EP authorization-receipt draft (`draft-schrock-ep-authorization-receipts`) and the verifier core are the load-bearing artifacts. Until a shared verifier core is dispatched and stable, a SCITT binding document would be premature — there would be nothing settled to bind.
2. **Then, this sketch could become a SCITT binding document.** If and when the verifier core dispatches, this material is the natural seed for a profile that says: "Here is how an EP Commit seal is encoded as a SCITT Signed Statement, how the EP anchor is expressed as a COSE Receipt, and how a relying party verifies the Transparent Statement." That would be a *binding/profile* document layered on the SCITT primitives — never a competing transparency standard.
3. **No adoption is claimed.** This is not a chartered SCITT deliverable, has not been adopted by any working group, and describes no production deployment, customer, or revenue. The SCITT references here are to public WG drafts; their revisions move, and any future submission must re-verify them.

The throughline, one more time: **EMILIA composes over SCITT.** The transparency standard is SCITT's. EMILIA's contribution is the Commit/seal/binding semantics that map onto it — and a verifier core that, once dispatched, makes such a binding worth writing down for the IETF.

---

## 7. References

- [SCITT-ARCH] IETF SCITT WG, "An Architecture for Trustworthy and Transparent Digital Supply Chains" (`draft-ietf-scitt-architecture`, work in progress; revision `-22` verified at time of writing).
- [SCITT-SCRAPI] IETF SCITT WG, "SCITT Reference APIs" (`draft-ietf-scitt-scrapi`, work in progress; revision `-09` verified at time of writing).
- [COSE-RECEIPTS] IETF COSE WG, "COSE Receipts" (`draft-ietf-cose-merkle-tree-proofs`, in RFC Editor queue; revision `-18` verified at time of writing). Registers `RFC9162_SHA256` as a Verifiable Data Structure.
- [RFC9052] Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and Process".
- [RFC9597] Prorock, M., et al., "CBOR Web Token (CWT) Claims in COSE Headers".
- [RFC9162] Laurie, B., et al., "Certificate Transparency Version 2.0".
- [RFC8785] Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)".
- [EP-EP-SPEC] `docs/EP-ENFORCEMENT-POINT-SPEC.md` — EP Enforcement-Point Profile (see §4 binding rule, §4 SCITT composition).
- [EP-RECEIPT-DRAFT] Schrock, I., "Authorization Receipts for High-Risk Agent Actions" (`standards/draft-schrock-ep-authorization-receipts-01.md`, work in progress).
- [RECEIPT-CLAIMS] `docs/RECEIPT-CLAIMS.md` — "What an Authorization Receipt Proves — and What It Doesn't".
