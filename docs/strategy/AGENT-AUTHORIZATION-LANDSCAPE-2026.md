<!-- SPDX-License-Identifier: Apache-2.0 -->
# The agent-authorization / receipt landscape — June 2026 deep survey

A consolidated map of every effort building "a signed receipt about an agent action,"
across IETF, OAuth/identity, RATS/COSE/SCITT, academia, industry, and regulation — and
where EMILIA Protocol's defensible core is. Sourced from a six-stream research sweep
(2026-06-22). The striking finding is how *consistent* the gap is across all six.

## 1. The middle core — what the whole field has converged on
Independently, ~40+ IETF drafts and a dozen+ academic papers converge on the **same
evidence substrate**:
- **JCS / RFC 8785 canonicalization** (near-universal; the only widely-shared primitive),
- **SHA-256 action/context digest**,
- **Ed25519 and/or ES256** signature (PQ — ML-DSA-65 — now appearing),
- **anti-replay / freshness** (nonce+expiry, RFC 3161 trusted time, or seq/replay-cache),
- **fail-closed** by default,
- a **chain/log** (linear `prev_hash` and/or monotonic scope-narrowing).

EP already speaks this substrate exactly. **The substrate is not the differentiator —
everyone has it.** The differentiation is *what the receipt attests* and *how it composes*.

## 2. The layer map — who does what
The field splits cleanly into five layers. Each is getting crowded except one.

| Layer | Representative efforts | Maturity |
|---|---|---|
| **Identity** (who is the agent / NHI) | klrc-aiagent-auth (OpenAI/Okta/AWS/Ping/Zscaler), WIMSE/SPIFFE, Sharif, DID+VC papers, Entra Agent ID, Okta/SailPoint/CyberArk | Crowded, well-funded |
| **Delegation** (agent authorized to act for principal) | Nelson DRP, OAuth Token-Exchange/Identity-Chaining, MIT "Authenticated Delegation", DAAP, Helixar, AATs | Crowded |
| **Policy permit** (machine policy allows the effect) | Lee permit-receipts, Farley ACTA, AgentROA, Munoz, Krausz | Crowded |
| **Transparency** (logged, append-only) | SCITT (+SCRAPI, COSE Receipts), Sigstore/Rekor, CT-style Merkle logs, GoDaddy ANS production log | Mature substrate (CBOR/COSE) |
| **Human authorization** (a *named, accountable human* approved *this exact action*) | **EP (receipts + quorum)**, Nelson DRP (binds a key, not an identity), Williams intent-token, Chang, Veridom OMP, Anokhin ATA (human-vs-AI flag) | **Thin, contested, mostly unfilled** |

## 3. The real gaps (ranked) — and EP's claim on each
**Gap A — The human-authorization evidence artifact itself.** Across ~25 industry efforts
and every standard, **almost no one** emits *(authenticated named human) + (exact action) +
(timestamp), signed so an unrelated third party verifies it offline without trusting the
originating vendor.* Three failure modes everyone falls into: (1) no human binding (signer is
a device/wallet/vendor key); (2) no exact-action binding (scope/identity token, not
tool+args); (3) not portable/offline (a mutable row in the vendor's DB). EP does all three.
*EP's edge within the few peers:* the **identity-binding profile** (real human, not just a raw
key — DRP and peers bind only a public key) and **conformance + formal verification**.

**Gap B — Composition.** Confirmed by every stream: 40+ receipts, academic papers
hand-rolling 4–5-primitive "composite proofs," but **no shared composition standard** for the
JSON/JCS receipt cluster. EAT detached-bundles (CBOR) + SCITT exist but nothing bridges the
JSON world to them. → **EP-AEC (Authorization Evidence Chain) is aimed exactly here and is
written but NOT YET FILED.** Filing it claims the single most-validated open slot.

**Gap C — Crypto-bound human oversight *inside the compliance receipts.*** ACTA / ASQAV /
AgentROA — the compliance-profile drafts regulators will actually cite — treat human oversight
as *procedural*, not signature-bound. EP binds it but isn't the compliance profile.
→ **Publish EP's human-authorization as an embeddable claim/overlay** those drafts can carry.
Adoption by inclusion, not displacement.

**Gap D — Multi-party / quorum human authorization.** Only **EP-QUORUM** treats M-of-N
distinct-human approval (the two-person rule) as a first-class, chainable primitive. Largely
unclaimed elsewhere.

**Gap E — Long-term, crypto-agile evidence-record renewal.** Regulators mandate multi-year
retention (DORA 5y, HIPAA 6y, SEC 17a-4) but only EP's **EP-EVIDENCE-RECORD** concept (RFC
4998 ERS-style hash renewal, sha256→sha384) addresses algorithm aging of stored receipts.
Written, **not filed**. Unowned slot.

## 4. The demand side — a regulatory/insurance vacuum, stated explicitly
Every framework surveyed **demands** verifiable human authorization and **specifies no
format**:
- **EU AI Act Arts. 12/14/19** — oversight + override + automatic logging + ≥6-month
  retention (binding); format unspecified.
- **NIST NCCoE (Feb 2026)** literally poses as *open questions*: "how can an agent prove its
  authority to perform a specific action," "bind agent identity with human identity," "non-
  repudiation… binding back to human authorization in a tamper-proof, verifiable manner."
- **SOX/COSO, 2 CFR 200, GAGAS** — require authorization + segregation of duties; evidence is
  ad-hoc (logs, e-sigs, screenshots).
- **Cyber/crime insurance** — dual-authorization + out-of-band callback + MFA are *conditions
  precedent*; claims are denied / policies rescinded when unproven (Travelers v. ICS); **AB 316
  (Jan 2026)** pins liability on the deployer; deepfakes now defeat the callback control
  itself. Proof is reconstructed forensically — **there is no machine-checkable artifact.**

This is the sharpest point in the whole survey: **bodies are publicly *asking for EP's
artifact*** (NIST NCCoE; the OAuth-WG audit-BOF thread, where a participant asked for "a
receipt/evidence format that binds to action payloads independently of whether the downstream
resource speaks OAuth"). The demand is named and unmet.

## 5. EP's defensible core (the "future")
EP should own **the human-authorization receipt as the universal, composable,
offline-verifiable evidence artifact every other layer plugs into and every
auditor/insurer/regulator can rely on** — not "another receipt." Unique assets, none of which
a competitor currently combines:
1. The **human primitive + EP-QUORUM** (multi-party, distinct-human).
2. **Self-contained offline verification** (embedded Merkle proof; no mandatory external log).
3. **Three interoperable implementations + cross-language conformance vectors + machine-checked
   TLA+/Alloy** — *no other receipt draft ships this.*
4. The **identity-binding profile** (binds to a real named human, closing the gap DRP leaves).
5. The **composition layer (AEC)** that turns rivals into legs of one chain.

## 6. Corrections this survey forced (accuracy)
- **draft-schrock-ep-authorization-evidence-chain is NOT on datatracker** — written in-repo,
  not filed. Same for EP-EVIDENCE-RECORD. (Both should be filed; both claim open slots.)
- **The 30 June joint Dispatch/SecDispatch interim** has six scheduled talks (TTTPS, AIIP,
  SDLP, CIRP, DAN, CRP). **None of EP's drafts — nor DRP, nor the receipts cluster — are
  scheduled.** EP is not presenting; engagement is via the list / AOB.
- The live forum for the receipt gap is the **agent2agent AUDIT BOF charter thread**
  (Courtney/Kühlewind/Birkholz). Kühlewind scoped *delegation chains* out — leaving the
  *receipt/evidence* gap open and unowned.
- **draft-klrc-aiagent-auth** (OpenAI/Okta/AWS/Ping/Zscaler/Defakto) is the heavyweight, but
  it's an **authN/identity** layer — complementary, not a receipt competitor.
- Credible architecture anchors to align EP vocabulary with: **Kühlewind** (audit-architecture)
  and **Birkholz** (verifiable-agent-conversations; RATS chair).

## 7. Recommended moves (priority order)
1. **File EP-AEC** (Gap B — the most-validated open slot) — already submission-ready.
2. **File EP-EVIDENCE-RECORD** (Gap E — unowned).
3. **Publish the embeddable human-authorization claim** (Gap C — wedge into ACTA/ASQAV).
4. **Engage the AUDIT BOF thread**; align vocabulary to Kühlewind/Birkholz; offer the survey
   matrix + the AEC as the composition answer.
5. **Respond to the NIST NCCoE concept paper / CAISI** — they are asking EP's exact question.
6. **Lead GTM with the insurance/audit forcing function** (proof-of-authorization that
   insurers reconstruct ad-hoc today) — this is also the fastest path to a reliance event.
7. Keep differentiating on **quorum + offline + conformance/formal rigor + identity binding.**

*Method note: synthesized from a six-stream parallel research sweep on 2026-06-22; several
arXiv IDs are future-dated in-index and a few primary pages were paywalled/blocked (flagged in
the raw findings). Treat draft version numbers as of that date.*
