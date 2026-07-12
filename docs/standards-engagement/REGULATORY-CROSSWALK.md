# EMILIA Protocol — Regulatory Crosswalk

*How EP maps to the real instruments creating demand for verifiable human authorization.*
*Maintained by EMILIA Protocol, Inc. · this is EP's own analysis of fit, not a claim of endorsement.*

## The convergent requirement

Across jurisdictions and sectors, governing instruments for high-risk and autonomous AI are
converging on one requirement they all state and none of them supply a format for: **evidence that a
named, accountable human authorized a specific consequential action — bound to the exact action,
produced before (or at) execution, one-time, tamper-evident, and verifiable by a third party without
trusting the operator.** EP is the artifact that satisfies that shared requirement; this document is
the crosswalk.

Scope discipline: EP proves authorization and evidence integrity — a **necessary, not sufficient**,
condition. Instrument numbers below are real as of 2026; forward-looking secondary legislation and
sectoral rules are marked **(anticipated)** and are *not* asserted as existing law. EP does not claim
to be named by any regulator today; it claims to be the implementation that meets the stated
requirement.

## European Union

| Instrument (real) | The requirement | EP feature that satisfies it | Status |
|---|---|---|---|
| **AI Act (Reg. (EU) 2024/1689) Art. 14 — Human oversight** | High-risk AI must be effectively overseen by natural persons who can intervene/decide | Named-human (or quorum) device-bound signoff over the exact action; on/in-the-loop via PIP-013 | In force; high-risk obligations phasing in |
| **Art. 12 — Record-keeping / logging** | Automatic, tamper-evident logging of high-risk AI events | EP Trust Receipt + EP-EVIDENCE-RECORD (long-term, crypto-agile) + Merkle anchoring | In force |
| **Art. 17 — Quality management system** | Documented procedures incl. authorization of actions | Receipts as authorization evidence records; RR-1 conformance | In force |
| **Art. 99 — Penalties** | Administrative fines for oversight failures | (Context: the cost of *unprovable* oversight) | In force |
| **CEN-CENELEC JTC 21 harmonized standards** | Presumption-of-conformity standards for Arts. 12/14 | EP positioned as the reference mechanism for the human-signoff + tamper-evident-log clauses | In development |
| **eIDAS 2.0 (Reg. (EU) 2024/1183)** | EU Digital Identity Wallet; qualified trust services incl. **qualified electronic ledgers** | EUDI-wallet keys as Class-A approver keys; receipts anchorable as a qualified electronic ledger record (legal-evidentiary path) | In force; wallet + QEL rollout |

## United States

| Instrument (real) | The requirement | EP feature | Status |
|---|---|---|---|
| **NIST AI RMF 1.0** | Documented, auditable human oversight (GOVERN/MANAGE) | Receipts as the auditable oversight artifact | Published 2023 |
| **NIST CSF 2.0** | Govern/protect functions extended to AI | EP receipts as the "verify human authorization" control evidence | Published 2024 |
| **OMB federal-AI-use guidance** | Human oversight for rights-/safety-impacting agency AI | EP receipts as the oversight evidence for federal high-impact AI | In force (per current memoranda) |
| **DoD Directive 3000.09** | Appropriate levels of human judgment over force | Quorum (two-person rule) + bounded on-the-loop envelopes; see HUMAN_CONTROL_CROSSWALK | In force |
| **FedRAMP AI control overlay** | Authorization evidence for cloud AI agent actions | EP receipt generation/verification in the authorization package | (anticipated) |
| **SEC / CFTC AI rulemaking** | Tamper-evident human-approval records for AI-driven trading/advice | Non-repudiable, one-time receipts bound to the order | (anticipated / emerging) |

## Sectoral

| Instrument (real) | The requirement | EP feature | Status |
|---|---|---|---|
| **FERC Order 2222 + NERC CIP family** | Verifiable records for DER/AI-driven grid dispatch; AI-system controls | **Proof-of-Curtailment (PIP-014) / GRACE**: human-authorized, attested, settlement-grade dispatch evidence | Order 2222 in force; AI-system controls (anticipated) |
| **Basel framework + EBA guidance** | Non-repudiable evidence of human signoff for AI risk-model decisions | Receipts as the signoff evidence | (anticipated / emerging) |
| **FDA AI/ML device guidance** | Human oversight + traceability for high-risk clinical AI | Clinical authorization profile (EP-CLINICAL-AUTHORIZATION-PROFILE) | Guidance issued; profile drafted |
| **ISO/IEC 42001 (AIMS)** + **42006** (auditing bodies) + **23894** (AI risk) | Audit trails + authorization evidence for certified AI management systems | Receipts as the A.8-style automated-decision audit-trail evidence | 42001 published; 42006 recent |

## International

| Instrument (real) | The requirement | EP feature | Status |
|---|---|---|---|
| **China TC260 AI Safety Governance Framework** | Tamper-evident, named-responsible-person authorization for high-risk algorithmic decisions | EP's offline-verifiable, no-operator-dependency receipt (data-sovereignty-friendly) | Framework published (v1.x) |
| **G7 Hiroshima AI Process** | Tamper-evident human-oversight records; mutual recognition | One EP receipt format satisfies cross-border recognition | Code of conduct → evolving |
| **ITU-T SG17 (security)** | Trust frameworks for agent authorization | EP as the base human-authorization layer | (anticipated) |

## Why EP is the fit (not one of several)

The shared requirement has five hard properties; EP is built around all five, and the common
alternatives miss at least one:

- **Offline-verifiable, no trust in the operator** — receipts verify with no live query; database logs,
  CIBA backchannels, and online-revocation models cannot.
- **Named, accountable human** — device-bound (WebAuthn/Class-A) signoff, not an operator-custodied key.
- **Bound to the exact action** — Ed25519 over RFC 8785 (JCS) canonical bytes; e-signature platforms sign documents, not action digests.
- **One-time consumption** — terminal, non-repayable; workflow tools allow replay.
- **Separation of duties** — initiator ≠ approver, enforced cryptographically (quorum), not just by RBAC policy.

## Composition (cede the rest, claim the apex)

EP composes with the identity (WIMSE/SPIFFE, klrc), delegation (DRP, AAP), machine-policy, and
transparency (SCITT/COSE) layers — see `standards/draft-schrock-ep-architecture`. EP supplies the
named-human authorization apex those layers reference but do not produce.

## The standards posture

EP stakes this ground openly: published Apache-2.0 standard, individual IETF Internet-Drafts (receipts, quorum,
enforcement-point, evidence-chain, evidence-record, architecture), three same-team language ports over
17 suites / 192 vectors, a pinned external Rust verifier over its pinned 16-suite/164-vector clean-room bundle plus 359 hostile cases, and formal models with explicit scope. When harmonized standards and implementing acts are written for the
requirements above, the intent is that EP is the obvious, already-running reference — not a proposal.

*See also: `docs/compliance/HUMAN_CONTROL_CROSSWALK.md` (defense/autonomy), `docs/strategy/AGENT-AUTHORIZATION-LANDSCAPE-2026.md` (competitive/IETF field map), `PIPs/PIP-013` (human-oversight), `PIPs/PIP-014` (grid.curtailment).*
