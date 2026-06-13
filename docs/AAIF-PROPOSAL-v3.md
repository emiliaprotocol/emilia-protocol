# EMILIA Protocol - AAIF Proposal for Authorization Receipts

**Version:** 3.2  
**Date:** June 2026  
**Author:** Iman Schrock, Protocol Author & CEO  
**License:** Apache 2.0  
**Repository:** github.com/emiliaprotocol/emilia-protocol  
**Internet-Draft:** [draft-schrock-ep-authorization-receipts](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/) (-01)  
**Packages:** [`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify) · [`@emilia-protocol/issue`](https://www.npmjs.com/package/@emilia-protocol/issue)  
**Site:** [emiliaprotocol.ai](https://www.emiliaprotocol.ai) · [essays](https://www.emiliaprotocol.ai/essays) · [verify a receipt](https://www.emiliaprotocol.ai/verify)  
**Target stage:** Growth (with an honest maturity statement below — we are seeking a Technical Committee sponsor first)

---

## One Sentence

**EMILIA Protocol is an open standard and Apache-2.0 reference implementation for authorization receipts: named-human, device-bound signoff over exact irreversible agent actions, verifiable offline by anyone.**

---

## Why This Matters Now

AI systems are moving from recommendation to execution. Agents deploy code, move money, change vendor bank details, modify infrastructure, and act through credentials that used to belong only to humans.

Most of today's governance stack answers the decision-time question:

> May this action happen?

That is important, but it is not enough. The harder question comes afterward:

> Who can prove what was authorized, by whom, under which policy, before the action ran?

Decision logs are testimony. Receipts are evidence.

A decision log is what the operator says happened, stored in infrastructure the operator controls. An authorization receipt is a named human's user-verified signature over the exact action hash, recorded before execution, and verifiable later without trusting EMILIA, the original operator, or any SaaS database.

This matters for users, auditors, regulators, and AI providers. When an agent causes harm, blame flows to the most legible actor: often the model or provider, even when the real decision was made by a human inside a deployment. The model becomes the crumple zone. A receipt makes the right party legible: either a named human approved the exact action, or the absence of a receipt proves the gated control was bypassed.

EMILIA's thesis is simple:

> The future of trust is not another score. It is portable evidence for irreversible actions.

---

## What Changed Since the April Draft

The earlier AAIF v3 draft described EP as a broad pre-action authorization stack. Since then, the project has shipped the more precise standardization surface: authorization receipts.

New artifacts now in the repository:

| Artifact | Why it matters |
|---|---|
| `docs/essays/why-authorization-is-not-proof.md` | Defines the core distinction: authorization decisions are not durable proof unless they produce a portable evidence artifact. |
| `docs/essays/the-model-is-the-crumple-zone.md` | Frames receipts as protection in both directions: humans from agents, and agents/providers from unprovable human decisions. |
| `docs/RECEIPT-CLAIMS.md` | States exactly what an `EP-RECEIPT-v1` proves and does not prove, including presentation, coercion, identity, and policy limits. |
| `packages/issue/` | Adds local receipt issuance: "issue locally, verify anywhere," with zero runtime dependencies, a CLI (`ep-issue`), and PIP-007 initiator-attestation support. |
| `packages/verify/` | Provides the offline verifier for receipt validation without an EMILIA API call. |
| `docs/conformance/FEDERATION-PROOF.md` | Documents live two-operator cross-verification across separately deployed EMILIA-operated nodes, with an honest note that the independent-third-party operator milestone remains open. |
| `formal/PROOF_STATUS.md` | Adds the PIP-006 federation Alloy model: seven safety assertions verified on 2026-06-11, alongside 26 TLA+ properties and 15 `ep_relations` Alloy assertions. |
| `docs/positioning/DIFFERENTIATION.md` | Maps EP against DRP, AgentOAuth, CHEQ, Sello, HumanLayer, Permit, Okta, Sigstore, AuthZEN, OPA, and Cerbos. |
| `docs/pilots/GOVGUARD-PILOT-OFFER.md` | Packages the first adoption wedge: a 60-day observe-mode GovGuard pilot for high-risk public-sector workflows. |

The proposal below reflects that newer center: AAIF should evaluate EP as a candidate open receipt profile for irreversible AI-agent actions.

---

## The Standardization Surface

### Authorization Receipt (`EP-RECEIPT-v1`)

An authorization receipt is a durable evidence artifact that binds:

- one exact action and its parameters;
- one policy reference and validity window;
- one or more named approvers;
- user-verified signatures over the canonical authorization context;
- separation-of-duties and approval-threshold checks;
- append-only log inclusion and checkpoint proof.

The receipt can be verified offline with only the receipt, public approver key material, and a log checkpoint. No EMILIA account, API key, or live operator is required.

### Core Verification Claim

A verified receipt proves, narrowly and checkably, that:

- a specific enrolled key signed this exact action;
- the key was bound to the stated approver under the stated policy before execution;
- Class-A signatures came from a device-bound key with user verification;
- the authorization was consumed at most once;
- separation of duties held within the modeled policy;
- the receipt was included in an append-only log;
- all of the above remains verifiable offline.

### Explicit Non-Claims

EP does not claim a receipt proves:

- the decision was wise, lawful, or good;
- the policy was adequate;
- the approver was not coerced;
- the signing UI rendered the action honestly;
- a stronger real-world identity proof than the key-to-approver enrollment provides;
- anything outside the model or verifier's stated scope.

This precision is intentional. The fastest way to lose trust in trust infrastructure is to claim more than the cryptography delivers.

---

## Technical Maturity

EP is no longer only a proposal. It is a working open-source protocol package with formal models, verifier implementations, conformance artifacts, and local issuance.

| Area | Current state |
|---|---|
| License | Apache-2.0 |
| Receipt format | `EP-RECEIPT-v1`, versioned and offline-verifiable |
| Internet-Draft | `draft-schrock-ep-authorization-receipts-01` |
| Offline verifier | `@emilia-protocol/verify`, with JavaScript, Python, and Go verification work in-repo |
| Local issuer | `@emilia-protocol/issue` 0.2.0, `ep-issue`, zero runtime dependencies |
| Issuer tests | 16 Node tests covering verifier round-trip, dual approval, anchoring, tamper rejection, wrong-key rejection, forged checkpoint rejection, fail-closed log-key handling, Class-A refusal for software signers, CLI keygen/issue/demo, and PIP-007 attestation validation/fail-closed behavior |
| Red-team cases | 85 adversarial cases in `docs/conformance/RED_TEAM_CASES.md` |
| Formal verification | 26 TLA+ properties verified by TLC 2.19, 413,137 states generated, 45,342 distinct states, 0 errors |
| Relational model | 15 `ep_relations.als` Alloy assertions verified |
| Federation model | 7 `ep_federation.als` PIP-006 assertions verified on 2026-06-11 |
| Federation proof | Two separately deployed EMILIA-operated operators cross-verify live through PIP-006 discovery surfaces |
| Compliance mappings | NIST AI RMF and EU AI Act mappings in `docs/compliance/` |
| Pilot wedge | GovGuard 60-day observe-mode pilot package for public-sector workflows |

Honest limitation: the federation proof demonstrates the mechanism across separate deployments, but both operators are still operated by EMILIA. The next standardization milestone is an independently operated node that issues or verifies receipts through the same surfaces.

---

## Relationship to Adjacent Work

EP is not trying to claim an empty category. Several efforts are converging on the same problem from different layers, which is good for standards.

| Effort | Relationship |
|---|---|
| DRP (`draft-nelson-agent-delegation-receipts`) | Sibling receipt profile. DRP covers upstream delegation from a user to an operator; EP covers downstream authorization of an exact organizational action. The two compose. |
| AgentOAuth | Strong OAuth-native delegation and verifier approval flow. EP provides the action-bound, offline-verifiable evidence artifact. |
| CHEQ | Human confirmation channel for agent actions. EP is the signed receipt produced by the confirmation. |
| Sello / Notarized Agents | Receiver-attested, post-hoc receipts. EP proves pre-execution authorization; receiver attestation proves what happened afterward. |
| HumanLayer / gotoHuman / Permit.io | Approval workflows and audit trails. EP makes the approval portable, cryptographic, and third-party-verifiable. |
| Okta / CIBA | Identity and approval rails. EP is the durable evidence object those rails can ask a human to sign. |
| Sigstore | Artifact provenance and transparency log. Potential anchor or complement, not a substitute for human authorization of actions. |
| OpenID AuthZEN / OPA / Cerbos | Decision-time authorization. EP answers the after-the-fact evidence question their logs do not answer by themselves. |

The positioning is convergence, not replacement: EP's distinct contribution is an open authorization receipt that survives vendor turnover, acquisition, SaaS sunset, and operator non-cooperation.

---

## Maturity, Honestly — Against the Growth-Stage Criteria

AAIF's lifecycle policy sets a high bar for Growth entry, and EP does not pretend to clear all of it today. Stating the gaps plainly is part of the protocol's discipline:

| Growth criterion | EP today | Plan |
|---|---|---|
| Technical Committee sponsor | **Not yet** — this proposal doubles as the request for one | Working-group participation first; sponsor before formal vote |
| Diverse maintainership | Single organization (EMILIA Protocol, Inc.); one protocol author | Conformance suite is designed for multi-implementer governance; recruiting 2-3 external conformance maintainers is the named next step |
| Production use at scale | Not yet — a 60-day government observe-mode pilot is the active wedge | First pilot converts to enforce-mode receipts on one real disbursement workflow |
| Ongoing flow of commits | Yes — daily commits, 13 CI workflows, 3,700+ automated tests | Sustained |
| Open governance | GOVERNANCE.md already states intent to transition to neutral stewardship under AAIF or equivalent; PIP process with core freeze | Formalize under foundation processes on acceptance |

If the Technical Committee judges this proposal early, the productive outcome is still concrete: a named sponsor conversation, working-group participation, and a re-submission once the pilot supplies production evidence. EP would rather be early and honest than padded.

---

## 6-12 Month Roadmap

| Window | Milestone |
|---|---|
| Q3 2026 | secdispatch outcome for `draft-schrock-ep-authorization-receipts` (cross-draft survey with PSEA/DRP/ScopeBlind already on-list); first government observe-mode pilot live on a county payment-integrity workflow; first external party issuing receipts with their own keys via `@emilia-protocol/issue` |
| Q4 2026 | First **independently operated** PIP-006 node (the open federation milestone); conformance suite v1 freeze; 2+ external conformance maintainers; pilot conversion from observe to enforce mode |
| Q1-Q2 2027 | Multi-organization maintainership; EP Core stability review under foundation governance; second regulated pilot; IETF working-group-forming conversation if dispatch supports it |

Each milestone is concrete and checkable; none depends on undisclosed work.

---

## What EP Proposes to AAIF

### 1. Review `EP-RECEIPT-v1` as a candidate authorization receipt profile for AI-agent actions

AAIF should evaluate whether the receipt object, verification algorithm, and security considerations are a suitable interoperable baseline for irreversible agent actions.

### 2. Convene a technical review on claims, limits, and conformance

The review should focus on the exact evidentiary claims in `docs/RECEIPT-CLAIMS.md`, the offline verifier, the conformance suite, and the security considerations around rendering, coercion, identity, and policy adequacy.

### 3. Help identify an independent operator or relying party

The most valuable next milestone is not another EMILIA-run demo. It is an AAIF member, partner, lab, or regulated organization standing up the PIP-006 surfaces or independently verifying externally issued receipts.

### 4. Provide feedback on PIP-007 initiator escalation attestation

PIP-007 records the initiator's stated reason for escalating to a human, while preserving the rule that the initiator is identified but never trusted. This could become an important missing link for agent accountability: not only who approved the action, but why the agent said a human was needed.

### 5. Connect EP to regulated pilot conversations where appropriate

GovGuard is packaged for observe-mode deployment: 60 days, one high-risk workflow, receipts recorded without blocking production. That creates an "accountability-surface map" before enforcement begins.

---

## Why AAIF Is the Right Forum

Authorization receipts sit between model providers, deployers, auditors, governments, and standards bodies. No single vendor should own the artifact that later proves whether a consequential AI-agent action was authorized.

AAIF can help turn this from a repository into shared infrastructure by asking the right cross-stakeholder questions:

- What minimum receipt fields should every consequential agent action carry?
- What must be verifiable offline?
- What should a receipt never claim?
- How should human approval channels, OAuth flows, delegation receipts, and receiver attestations compose?
- What independent conformance evidence is enough for adoption?
- Which regulated workflows should be piloted first?

EP brings a concrete answer to evaluate, not a white paper alone.

---

## Review Packet

Recommended review path (all paths relative to [github.com/emiliaprotocol/emilia-protocol](https://github.com/emiliaprotocol/emilia-protocol)):

1. `docs/RECEIPT-CLAIMS.md` - exact proof claims and non-claims.
2. [`draft-schrock-ep-authorization-receipts`](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/) - protocol specification (also `standards/` in-repo).
3. `packages/verify/README.md` - offline verification package ([npm](https://www.npmjs.com/package/@emilia-protocol/verify)).
4. `packages/issue/README.md` - local issuance package and CLI ([npm](https://www.npmjs.com/package/@emilia-protocol/issue)).
5. `docs/conformance/FEDERATION-PROOF.md` - two-operator federation proof and open limitation.
6. `formal/PROOF_STATUS.md` - formal verification status.
7. `docs/positioning/DIFFERENTIATION.md` - adjacent-work map.
8. [Why Authorization Is Not Proof](https://www.emiliaprotocol.ai/essays/why-authorization-is-not-proof) - narrative framing.
9. [The Model Is the Crumple Zone](https://www.emiliaprotocol.ai/essays/the-model-is-the-crumple-zone) - accountability framing.
10. `docs/pilots/GOVGUARD-PILOT-OFFER.md` - first regulated pilot package.

Sixty-second hands-on check: `npx @emilia-protocol/issue demo` issues a receipt locally and verifies it 7/7 offline with the published verifier — no EMILIA account or backend involved.

---

## Ask

AAIF should evaluate EP against this question:

> When an AI system takes a consequential action, what open, interoperable, offline-verifiable artifact proves that the action was authorized?

EP's answer is the authorization receipt.

We request:

1. AAIF technical review of `EP-RECEIPT-v1`.
2. Feedback on receipt claims, non-claims, conformance, and PIP-006 federation.
3. Help identifying one independent operator or relying party to close the next federation milestone.
4. Feedback on PIP-007 initiator escalation attestation.
5. Introductions to regulated pilot contexts where observe-mode receipts can produce immediate learning without blocking production.

---

## Contact

Iman Schrock  
Protocol Author & CEO  
team@emiliaprotocol.ai  
github.com/emiliaprotocol/emilia-protocol · emiliaprotocol.ai
