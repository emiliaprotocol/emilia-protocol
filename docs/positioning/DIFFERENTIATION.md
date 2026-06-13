# EP — How It Differs

**Date:** 2026-06-12
**Audience:** Buyers, auditors, standards reviewers, and anyone comparing EP to an adjacent effort.
**Companion:** For private-sector vendor-payment-fraud competitors (Trustpair, Eftsure, Validis, Onyxia, Creditsafe), see [`docs/strategy/DIFFERENTIATION.md`](../strategy/DIFFERENTIATION.md). This page covers AI-agent and standards-layer efforts.
**Category phrase:** EP is **the open standard for authorization receipts**. The category is not empty — several efforts are converging on it, and that is good for everyone. This page states EP's specific, verifiable position within it.

---

## What EP is, stated in verifiable specifics

An **authorization receipt** is a named human's WebAuthn (Class-A) device signoff over one exact, irreversible action, under a stated policy, *before* the action executes — producing an offline-verifiable artifact (`EP-RECEIPT-v1`). Every claim below maps to a path in this repository:

- **Named-human, device-bound signoff.** The approver's signature is produced by a key held in a platform authenticator or security key and exercised over WebAuthn, with user verification (biometric/PIN) required. The EP operator never holds the key and cannot forge the signature. See the I-D §5.1 (Class A) and `packages/verify/index.js → verifyWebAuthnSignoff`.
- **Fully offline verification, in three independent languages.** JavaScript (`@emilia-protocol/verify`, 1.3.0 on npm), Python (`packages/python-verify`), and Go (`packages/go-verify`) are proven to agree on the canonical adversarial vectors on every push. That is the IETF bar for a standard: multiple independent interoperable implementations.
- **A public conformance suite.** `conformance/` — canonical fixtures plus a cross-language runner; an implementation either reproduces the expected outputs or it does not.
- **A live two-operator federation.** A second operator runs on separate infrastructure, publishing the PIP-006 surfaces; a relying party verifies its receipts live against its own published keys and revocation surface. **Honest scope: that second operator is also operated by EMILIA — it is a separately-deployed node, not an independent third party.** See `docs/conformance/FEDERATION-PROOF.md`.
- **Formal evidence.** 26 machine-checked TLA+ safety properties (`formal/ep_handshake.tla`) and Alloy relational models (`formal/ep_relations.als`, `formal/ep_federation.als`), run in CI. The models prove safety of the state machine; they do not prove anything about deployment topologies they do not model — see the I-D §11.5.
- **Compliance mappings.** NIST AI RMF and EU AI Act Article 14 mappings in `docs/compliance/`.

**The wedge:** *Decision logs are testimony. Receipts are evidence.* A log is what the operator says happened, recorded in a database the operator controls. A receipt is a named human's user-verified signature over the exact action hash, verifiable by anyone, offline, without the operator's cooperation.

**The survivorship claim:** *Audit evidence that survives vendor turnover, acquisition, and SaaS sunset.* A receipt verified in 2026 still verifies in 2033 with only the receipt, the approver's public key material, and a published log checkpoint — even if the issuing operator no longer exists.

---

## How EP relates to adjacent work

One line each. The posture is convergence, not category ownership.

- **DRP (`draft-nelson-agent-delegation-receipts`, IETF -09).** A **sibling profile over a shared verifier core**, not a competitor: DRP binds a *user's* delegation to an *operator's* instructions (upstream consumer delegation, append-only log); EP binds an *organizational approver* to an *exact action* (downstream authorization, separation of duties, m-of-n, offline verification). The two compose — a DRP delegation can be referenced in an EP Action Object's provenance — and convergence is already in motion: DRP is one of the four efforts (PSEA, EP, DRP, ScopeBlind) mapped onto a single verifier-side decision matrix in the three-author cross-draft survey now in front of the IETF secdispatch list.
- **AgentOAuth (`verifier.agentoauth.org`).** OAuth-flavored proof of agent intent plus verifier approval. Strong for the OAuth-native delegation flow; it emits an approval, not an action-bound, offline-verifiable, one-time-consumable receipt. Complementary at the transport layer.
- **CHEQ (`draft-rosenberg-cheq`, OAUTH-WG).** Human confirmation of agent actions, MCP-integrated and interaction-focused. CHEQ can be the channel by which an approver is *reached*; the EP signoff is the evidence artifact they *produce* when they get there.
- **Sello / "Notarized Agents" (arXiv 2606.04193).** Receiver-attested, post-hoc receipts: the receiving service signs what it observed. Complementary — EP proves the action was authorized *before* execution; receiver attestation proves what then actually occurred.
- **HumanLayer / gotoHuman.** Approval-workflow services. Good developer ergonomics; no portable cryptographic proof — the approval lives in the service.
- **Permit.io approval flows.** Platform-internal approvals plus audit. Not portable, not third-party-verifiable outside the platform.
- **Okta "Auth for GenAI" / CIBA.** Approval rails and identity that emit *tokens*, not evidence artifacts. CIBA can transport the approval request; EP is what the approver signs.
- **Sigstore.** Artifact provenance plus a transparency log — not human authorization of actions. A potential *complement*: Rekor could anchor EP checkpoints.
- **OpenID AuthZEN (FINAL, ~March 2026).** A decision-time access-evaluation API. Answers "may this happen?"; produces no evidence artifact. Different layer.
- **OPA / Cerbos decision logs.** Excellent policy engines. Their decision logs are operator-side, unsigned, and non-portable — testimony, not evidence.

---

## The honest summary

EP does not claim the category is empty, that it has no peers, or that its open federation milestone is met by an independent third party (it is not — see `FEDERATION-PROOF.md`). What EP claims is narrow and checkable: it is the open standard for **authorization receipts** — a named human's device-bound signoff over an exact irreversible action, verifiable offline by anyone, in three languages, against a public conformance suite, with formal evidence and compliance mappings behind it. For the buyer who needs audit evidence that outlives the vendor, that is the differentiated answer. For everyone else, the adjacent efforts above are good at what they do.
