# OpenAI Cybersecurity Grant — Form Answers (as submitted) + Resubmission Notes

**Status:** SUBMITTED 2026-06-13 at a $250,000 ask (credits-weighted).
**Form:** https://openai.com/form/cybersecurity-grant-program/ (rolling review)
**Submitted from:** team@emiliaprotocol.ai

These are the exact field answers as submitted, followed by a **Revision
playbook** the program explicitly invites ("If you refine your idea later on,
feel free to submit the updated proposal in full and mention it's a revision").

---

## Field answers (as submitted)

### Project title
EMILIA Protocol: an open, formally-verified standard that gates every irreversible AI-agent action behind a cryptographic authorization ceremony and emits a portable receipt any defender can verify offline.

### What problem are you trying to solve? (<=200 words)
AI agents are shifting from recommendation to autonomous action — deploying code, moving money, rotating credentials, calling tools with real consequences. Cyber defense's question shifts from "is the model accurate?" to "did this agent have authorization to take this specific irreversible action on behalf of this principal — and can a defender prove it afterward?"

Existing primitives don't answer that. OAuth and API keys prove "this caller has this scope," not "this caller authorized this exact action under this policy"; once a key is exfiltrated or a session hijacked, every downstream action is silently authorized. RBAC/ABAC has no native concept of action-bound consent or replay protection for agent-to-agent delegation. SIEM and audit logs record events after the fact, unstructured, and are produced by the same system whose integrity is in question. Prompt-injection defenses harden the model's reasoning but leave no artifact a third party can check — when an injected agent acts, nothing portable distinguishes an authorized action from a bypass.

There is no open standard for verifiable pre-action authorization in agent systems, and no portable evidence for responders to reconstruct who authorized what.

### Project proposal (plaintext, no links, <=3000 words)
EMILIA Protocol (EP) is an open standard and Apache-2.0 reference implementation for authorization receipts: cryptographic, offline-verifiable proof that a named principal authorized an exact irreversible AI-agent action, under a stated policy, before it executed. The receipt is the artifact. It verifies anywhere, with open-source code, independent of the system that issued it — defenders do not have to trust the operator's runtime, logs, or continued existence.

EP gates each irreversible action behind a short ceremony — risk watch, pre-action handshake, named human signoff for high-stakes actions, then an atomic sealed commit — and emits a receipt that cryptographically binds seven things: (1) the canonical hash of the exact action, so a receipt presented for any other action fails; (2) a hash-pinned policy version, so mutating policy between authorization and execution fails verification, closing silent-upgrade attacks; (3) a server-issued nonce for replay resistance; (4) one-time consumption, formally proven, so an accepted authorization is consumed at most once; (5) authority-chain integrity, binding the actor to a specific delegation chain with proven acyclicity, so a key holder cannot claim authority never granted; (6) a named, accountable human signoff (a specific person, not a role) hash-bound to the exact action and policy; and (7) append-only, Merkle-anchored logging of every transition for independent audit.

The property most relevant to agentic defense is containment. Prompt injection can change what an agent proposes, but it cannot forge the device-bound human approval or the signed receipt. Either a valid receipt exists for a gated action, or it does not — and the absence of a receipt for a gated action is itself a positive bypass signal, not merely a missing log line. This converts an open-ended "did the agent misbehave?" question into a bounded, checkable evidentiary one.

EP is not a proposal on paper; it ships today. There is an IETF Internet-Draft, draft-schrock-ep-authorization-receipts, at revision -01, defining the receipt schema, the offline verification algorithm, and an initiator-escalation attestation (PIP-007): the agent's own signed, machine-checkable reason for escalating an action to a human — useful, audited context, explicitly framed as a claim by a party the protocol identifies but never trusts, not proof of the model's internal state. There are published, zero-dependency npm packages — @emilia-protocol/verify and @emilia-protocol/issue ("issue locally, verify anywhere") — plus independent verifiers in JavaScript, Python, and Go and a public conformance suite, so a third party can confirm a receipt without trusting us. Safety is machine-checked: 26 TLA+ properties verified by TLC across 413,137 states with zero errors, and 22 Alloy assertions with zero counterexamples (15 on the core model, 7 on cross-operator federation), all re-run in CI. An 85-case red-team suite includes prompt-injection containment. An MCP server lets any MCP-speaking agent place EP as a pre-action guard without changing its tool definitions.

Fit with this program. OpenAI's program now prioritizes deploying models to accelerate cyber defense, explicitly including defensive cybersecurity agents and secure-by-design software. EP is purely defensive — it gates and proves agent actions and has no offensive capability — and it gives defenders a portable containment-and-evidence artifact for the exact risk agentic deployment creates. The MCP guard is the concrete integration: an agent on OpenAI's platform adopts EP as a pre-action gate through the Model Context Protocol, and every gated action emits a receipt a defender can verify offline. EP is open, already reified, and formally verified — the kind of public-good defensive infrastructure the program exists to accelerate.

What we would build with this grant. First, cross-language verifier hardening and conformance expansion: extend the three verifiers and the conformance suite to fully cover the PIP-007 escalation-attestation path, so any defender's stack can validate agent escalations independently; OpenAI API credits would fund codegen-assisted porting and test generation. Second, an agentic red-team containment benchmark: expand the 85-case suite into a structured evaluation, run against frontier models on API credits, that empirically measures the containment claim — that an injected proposal never yields a valid receipt for a gated action. Third, an independent cryptographic implementation audit (Trail of Bits / NCC / Cure53 class) of canonicalization, signing, and cross-verification. Fourth, an MCP guard reference deployment with defender onboarding documentation, and the first external party issuing receipts with its own keys. Grant funds a part-time contract cryptographer alongside the PI for the verifier-hardening and audit-response work.

Honest scope. EP has no production customers yet; a 60-day government observe-mode pilot for county payment-integrity workflows (vendor bank-account-change fraud) is in active outreach, not signed. EP also does not claim more than the cryptography delivers: a receipt proves a named principal authorized a specific action under a specific policy before execution — not that the decision was wise, lawful, or correct, and not the initiator's internal reasoning. That precision is deliberate; the fastest way to lose trust in trust infrastructure is to claim more than you can verify.

Team. Iman Schrock, founder and principal investigator, authored the full stack: the IETF Internet-Draft, the TLA+ and Alloy models, the 85-case red-team suite, the three-language verifiers, and the npm toolkit. Background in trust systems, cryptographic protocols, and regulated-industry software. All artifacts are Apache-2.0 and public.

### Project timeline
Aug 2026 - Cross-language verifier + conformance hardening: full PIP-007 escalation-attestation verification path across the JS/Python/Go verifiers and conformance vectors.
Sep 2026 - Agentic red-team containment benchmark v1: structured prompt-injection eval against frontier models, measuring that injected proposals never yield a valid receipt for a gated action.
Oct 2026 - MCP guard reference deployment + defender onboarding docs; first external party issuing receipts with its own keys.
Nov 2026 - Independent cryptographic implementation audit underway (canonicalization, signing, cross-verification).
Dec 2026 - Public benchmark results + audit summary published; conformance suite v1 freeze.

### Requested funding / API credits
Up to $250,000 total, applying in the program's $10,000 increments, API credits primary.
- ~$150,000 in OpenAI API credits: the agentic containment benchmark at scale (thousands of adversarial prompt-injection trials across multiple frontier models, repeated over the cycle) + codegen-assisted porting/test generation for the three verifiers.
- ~$60,000 direct: independent cryptographic implementation audit (Trail of Bits / NCC / Cure53 class).
- ~$40,000 direct: focused engineering time — PI full-time plus a part-time contract cryptographer.
Glad to right-size; a credits-only award funds the benchmark and verifier work and stands alone.

### Papers (author) link
https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/ — IETF Internet-Draft (author: Iman Schrock); the specification this proposal implements and extends.

### PDF / Additional notes
PDF: left blank (proposal self-contained). Additional notes: "All EMILIA Protocol artifacts are open-source (Apache-2.0); no confidential or personal data is included in this submission."

---

## RESUBMISSION PLAYBOOK (the program invites a marked revision)

**When:** hold ~1 week after the 2026-06-13 submission (a same-day revision reads as scattered). They contact promising teams regardless, so this is upside, not a rescue.

**How:** resubmit the FULL proposal via the same form; in the first line of the proposal and the Additional notes, mark it: "Revision of our 2026-06-13 submission — adds an open benchmark-dataset release plan and model specifics."

**The three upgrades** (each closes an explicit rubric question the first version answered thinly):

1. **Name the benchmark as a released open dataset** (their rubric asks "will you create any new datasets?" — biggest single lever). Drop into the "What we would build" paragraph, replacing the second deliverable:
   > Second, we will create and openly release the **EP Agentic Authorization-Containment Benchmark**: a labeled dataset of adversarial agent scenarios — injection variants paired with pass/fail receipt outcomes and policy-defined escalation ground truth — published under a permissive license (Apache-2.0 / CC-BY) as a reusable eval any lab can run against any agent model. Built and run on OpenAI API credits.

2. **Name the models** (their rubric asks "which AI models you want to use?"). Add to the benchmark sentence:
   > Evaluated against GPT-5.5, GPT-5.4, and GPT-5.3 Instant.

3. **Crisp open-release plan** (their stated priority: "maximal public benefit... clear plan"). Add one line near the close:
   > Release plan: the protocol, three verifiers, conformance suite, and the new benchmark dataset + methodology + results are all published openly (Apache-2.0 / CC-BY); findings shared early per the program's collaboration norm. Purely defensive — no offensive-security component.

Everything else in the submitted proposal stays. Keep the $250k ask + the part-time-cryptographer line (the cash is justified only with that hire in scope).
