# OpenAI Cybersecurity Grant Program — Application

**Program**: OpenAI Cybersecurity Grant Program
**Index page**: https://openai.com/index/openai-cybersecurity-grant-program/
**Form URL**: https://openai.com/form/cybersecurity-grant-program/ (live, verified June 2026)
**Award**: Increments of $10,000 USD, as API credits, direct funding, and/or equivalents
**Cycle**: Rolling review (changed from quarterly; program evolved Feb 5, 2026)
**Format**: Web form (short-form questions; this document is the
content to paste into each field)

> Program note (June 2026): On Feb 5, 2026 OpenAI evolved the program to
> emphasize large-scale deployment of models to accelerate cyber defense,
> committed an additional $10M in API credits, and launched Trusted Access
> for Cyber. Current stated priorities include training defensive
> cybersecurity *agents*, secure-by-design software, threat intelligence,
> porting code to memory-safe languages, and protecting open-source
> software. Named recipients include Socket, Semgrep, and Trail of Bits.
> This refresh leans into the agentic-security framing.

---

## 1. Project Title

EMILIA Protocol — Verifiable Authorization Receipts for AI Agent Actions

## 2. One-line description

An open standard and zero-dependency reference toolkit that gates every
irreversible AI-agent action behind a cryptographic ceremony binding
identity, authority, policy, and the exact action — producing a portable,
tamper-evident receipt any defender can verify offline. Formally verified;
IETF Internet-Draft published; npm-shipped.

## 3. Problem (≤300 words)

AI agents are moving from recommendation to autonomous action: deploying
code, moving money, rotating credentials, calling tools with real-world
consequences. The defensive question is shifting from "is the model
accurate?" to "did this agent have authorization to take *this specific
irreversible action* on behalf of *this specific principal* — and can a
defender prove it after the fact?"

Existing primitives don't answer that:

- OAuth and API keys prove "this caller has this scope" — not "this caller
  authorized this specific action under this specific policy." Once a key
  is exfiltrated or a session hijacked, every downstream action is silently
  authorized.
- RBAC/ABAC wasn't designed for AI-to-AI delegation chains. No native
  concept of action-bound consent or replay protection.
- SIEM and audit logs record what happened *after* the fact — too late to
  prevent the action, too unstructured to drive enforcement, and produced
  by the same system whose integrity is in question.
- Prompt-injection defenses harden the model's reasoning but leave no
  artifact a third party can check. When an injected agent acts, there is
  nothing portable that distinguishes an authorized action from a bypass.

The first time an autonomous agent ships money, publishes a statement, or
rotates a credential it shouldn't have, the litigation and regulatory cost
will dwarf any authorization infrastructure that could have prevented it —
and incident responders will have no portable evidence to reconstruct who
authorized what. Today there is no open standard for verifiable pre-action
authorization in agent systems. EMILIA Protocol is that standard.

## 4. Solution (≤500 words)

EP gates each irreversible action behind a cryptographic ceremony that
produces a tamper-evident, third-party-verifiable receipt. The receipt
proves authorization — EMILIA the runtime does not vouch; the receipt does,
and anyone can check it offline with no call back to us.

The ceremony, end to end:

  Eye (risk watch) → Handshake (pre-action authorization) →
  Signoff (named human accountability) → Commit (atomic, sealed action)

The receipt cryptographically binds:

1. Action binding — the canonical hash of the exact action authorized.
   Present the receipt for a different action and verification fails.
2. Policy hash pinning — the policy version is hash-pinned at handshake.
   Mutate policy between authorization and execution and verification
   fails (closes silent-upgrade attacks).
3. Replay resistance — server-issued nonce; a consumed receipt cannot be
   replayed.
4. One-time consumption — formally proven: an accepted handshake is
   consumed at most once.
5. Authority chain integrity — the actor is bound to a specific delegation
   chain (acyclicity proven); a key holder can't claim authority never
   granted.
6. Named accountable signoff — for high-stakes actions an irrevocably-named
   human (not a role) attests, hash-bound to the exact action and policy.
7. Append-only event store — every transition recorded in a
   Merkle-anchored log, independently auditable.

Containment property (directly relevant to agentic defense): prompt
injection can change what the agent *proposes*, but never the device-bound
human approval. Injection can rewrite the proposal; it cannot forge the
receipt. And the *absence* of a receipt for a gated action is itself
evidence of bypass — defenders get a positive signal, not just a missing
log line.

What ships today (June 2026):

- IETF Internet-Draft `draft-schrock-ep-authorization-receipts-01`,
  including PIP-007, an initiator escalation attestation: the agent's
  signed, machine-checkable reason for escalating to a human.
- npm `@emilia-protocol/verify` 1.4.0 (verify anywhere) and
  `@emilia-protocol/issue` 0.2.0 (issue locally) — zero-dependency.
- Verifiers in three languages plus a conformance suite.
- Formal verification: 26 TLA+ properties, 22 Alloy assertions, 0
  counterexamples, re-run in CI.
- 85 red-team cases, including prompt-injection containment.
- An MCP server so any MCP-speaking agent can place EP as a pre-action
  guard without changing its tool definitions.

The protocol and reference code are open under Apache 2.0. For an agent
built on OpenAI's platform, EP is the audit-and-containment artifact for
every action it takes: portable, offline-verifiable evidence that turns
"the agent did something" into "here is the signed authorization, or here
is proof there wasn't one."

## 5. Why this is a fit for OpenAI's program (≤200 words)

OpenAI's program now prioritizes deploying models to accelerate cyber
defense — explicitly including defensive cybersecurity *agents* and
secure-by-design software. EP sits at that center: it is purely defensive
(it gates and proves agent actions; no offensive capability), and it gives
defenders a portable containment-and-evidence artifact for the exact
problem agentic deployment creates — proving, after the fact, that an
autonomous action was authorized.

The MCP guard is the concrete integration: an OpenAI-platform agent
adopts EP as a pre-action gate through the Model Context Protocol without
changing its tool definitions, and every gated action emits a receipt a
defender can verify offline. The prompt-injection containment property is
formally stated and red-teamed: injection can change the proposal, never
the device-bound approval, and a missing receipt for a gated action is
itself a bypass signal.

EP is open (Apache 2.0), already reified (IETF I-D, npm packages, 3-language
verifiers), and formally verified — the kind of public-good defensive
infrastructure the program exists to accelerate.

## 6. Use of grant funds (≤200 words)

We request a grant in the program's $10,000 increments. Priorities, in
order, scoped for a Phase-I award:

Cross-language verifier hardening + conformance expansion. Extend the
three existing verifiers and the conformance suite to cover the full
PIP-007 escalation-attestation path, so any defender's stack can validate
agent escalations independently. (OpenAI API credits applied to
codegen-assisted porting and test generation.)

Cryptographic implementation audit. Independent review (Cure53 / NCC /
Trail of Bits class) of canonicalization, signing, and cross-verification.

Agentic red-team benchmark. Expand the 85-case suite into a structured
eval of prompt-injection containment against frontier models, run on
OpenAI credits — measuring that injected proposals never yield a valid
receipt for a gated action.

MCP guard reference deployment + docs. A reference agent that places EP
as a pre-action gate via MCP, with onboarding docs for defenders.

We are glad to right-size the request to the program's increment structure
and to take support as API credits where that is the most useful form.

## 7. Team (≤100 words)

**Iman Schrock**, Founder & PI. Authored the protocol stack: the IETF
Internet-Draft (`draft-schrock-ep-authorization-receipts-01`), 26 TLA+
properties and 22 Alloy assertions (0 counterexamples, re-run in CI), an
85-case red-team suite, three-language verifiers, and the npm toolkit
(`@emilia-protocol/verify`, `@emilia-protocol/issue`). NIST AI Safety
working-group engagement. Background in trust systems, cryptographic
protocols, and regulated-industry software. Apache 2.0 history is public
at github.com/emiliaprotocol/emilia-protocol.

## 8. Public artifacts (links)

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- IETF Internet-Draft: draft-schrock-ep-authorization-receipts-01
- npm: `@emilia-protocol/verify` 1.4.0, `@emilia-protocol/issue` 0.2.0
- Essays: https://emiliaprotocol.ai/essays
  (start with "The Model Is the Crumple Zone")
- Live demo: https://emiliaprotocol.ai/try (device-bound approval demo)
- Formal proofs: `formal/PROOF_STATUS.md`, `formal/ep_handshake.tla`,
  `formal/ep_relations.als`
- Compliance mappings: `docs/compliance/NIST-AI-RMF-MAPPING.md`,
  `docs/compliance/EU-AI-ACT-MAPPING.md`
