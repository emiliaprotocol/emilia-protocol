# Anthropic Research / Grant Programs — Application

**Programs targeted** (verified live, June 2026):

1. **External Researcher Access Program** — free Claude API credits for
   AI safety & alignment research. ~$1,000 in credits per approved
   applicant (higher in rare cases). Reviewed the first Monday of each
   month. Apply: https://forms.gle/pZYC8f6qYqSKvRWn9
   (linked from support.claude.com article 9125743). This is the
   highest-fit, lowest-friction path — apply first.
2. **Anthropic Fellows Program** — 4-month mentored AI-safety research
   with Anthropic scientists; ~$3,850/wk stipend + ~$15k/mo compute.
   Listed research areas include AI control, AI security, and model
   welfare — PIP-007 agent-accountability work fits "AI control / AI
   security." Cohorts May & July 2026, then rolling for late-Sept 2026+.
   Apply via Anthropic careers (greenhouse) / fellows@anthropic.com.
   Note: requires US/UK/Canada residence + work authorization.
3. **Economic Futures Research Awards** — $10K–$50K for empirical
   research on AI's economic impact. Secondary fit: the cost of
   unattributable agent actions (liability, insurability) is an economic
   externality EP measurably reduces. Use only if a labor/economics
   framing is wanted. https://www.anthropic.com/economic-futures/program

**Format**: Each program has its own form/inbox (URLs above). This
document is the content; map sections to the program as noted in
`submission.md`. Submit via the form, or attach as a proposal PDF for
direct researcher outreach.

---

## 1. Project Title

Verifiable Authorization Receipts for Agentic AI — Crumple-Zone
Infrastructure for the Model Provider

## 2. Research thesis (≤200 words)

When an autonomous agent takes an irreversible action a human shouldn't
have authorized, the headline is "the model did it" — and the blame, the
Senate letter, and the regulatory exposure land on the model provider.
This is the crumple-zone problem: absent a portable record of who
authorized what, the model absorbs accountability for human-authorized
actions. EMILIA Protocol is the infrastructure that makes "the model did
it" answerable.

EP is a formally-verified open standard for pre-action authorization. Each
irreversible action a Claude-driven agent takes can be wrapped in an EP
handshake → signoff → commit ceremony that produces a tamper-evident,
third-party-verifiable receipt. The receipt — not EMILIA, not the model —
binds the action's canonical hash to the exact policy version, the actor's
delegation chain, and, where required, a named human signatory. The
*absence* of a receipt for a gated action is itself evidence of bypass.

Reified, not theoretical: IETF Internet-Draft
`draft-schrock-ep-authorization-receipts-01`; 26 TLA+ properties + 29
Alloy assertions (0 counterexamples, re-run in CI); 85 red-team cases;
three-language verifiers; npm `@emilia-protocol/verify` 1.4.0 and
`@emilia-protocol/issue` 0.2.0 (zero-dependency); MCP server. Apache 2.0.

## 3. Why this matters for Anthropic's safety mission (≤300 words)

**(a) Crumple-zone protection for the model provider — the direct fit.**
The Nov 2025 espionage disclosure showed where accountability flows: the
Senate letter went to Anthropic, not to the operators who directed the
agent. When an agent acts, the public-facing question becomes "did
Anthropic's model do this?" EP changes the answerable artifact. With
device-bound, human-authorized receipts, a human-directed action carries a
signed record naming the authorizing principal — and an action without a
receipt is provably a bypass, not the model acting unbidden. EP is the
public-good infrastructure that lets the provider point to evidence
instead of absorbing the blame.

**(b) PIP-007 as agent-accountability research.**
The Internet-Draft's PIP-007 is an initiator escalation attestation: the
agent's signed, machine-checkable *reason* for escalating to a human. This
is precisely the kind of legible agent-control primitive Anthropic's AI
control and AI security agendas want — a verifiable record of when and why
an agent decided it needed a human, not a post-hoc rationalization.

**(c) Prompt-injection containment, formally stated.**
EP's containment property: injection can change what the agent *proposes*,
but never the device-bound human approval. Injection can rewrite the
proposal; it cannot forge the receipt. This composes with Constitutional
AI — the constitution gives the model a disposition to refuse; EP gives the
surrounding system a cryptographic record of authorization vs. bypass that
is third-party verifiable. It also makes misalignment empirical: query the
log for actions whose receipts don't match the policy a human authorized,
rather than arguing about what the model "wanted."

Without the action-side primitive, the safety story has a gap adversarial
deployments will exploit — and one that routes blame to the provider. EP
fills it with formal proofs and a published standard.

## 4. What we are asking for (≤200 words)

Mapped to the live programs, in priority order:

1. **External Researcher Access Program** — Claude API credits for
   AI-safety research. Used to: run the 85-case red-team suite (and its
   expansion) against Claude to measure prompt-injection containment —
   confirming injected proposals never yield a valid receipt for a gated
   action; evaluate PIP-007 escalation-attestation behavior; generate
   policy expansions for the EP policy library. Per-applicant credits are
   modest (~$1k); we will scope the eval to fit, and reapply as the
   benchmark grows.

2. **Direct technical engagement** with Anthropic's safety / control
   researchers — a few hours of consultation on red-team methodology for
   the EP eval, and on whether PIP-007 escalation attestations are a
   useful control primitive for Claude agents.

3. **Visibility / endorsement.** If the formal verification and the
   crumple-zone framing merit it, an Anthropic-aware write-up of the agent
   authorization-receipt results, published as a public report.

We are not asking Anthropic for cash. Credits plus technical engagement is
the highest-leverage support given the program shapes above.

## 5. Team (≤100 words)

**Iman Schrock** — Founder, EMILIA Protocol. Authored the IETF
Internet-Draft (`draft-schrock-ep-authorization-receipts-01`, incl.
PIP-007), the formal model (26 TLA+ properties, 22 Alloy assertions, 0
counterexamples in CI), the 85-case red-team suite, three-language
verifiers, and the npm toolkit (`@emilia-protocol/verify`,
`@emilia-protocol/issue`). NIST AI Safety working-group engagement.
Apache 2.0 history at github.com/emiliaprotocol/emilia-protocol.

## 6. Public artifacts and verifiable claims

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- IETF Internet-Draft: draft-schrock-ep-authorization-receipts-01
  (handshake → signoff → commit; PIP-007 initiator escalation attestation)
- Formal proofs: `formal/PROOF_STATUS.md`, `formal/ep_handshake.tla`,
  `formal/ep_relations.als` (26 TLA+ properties, 22 Alloy assertions)
- npm: `@emilia-protocol/verify` 1.4.0, `@emilia-protocol/issue` 0.2.0
  (zero-dependency; issue locally, verify anywhere)
- Essays: https://emiliaprotocol.ai/essays — "The Model Is the Crumple Zone"
- Live demo: https://emiliaprotocol.ai/try (device-bound approval)
- MCP integration: EP pre-action guard for any MCP-speaking agent
- Red-team: 85 cases incl. prompt-injection containment
- Compliance mappings: NIST AI RMF, EU AI Act (Articles 9–15, 26)
