# Anthropic Research / Grant Programs — Application

**Programs targeted**:
1. **Anthropic Research API Access** — Claude API credits + technical
   support for AI safety researchers (rolling).
2. **Anthropic Academic / Research Grants** — direct funding for
   alignment, safety, and verification research (rolling, when active).
3. **Frontier Model Forum** research collaboration (longer-term play).

**URL**: https://www.anthropic.com/research (start here; the
research-grants page has moved historically — if not at /research-grants,
search for "Anthropic research grants" and follow the most recent blog
post or careers page reference).

**Award**: API credits ($10K–$500K typical), occasional cash co-funding,
direct technical support from Anthropic's safety team.

**Format**: Application form / direct outreach to Anthropic Research
team. This document is the content; submit via the form, or as a
proposal PDF if the form is unavailable.

---

## 1. Project Title

Verifiable Pre-Action Authorization for Agentic AI Systems

## 2. Research thesis (≤200 words)

Anthropic's safety research agenda repeatedly returns to a hard problem:
how do we know an autonomous AI agent did the right thing? Constitutional
AI, RLHF, and interpretability work address the *intent* side — making
the model less likely to want bad outcomes. But on the *action* side,
once the model decides to act, there is no standard, formally-verified
mechanism for binding that action to a specific authorized policy and a
specific accountable principal.

EMILIA Protocol is the action-side complement. It is a formally-verified
open standard for pre-action authorization. Each consequential action a
Claude-driven agent takes (or any agent takes) can be wrapped in an EP
handshake → signoff → commit ceremony that produces a tamper-evident,
cryptographically-verifiable receipt. The receipt binds the action's
canonical hash to the exact policy version, the actor's identity chain,
and (where required) a named human signatory.

26 TLA+ properties verified, 35 Alloy facts verified, 3,483 tests, 0
counterexamples — all re-run in CI on every commit. Apache 2.0,
production-ready, integrates with Claude tool use via the
`@emilia-protocol/sdk` package and 34 MCP tools.

## 3. Why this matters for Anthropic's safety mission (≤300 words)

Three concrete safety wins:

**(a) Detecting misalignment empirically rather than philosophically.**
When every agent action emits a structured receipt, you can query the
audit log for actions that were authorized but probably shouldn't have
been (action context X but expected context Y, signoff under high
assurance but actually low assurance, etc.). This shifts alignment
testing from "did the model want to do this" (hard, philosophical) to
"did the action it took match the action it was authorized for"
(empirical, queryable, falsifiable).

**(b) Bounding blast radius of frontier-model failures.**
A failure of Claude — hallucinated tool call, prompt injection — is
contained at the EP layer because the action is gated on a policy hash
that doesn't match the contextual policy the human authorized. This
turns an open-ended frontier-model risk into a bounded, RFC-style
authorization-rejection risk.

**(c) Multi-stakeholder agent governance.**
Constitutional AI says "the model should not do X"; EP says "no one is
authorized to make the model do X without a hash-bound named human
attestation." The two compose: Constitutional AI gives the model a
disposition to refuse; EP gives the surrounding system a *cryptographic
record* of refusal vs. authorization that is third-party verifiable.

Without the action-side primitive, Anthropic's safety story has a
gap that adversarial deployments will exploit. EP fills that gap with
formal proofs.

## 4. What we are asking for (≤200 words)

In priority order:

1. **Claude API access at research scale** ($50K–$200K credits over 12
   months). Used for: structured-output adversarial benchmarks of
   trust-reasoning behavior, evaluating EP receipts under prompt-injection
   attacks, generating policy expansions for EP's policy library.
2. **Direct technical engagement** with Anthropic's Frontier Red Team
   (or equivalent). 4–6 hours of consultation on red-team evaluation
   methodology for the EP Eval benchmark.
3. **Co-publication / endorsement** opportunities. If the formal verification
   work merits it, a co-authored or Anthropic-endorsed write-up of the
   "agent authorization protocol" results, published as a public report
   or blog post.

We are not asking for cash funding from Anthropic. The Claude API access
+ technical engagement is the highest-leverage form of support given
Anthropic's organizational shape.

## 5. Team (≤100 words)

**Iman Schrock** — Founder, EMILIA Protocol. Authored the formal model
(TLA+, Alloy), reference runtime (Next.js + Supabase), SDK ecosystem
(TypeScript + Python). NIST AI Safety Working Group engagement in
progress. Apache 2.0 history at github.com/emiliaprotocol.

## 6. Public artifacts and verifiable claims

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- Formal proofs: `formal/PROOF_STATUS.md` (T1–T26), `formal/ep_handshake.tla`,
  `formal/ep_relations.als`
- Live deployment: https://www.emiliaprotocol.ai
- npm SDK: `@emilia-protocol/sdk`, `@emilia-protocol/verify`
- MCP integration: 34 EP-prefixed tools at `mcp-server/index.js`
- Compliance mappings: NIST AI RMF (38 subcategories), EU AI Act
  (Articles 9–15, 26).
