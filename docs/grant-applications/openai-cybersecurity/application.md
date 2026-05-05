# OpenAI Cybersecurity Grant Program — Application

**Program**: OpenAI Cybersecurity Grant Program
**URL**: https://openai.com/index/cybersecurity-grant-program/
**Award**: $10K – $1M (in OpenAI API credits and/or cash)
**Cycle**: Quarterly review
**Format**: Web form (short-form questions; this document is the
content to paste into each)

---

## 1. Project Title

EMILIA Protocol — Verifiable Pre-Action Authorization for AI Agent Systems

## 2. One-line description

Open standard and Apache-2.0 reference runtime that gates every consequential
AI-agent action behind a cryptographic ceremony binding identity, authority,
policy, and action — formally verified, federation-ready, in production today.

## 3. Problem (≤300 words)

AI agents are moving from recommendation to autonomous action: deploying
code, sending email and money, modifying infrastructure, calling APIs that
have real-world consequences. The defensive cybersecurity question is
shifting from "is the model accurate?" to "did this agent have authorization
to take *this specific action* on behalf of *this specific principal*?"

Existing primitives don't answer that question:

- **OAuth / API keys** prove "this caller has access to this scope" — but
  not "this caller authorized this specific action under this specific
  policy." Once a key is exfiltrated or a session hijacked, every
  downstream action is silently authorized.
- **RBAC / ABAC** systems weren't designed for AI-to-AI delegation chains.
  They have no native concept of action-bound consent or replay protection.
- **Reputation scoring** systems produce opaque numbers that aren't
  cryptographically verifiable by third parties — useless when an
  external operator must accept the assertion.
- **Existing audit / SIEM systems** record what happened *after* the
  action — too late to prevent fraud, too unstructured to drive
  enforcement.

The first time an autonomous agent ships money it shouldn't have, sends
a public statement it shouldn't have, or rotates a credential it
shouldn't have, the regulatory and litigation cost will dwarf any
authorization infrastructure investment that could have prevented it.
Today there is no open standard for "verifiable pre-action authorization"
in AI systems. EMILIA Protocol is that standard.

## 4. Solution (≤500 words)

EP gates each consequential action behind a cryptographic ceremony that
produces a tamper-evident, third-party-verifiable receipt:

```
[Eye] → [Handshake] → [Signoff] → [Commit]
 risk     pre-action    named human    atomic
 watch   authorization  accountability action seal
```

Concretely, the protocol enforces seven safety properties (formally
proven, T1–T7 in `formal/PROOF_STATUS.md`):

1. **Action binding** — the receipt includes the canonical hash of the
   action being authorized; presenting the receipt for a different action
   fails verification.
2. **Policy hash pinning** — the policy version is hash-pinned at
   handshake initiation; if the policy is mutated between authorization
   and execution, verification fails (closes silent-upgrade attacks).
3. **Replay resistance** — each handshake has a server-issued nonce;
   replaying a previously-consumed receipt is rejected at the database
   level under `FOR UPDATE` lock.
4. **One-time consumption** — proven by formal model: an accepted
   handshake can be consumed at most once.
5. **Authority chain integrity** — the handshake ties the actor to a
   specific authority chain (with delegation acyclicity proven), so a
   key holder can't claim authority they were never granted.
6. **Named accountable signoff** — for high-stakes actions, an
   irrevocably-named human (not a role) attests, and that attestation
   is hash-bound to the exact action and policy.
7. **Append-only event store** — every state transition is recorded in
   a Merkle-anchored event log, independently auditable.

The runtime is in production (Vercel + Supabase, RLS-hardened, 50+ API
endpoints, 34 MCP tools for agent integration). The protocol spec is
open under Apache 2.0. The verification library is npm-published
(`@emilia-protocol/verify`); cross-language ports (Python, Go, Rust)
are the work this grant would fund.

## 5. Why this is a fit for OpenAI's program (≤200 words)

OpenAI's grant program funds defensive cybersecurity tools and AI safety
infrastructure. EP sits at exactly that intersection: it is defensive
(it prevents unauthorized agent actions), uses formal verification
(rare in deployed protocols), and ships open-source under Apache 2.0
(removes the lock-in concern OpenAI has historically had with
external dependencies). EP also integrates natively with OpenAI's
function-calling and agent SDKs — the schema for "EP-authorized tool
call" is published in `docs/LLM-FUNCTION-CALLING-SCHEMA.md`. Agents
built on the OpenAI platform can adopt EP as a pre-action gate without
changing their tool definitions.

## 6. Use of grant funds (≤200 words)

| Line | Amount | What |
|---|---|---|
| Cross-language verify ports (Python/Go/Rust) | $25,000 | Engineering + OpenAI API credits for codegen-assisted port. |
| Cryptographic implementation audit | $15,000 | Cure53 or NCC Group review of the canonicalization, signing, and federation cross-verification logic. |
| Federation reference deployment | $20,000 | AWS GovCloud + control-plane infra for second operator. |
| Adversarial benchmark (LLM eval) | $15,000 | Red-team prompts + structured evaluation against OpenAI's frontier models for trust-reasoning capability. |
| Open-source community + documentation | $5,000 | Contributor onboarding, technical writers for the public spec. |

**Total: $80,000.** Phase I scope; willing to right-size up or down.

## 7. Team (≤100 words)

**Iman Schrock**, Founder & PI. Designed and authored the protocol stack:
26 TLA+ theorems, 35 Alloy facts, 3,483 tests, formal proofs in CI. Active
NIST AI Safety Working Group engagement. Background in trust systems,
cryptographic protocols, regulated-industry software. Apache 2.0 commit
history is public at github.com/emiliaprotocol.

## 8. Public artifacts (links)

- Repository: https://github.com/emiliaprotocol/emilia-protocol
- Live API: https://www.emiliaprotocol.ai/protocol
- Verify library on npm: `@emilia-protocol/verify`
- Formal proofs: `formal/PROOF_STATUS.md`, `formal/ep_handshake.tla`,
  `formal/ep_relations.als`
- Compliance mappings: `docs/compliance/NIST-AI-RMF-MAPPING.md`,
  `docs/compliance/EU-AI-ACT-MAPPING.md`
