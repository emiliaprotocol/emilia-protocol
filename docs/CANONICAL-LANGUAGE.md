# EP Canonical Language

This document defines the authoritative vocabulary for EMILIA Protocol across docs, APIs, SDKs, product surfaces, proposals, investor materials, and website content.

## Canonical company category

> **EMILIA is the authority control plane for autonomous work.**

## Canonical company line

> **Every consequential agent action enters with authority and exits with a receipt.**

The plain-language operating picture behind that category is the **authority
toll booth for autonomous work**. It is a customer-owned Gate at a configured
protected boundary, not a claim that EMILIA currently operates a global central
network or mediates every action.

## Canonical technical line

> **EMILIA Protocol is the open verification and evidence substrate for consequential machine actions. EMILIA Gate is the deny-by-default consequence firewall at the executor boundary: it verifies the relying party’s selected evidence, binds it to the exact material action, consumes accepted authority once, and preserves the outcome.**

## Canonical market line

> **Identity says who or what is present. Delegation says what an agent may call. Policy says what a machine rule permitted. EMILIA proves who authorized the exact material action and controls whether the protected executor may create the consequence now.**

## Canonical investor line

> **Humans define authority. Agents exercise it. EMILIA ensures the agent cannot quietly widen it. EMILIA charges where authorized intent becomes consequential action.**

The second sentence names the value location, not a current per-action billing meter. Current offers
remain protected-workflow pilot, implementation, and annual Gate plus Assurance.

## Canonical protocol and product shorthand

> **Protocol proves. Gate prevents.**

## Canonical interoperability line

> **AgentROA governs what an agent may call. ORPRG verifies that policy permitted the effect. EMILIA proves who authorized the exact material action — and safely controls the consequence when money, infrastructure, regulated records, or irreversible state is involved.**

This is precise composition language, not an exclusivity claim. AgentROA and
ORPRG remain independently verified native inputs. CAID correlates their
material action only under relying-party-pinned mapping profiles. AEC evaluates
whether the required evidence is satisfied. The executor separately authorizes
and Gate enforces.

## Canonical AI / agent supporting line

> **MCP tells agents how to use tools. EMILIA Gate makes a protected tool or system refuse consequential mutation until its exact-action evidence requirement is met.**

Use this as a supporting line in AI-native contexts. It is not the main company definition.

## Canonical signoff line

> **Accountable Signoff ensures that when policy requires human ownership, a named responsible human must explicitly assume responsibility for the exact action before it executes.**

## Canonical Eye line

> **Emilia Eye is the lightweight warning layer that flags when stricter EP trust controls should apply.**

## What EP is

- A protocol-grade trust substrate
- A deny-by-default consequence-control layer at protected executor boundaries
- A policy-bound, authority-aware, replay-resistant decision system
- An interoperable object model for trust receipts, trust profiles, trust decisions, and pre-action enforcement
- An interoperable consumer of native delegation and policy evidence, including
  AgentROA and concrete ORPRG profiles, without collapsing those artifacts into
  human authorization

## What EP is not

- Not a generic identity platform
- Not a wallet
- Not a social reputation network
- Not a generic workflow engine
- Not a broad marketplace for “trust”
- Not a replacement for agent delegation, identity, or policy-decision protocols
- Not proof that a provider effect succeeded merely because authorization was valid

## Deprecated framing to avoid

Do not use these as primary descriptions:
- trust before high-risk action
- actors and high-risk workflows
- install preflight as the main company story
- trust marketplace
- credit score for the agent economy
- software trust as the whole category
- another general-purpose agent authorization gateway

## Retired claim language (indefensible categorical claims)

These are not framing preferences; they are claims a hostile review showed our own docs
already carried, each defeated by a concrete, named failure mode. Enforced by
`scripts/check-language-governance.ts`.

| Retired phrase | Why it is indefensible | Replace with |
|---|---|---|
| non-repudiable / non-repudiation (as a claim about an EP artifact) | Key compromise and backdating defeat the categorical claim | "signed and attributable under pinned keys" / "cryptographically attributable." In a legal-facing document, pair it with the boundary: attribution is a technical property; legal non-repudiation is a legal conclusion no artifact can guarantee by itself. |
| forgery is impossible / cannot be forged / impossible to forge | Never claim impossibility | State the actual mechanism: "a signature that does not verify under the pinned key is refused" or "forging a receipt requires possession of the signing key." |
| proves compliance / compliance-proof | Legal interpretation of what satisfies a regulation is not ours to claim | "supports compliance assessment" / "provides evidence a compliance reviewer can verify." Keep any mapping tables intact; only the verb changes. |
| no competitor has this / nobody else has this / nobody else can | Unverifiable market claim | Name the specific, checkable capability gap instead of a categorical claim about the entire market. |
| prices risk accurately / accurate risk pricing | An actuarial claim EP cannot substantiate; EP supplies evidence to a pricing process, it does not price risk | Describe the evidence EP supplies (e.g., "gives underwriters signed evidence of human authorization to price against"), never the pricing outcome itself. |
