# OpenAI Contact Map

Last checked: 2026-07-03

## Positioning

Lead with:

> Permission is not proof. Agent actions need admissible evidence.

The ask:

> Is AE-CHALLENGE / EP-AEG the missing evidence-negotiation layer for
> consequential agent tool calls?

## No-warm-intro contact list

Use public professional channels only: LinkedIn, X, GitHub, OpenAI Developer
Forum, official event Q&A, or official forms. Do not hunt for personal emails.

### Tier 1: named agent people

These names appear on OpenAI's public Operator announcement as leads or core
contributors. Start with the leads; they are closest to agent action safety.

| Person | Public association | Why them | Approach |
|---|---|---|---|
| Yash Kumar | Operator lead | Agent execution/product proximity | LinkedIn/X DM; ask for a technical sanity check |
| Casey Chu | Safety and Model Readiness lead | Consequential-action safety | DM with prompt-injection + action-proof angle |
| Aaron Schlesinger | Infrastructure lead | Runtime, nonce, action boundary fit | LinkedIn/GitHub; lead with reference implementation |
| David Medina | Research Infrastructure lead | Replay/eval/infrastructure fit | LinkedIn/GitHub; lead with replayable verdicts |
| Hyeonwoo Noh | Overall Research lead | Agent research direction | LinkedIn/X; keep it research-grade |
| Reiichiro Nakano | Overall Research lead | Agent research direction | LinkedIn/X; keep it research-grade |

Search strings:

```text
"Yash Kumar" "OpenAI" "Operator"
"Casey Chu" "OpenAI" "Operator"
"Aaron Schlesinger" "OpenAI" "Operator"
"David Medina" "OpenAI" "Operator"
"Hyeonwoo Noh" "OpenAI" "Operator"
"Reiichiro Nakano" "OpenAI" "Operator"
```

### Tier 2: public technical routes

| Route | Link | Use for |
|---|---|---|
| OpenAI Developer Forum | https://community.openai.com/ | Public technical visibility |
| openai-agents-js GitHub | https://github.com/openai/openai-agents-js | Concrete SDK / guardrail discussion |
| openai-agents-python GitHub | https://github.com/openai/openai-agents-python | Concrete SDK / guardrail discussion |
| OpenAI Apps SDK examples | https://github.com/openai/openai-apps-sdk-examples | Apps/MCP/checkout example path |
| OpenAI for Startups | https://openai.com/startups/ | Event access / technical staff |
| Contact Sales | https://openai.com/contact-sales/ | Enterprise/API/Codex partnership angle |
| Security disclosure | https://openai.com/security/disclosure/ | Concrete OpenAI vulnerability only |

### Tier 3: leadership amplification

Use only after the demo is public and concise.

| Person/channel | Why | Suggested move |
|---|---|---|
| Greg Brockman | Technical/product leadership | Reply to relevant public agent/tool post with the 90-second demo |
| Sam Altman | High-reach amplification | Public post only; do not cold pitch |
| OpenAI developer/social accounts | Distribution | Tag after demo is live and useful |

## First DM

OpenAI's agent work has the right UX instinct: ask before actions of
consequence.

I think the missing protocol layer is underneath that confirmation: portable
proof that the exact action had fresh admissible evidence and was consumed once.

We built a small I-D + reference implementation for that loop:
AE-CHALLENGE -> EP-AEG -> replayable verdict.

Not a pitch deck. I can show the bypass/fix in 5 minutes. Who is the right
person on agents/tool safety to sanity-check it?

## Developer Forum post

Title:

> Proposal: evidence challenges for consequential agent tool calls

Body:

OpenAI's agent stack already has the right UX instinct: ask before actions of
consequence.

I think the missing protocol piece is what happens under that confirmation:
how a tool, merchant, enterprise system, or auditor can later prove that the
exact action had fresh admissible evidence and was consumed once.

We built a small reference loop:

```text
AE-CHALLENGE -> obtain evidence -> EP-AEG presentation -> policy replay ->
admissible/missing/stale/conflicted/unverifiable -> consume once
```

It is not a replacement for guardrails or human-in-the-loop UX. It is a
portable evidence-negotiation layer for the effect boundary.

Demo cases:

- partial evidence returns a follow-up challenge;
- stale authorization is re-requested;
- action-digest swap is refused before policy replay;
- complete evidence yields a replayable admissible verdict.

Question for agent/tool builders: where would this belong best: an MCP tool
contract, an Agents SDK guardrail pattern, an Apps SDK checkout pattern, or a
separate I-D?

Happy to share the tiny reference implementation and draft.
