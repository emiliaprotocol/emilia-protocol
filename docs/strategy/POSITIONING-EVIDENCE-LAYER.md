<!-- SPDX-License-Identifier: Apache-2.0 -->
# Positioning v2 — the portable evidence layer for agent actions

**Status:** adopted 2026-06-30. Supersedes the "lead with *authorization receipt*" canon as the
*cold-buyer* lead (that canon stays true for the mechanism; it was just the wrong first word).

## Diagnosis (why the motion feels like shouting through glass)

The tech is ahead of the market's vocabulary. EP led with a **narrow primitive (the receipt)** and
asked people to adopt it as a **category** before they had a buying frame. Today's two maintainer
closes (Portkey, Supabase) weren't "your tech is bad" — they were "no buying frame / no adoption
yet." That is a vocabulary/category problem, not a technology problem. The current homepage even
leads with *"machine-checked math"* — proof of the work, shown before the pain. Fix the frame, not
the primitive.

Arcade's $60M (WSJ) **validates the category**: secure agent action authorization, action control,
policy enforcement at execution time, audit. That is buyer language. Borrow it.

## The move (one line)

**Stop leading with receipts. Lead with authorized/safe agent actions. The receipt is the proof
artifact underneath.**

## The category door — then the pivot (this ordering is the whole game)

Borrow the category **noun** to get in the door, then pivot on the same breath to the **verb only EP
owns** — otherwise a buyer compares open-source-EP to funded-platform-Arcade on completeness and EP
loses.

- **Door (their words):** the secure agent-action layer — control what agents can do, enforce policy
  at execution, keep an audit trail.
- **Pivot (our words, immediately):** **portable, offline-verifiable evidence of *who authorized
  exactly what* — across runtimes, tools, logs, auditors, insurers, and standards bodies.**

> EMILIA is the **portable evidence layer for agent actions**: it plugs into MCP, agent runtimes,
> SCITT, and system-of-record workflows so high-risk actions can't execute without verifiable
> authorization — and every executed action carries offline proof of who approved exactly what.

## Versus Arcade — reframe from competitor to emitter

Do **not** try to out-platform them (they have money, team, runtime, sales). The distinction:

- **Arcade controls actions *inside Arcade*.** Lock-in is their incentive.
- **EMILIA makes authorization evidence *portable across* runtimes/tools/logs/agencies/insurers/
  standards.** Portability is structurally anti-their-interest — they can't easily copy it without
  undercutting their own lock-in.

**Win condition:** become **the receipt format the category emits** — the PDF / JWT / OpenTelemetry /
SBOM of agent-action authorization. Categories converge on one evidence/interchange format, and the
winner isn't the biggest platform, it's whoever's format everyone emits. That reframes Arcade (and
every other runtime) from *competitor* to *future emitter / customer*. You are not losing a platform
race — you're not in one.

Category-proof line: *"$60M says agent-action authorization is real. EMILIA is the open,
offline-verifiable evidence layer for that category."*

## Two funnels — never conflate them

| | Social-object funnel | Buyer funnel |
|---|---|---|
| Purpose | mindshare / category ownership | proof + revenue |
| Wedge | **"Receipt Required for MCP"** — RR-1 badge, registry, PR kit, public report, fire-drill leaderboard | **one painful high-risk action** |
| Buyer feels pain? | No (maintainers don't; their users do) — it's **free + viral**, not revenue | Yes — someone loses money/compliance if it's wrong |
| KPI | RR-1 badges in the wild, fire-drill scans, awareness | 1 implementation event + 1 reliance event |

MCP is the **awareness channel**, not the revenue channel. Today proved maintainers resist adopting
it as a dependency — so the social object is the *zero-dep drop-in + the badge*, not "install our
package." Keep the two funnels separate in every plan.

## The buyer wedge — pick the action, run two lanes

**The action (right, per Iman):** *payment-destination / vendor bank-detail change.* It is the single
most fraud-prone irreversible agent action (BEC / vendor-account-change fraud), concrete, painful,
auditable, and the receipt story lands instantly: *"a named human approved changing this vendor's
payout account — verifiable offline, forever."*

**Refinement — split the buyer, keep the action:**
- **Fast lane (proof + revenue): commercial AP / fintech / accounting.** Larger, faster buyers who
  feel the dollar loss directly. This is where a design partner and a paying pilot come from. (Note:
  `bexio-mcp-server#15`, opened today, is literally an accounting MCP with `create_iban_payment` /
  bank-detail actions — the wedge action showed up organically.)
- **Lighthouse lane (mandated demand + narrative): government / regulated finance & health.** Slower
  sales cycle, but demand is **non-discretionary** — EU AI Act Art.14, DoD 3000.09, audit mandates
  *require* provable human oversight, so the receipt is a compliance artifact, not a nice-to-have.
  This is the story and the marquee logo, not the fast revenue.

Lead the **story** with the mandated/regulated angle; get the fast **proof** from commercial AP.

## The asks — implementation events, not belief

Never ask anyone to believe. Ask for one concrete event:
- *"Let me wrap one dangerous action in your server."*
- *"Let me generate one evidence packet for a real workflow."*
- *"Would your auditor rely on this receipt as evidence?"*

Two events are the only near-term KPI that matters: **one external implementation** + **one reliance**
(a named auditor/insurer/agency says they'd rely on a receipt).

## Message ladder — three audiences, one truth

- **Buyer:** "Stop your AI from wiring money to the wrong account — and prove a named human approved
  it." (Never say "receipt format" or "evidence layer" to a buyer; that's not their language.)
- **Investor / analyst:** "The open, offline-verifiable evidence layer for the agent-action category
  Arcade just validated — the format every runtime emits."
- **Standards / AAIF / SCITT:** "The human-authorization artifact SCITT logs and AIPF defers — an EP
  receipt rides as a COSE Signed Statement." (SCITT architecture is now **RFC 9943**.)

## What NOT to do

- Don't lead with "receipt" or "machine-checked math" to a cold buyer. (Mechanism ≠ pain.)
- Don't compare feature-completeness to Arcade. Compete on portability / offline / trust-no-operator.
- Don't sell "a format" — nobody buys a format. Sell the solved painful action; let the format become
  inevitable underneath.
- Don't let a beautiful new homepage substitute for the two hard events. Messaging **serves** the
  adoption asks; it does not replace them.

## Why this pivot is cheap right now (assets already exist)

This is a re-frame of built assets, not a rebuild:
- **Zero-dep drop-in shipped today** (`emilia-gate.mjs`) → makes "emit a receipt" trivial = fuels the
  "format everyone can emit" thesis.
- **RR-1 + fire-drill leaderboard** built → the social object already exists.
- **SCITT architecture → RFC 9943 (today)** + our profile/demo → the "plugs into standards" proof is
  timely and real.
- **bexio#15** → the payment-change wedge action, organic.
- **Gov assets** (Utah/Cam Bronson, GovGuard, Art.14 briefs, county-finance/NASCIO list) → the
  lighthouse lane is already seeded.

See [[project_emilia_positioning]], [[project_emilia_gate]], [[project_emilia_adoption]],
[[reference_competitor_cohesion]].
