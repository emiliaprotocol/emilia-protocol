# EU AI Act — Article 14 Human-Oversight Kit

> **Not legal advice.** This maps EMILIA Protocol *capabilities* to the obligations in the
> EU AI Act for high-risk AI systems. The Act applies in phases and its interpretation is
> fact-specific — validate scope and sufficiency with qualified counsel. Use this as an
> engineering starting point, not a compliance guarantee.

High-risk AI systems carry obligations including risk management (Art 9), record-keeping /
logging (Art 12), and **human oversight (Art 14)**. EMILIA gives you a concrete technical
implementation for the parts that are about *a human being able to intervene before an
irreversible action, with an auditable record of who decided what.*

## How EP maps to the obligations

| Obligation | What it asks for | EP capability |
|---|---|---|
| **Art 14 — Human oversight** | Humans can oversee, intervene, and stop the system | **Accountable Signoff** — an irreversible action is gated until a *named* human approves the exact action; `deny` stops it outright |
| **Art 12 — Record-keeping / logging** | Automatic logging of events over the system's lifetime | **Trust Receipts** — Ed25519-signed, Merkle-anchored, offline-verifiable records of every gated decision (who, what, policy, outcome, time) |
| **Art 9 — Risk management** | Identify and mitigate risks of high-risk actions | **Policy evaluation** — actions classified by risk; high-risk classes routed to signoff or denied (formally verified engine: 26 TLA+ theorems) |
| **Governance evidence** (NIST AI RMF / ISO 42001 adjacent) | Demonstrable, documented controls | **Receipt export** — an auditor-ready evidence bundle (`EP-BUNDLE-v1`) anyone can verify without trusting EP |

## The oversight policy (express it for your system)
EP gates on *canonical actions*. For a high-risk deployment, the human-oversight rule is:
"these action classes cannot execute without a named human's signed approval." Examples:

| Canonical action | Oversight rule | Maps to |
|---|---|---|
| `payment.release` (≥ threshold or new destination) | Accountable signoff required | Art 14 |
| `record.delete` / `data.erasure` | Accountable signoff required | Art 14 |
| `benefit.decision` (grant/deny/modify) | Signoff + receipt retained | Art 14 + Art 12 |
| `contract.sign` | Accountable signoff required | Art 14 |
| Hard-deny flags (impossible-travel, known-compromised device) | Deny + alert | Art 9 |

(These are policy *intents* you configure for your gate — not a drop-in legal control.)

## A 30-day path
1. **Week 1 — Inventory.** List the irreversible actions your high-risk system can take. Each
   becomes a canonical action.
2. **Week 2 — Gate (observe-only).** Wrap them (MCP server, `withGuard`, or `require-receipt`)
   in **Emilia Eye** mode: log "what would have been blocked" with zero enforcement. No risk.
3. **Week 3 — Enforce + sign-off.** Turn on `signoff_required` for the high-risk classes; wire
   approvals to your humans (Slack, dashboard, signoff API). Every approval mints a receipt.
4. **Week 4 — Evidence.** Export the receipt bundle; hand your auditor a record they can verify
   offline (`@emilia-protocol/verify`, JS or Python) — no need to trust EP or you.

## What EP does *not* do
It is not a complete AI-Act compliance program. It does not cover data governance (Art 10),
transparency obligations (Art 13), conformity assessment, or your documentation/QMS. It
implements the *human-in-the-loop-before-irreversible-action* slice — well, and provably.

**Start:** `docs/QUICKSTART.md` · **Verify:** `@emilia-protocol/verify` / `emilia-verify` (Python)
