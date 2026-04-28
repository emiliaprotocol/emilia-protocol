---
title: EMILIA GovGuard
subtitle: Pre-execution payment integrity for public funds
geometry: margin=0.6in
fontsize: 10pt
---

# EMILIA GovGuard

**Pre-execution payment integrity for public funds.**

---

## The control gap

Most fraud against public funds happens *inside valid sessions*. The actor is authenticated. The system records a successful action. The control surface verifies *who is logged in* — it does not produce a tamper-evident, cryptographically bound record proving that **this exact change** was authorized by **the right named human** under **the right policy** at **the exact moment** it executed.

That gap is where benefit-routing fraud, vendor-bank-account redirection, and operator-override misuse succeed.

## What GovGuard does

GovGuard is a pre-execution control layer. It sits between the case-system save and the payment system, intercepting high-risk actions before they commit:

- **Verifies actor identity.** Cryptographically — not just session-level.
- **Verifies authority chain.** Complete delegation path from root authority to the acting principal.
- **Binds exact action context.** Specific operation, target, parameters, environmental conditions — pinned to a one-time cryptographic ceremony.
- **Pins policy version and hash.** Immutable reference to the exact policy that authorized this action.
- **Requires named human signoff.** Where policy demands it, a specific accountable human assumes irrevocable ownership of the outcome — not a role, a person.
- **Issues a tamper-evident receipt.** Ed25519-signed, Merkle-anchored, verifiable offline by anyone.

## What auditors get

Every controlled action produces an evidence packet:

- decision record · policy version + hash · actor identity source · authority chain · approval sequence · signoff trace · nonce, expiry, and one-time consumption proof · execution reference · final outcome

Live example a buyer can verify themselves: **https://emiliaprotocol.ai/r/example**

Anyone can install `@emilia-protocol/verify` and re-check the signature without trusting our infrastructure.

## 30-day pilot scope

| Phase | Duration | Activity |
|---|---|---|
| Week 0 | 5 days | Workflow selected, source systems identified, risk thresholds set, approval rules configured, success metrics agreed |
| Week 1 | 7 days | Shadow mode — GovGuard observes, never blocks. Daily report: high-risk actions, missing-authority signals, after-hours actions, new-destination changes |
| Week 2 | 7 days | Shadow + receipt mode — every high-risk action gets a Trust Receipt preview |
| Week 3 | 7 days | Limited enforcement on one class (e.g., vendor bank-account changes ≥$10K) |
| Week 4 | 4 days | Final report — high-risk actions found, approvals required, evidence packets generated, expansion proposal |

**Pilot fee:** $25,000 – $75,000 depending on integration depth.
**Annual license** (post-pilot): $150,000 – $500,000 or per-action pricing ($0.50–$5/action), whichever the agency prefers.

## Open standard, no lock-in

- **License:** Apache 2.0 — agency can self-host, fork, or independently verify.
- **Formal verification:** 20 TLA+ theorems verified, 32 Alloy facts + 15 assertions, both run in CI.
- **Compliance mappings:** NIST AI RMF (38 subcategories), EU AI Act Articles 9–15 + 26.
- **Open-source verifier:** `npm install @emilia-protocol/verify` — zero-dependency, works offline.

## Contact

**Iman Schrock** — Founder, EMILIA Protocol
iman@emiliaprotocol.ai · github.com/emiliaprotocol · emiliaprotocol.ai/govguard
