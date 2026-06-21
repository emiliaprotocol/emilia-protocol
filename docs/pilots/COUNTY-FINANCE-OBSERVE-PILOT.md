<!-- SPDX-License-Identifier: Apache-2.0 -->
# Authorization Evidence — 60-Day Observe-Mode Pilot
### For county finance offices · vendor payments, grant disbursements, benefit payments, procurement

**The receipt, not the dashboard. We produce audit evidence — we change nothing in your payment flow.**

---

## The question this pilot answers

> *Six months from now, can you prove **who approved** this disbursement — to **this** payee, for **this** amount — without asking anyone to trust the system that processed it?*

Today the honest answer is usually: *"It's in the workflow tool's logs."* Those logs are
kept by the same system whose conduct an auditor is examining, they aren't bound to the
exact payment, and they can't be checked by an outside party. When the question comes from
an external auditor, a vendor-fraud investigation, or a board — after a bank-account-change
scam or a disputed disbursement — a log entry is testimony, not proof.

EMILIA produces **proof**: a cryptographic **authorization receipt** that binds the named
human approver(s) to one exact action, verifiable **offline** by anyone, forever — even if
EMILIA, the county system, and the internal log are all gone.

## What we do in 60 days — observe mode

We run **alongside** one of your high-risk workflows. **We block nothing. We touch no
payment.** We observe the actions and the approvals that already happen, and we show you,
on real data, what accountable authorization evidence *would* look like — and where it's
missing today.

This is deliberately the safe version: no integration into the release path, no operational
risk, no rip-and-replace. You see the value as evidence before anyone debates enforcement.

## The deliverable: an Auditor Workpaper Package

Not analytics. Not a dashboard. **Evidence an auditor can rely on.** For the observed
workflow you receive:

1. **Risk-action inventory** — the high-value actions in the workflow that warrant
   accountable approval (e.g. vendor bank-account changes, disbursements over a threshold,
   benefit redirects, overrides).
2. **A "would-have-required-signoff" report** — which observed actions would have triggered
   single or dual authorization under recommended policy, and which executed with approval
   evidence that *cannot* be independently verified today (**the gap, made visible**).
3. **Sample authorization receipts** — generated from your real action shapes, each one
   **offline-verifiable**, with a determination that reads either
   **PRESENT AND INDEPENDENTLY VERIFIED** or **ABSENT / UNVERIFIABLE — DO NOT RELY**.
4. **A recommended dual-control policy** — amount thresholds, new-beneficiary escalation,
   override rules — mapped to your existing approval chain and delegation-of-authority matrix.
5. **An executive + audit readout.**

Every receipt in the package is reproducible by your own auditor with one command, against
no server:

```
npx -y @emilia-protocol/crash-test verify ./authorization-receipt.json
```

*Want to see it before we start? The 90-second version runs on your laptop, offline:*
`npx -y @emilia-protocol/crash-test` *— a $2.4M disbursement to a new vendor account,
self-approval rejected, two named approvers, receipt issued, then verified six months later
with EMILIA deleted, and a forged copy rejected.*

## Scope

- **One workflow.** Pick the one that hurts: **vendor bank-account change**, **disbursement
  release**, **benefit payment redirect**, **caseworker/override**, or **procurement above
  threshold**.
- **Read-only.** We work from an export, a log feed, or a sample of recent high-value
  approvals — whatever's least disruptive. No production write access.
- **Fixed.** 60 days, one workflow, one readout. No scope creep.

## What we need from you

- A description of the one workflow and its current approval chain.
- A read-only sample of recent high-value actions in it (real or representative).
- **One introduction to the external auditor** who reviews these controls.

## Timeline

| Weeks | What happens |
|---|---|
| 1–2 | Map the workflow + approval chain; agree the risk-action inventory and draft policy thresholds. |
| 3–6 | Observe real actions; generate the would-have-required-signoff report and sample receipts. |
| 7–8 | Auditor review session; finalize the Workpaper Package; executive readout. |

## How we'll know it worked

Not traffic. Not receipts issued. **One sentence, in writing, from your external auditor:**

> *"This authorization-evidence package is audit-grade — I would rely on it in a controls review."*

That single confirmation is the outcome we're buying together. Everything else follows from it.

## Price

**$25,000 · 60 days · one workflow · fixed scope.**

## What this is — and is not

- **Is:** independent, offline-verifiable evidence that the required humans approved a
  specific action before it executed; an honest map of where that evidence is missing today.
- **Is not:** a change to your payment process during the pilot; a claim to eliminate fraud.
  EMILIA forces the highest-risk actions through accountable, action-bound authorization and
  leaves proof an outsider can check. It makes abuse **attributable and provable** — it does
  not make collusion among authorized people impossible, and it says so.

## Who this is for

County **treasurer / controller / finance director**, **program integrity**, **benefits
operations**, **procurement finance**, and **internal/external audit**.

---

**Next step:** a 30-minute call to pick the one workflow and confirm the auditor introduction.
**team@emiliaprotocol.ai** · https://www.emiliaprotocol.ai/quorum

*Protocol: open, Apache-2.0. Authorization-receipt format published as an IETF Internet-Draft
(draft-schrock-ep-authorization-receipts) with a multi-party companion (draft-schrock-ep-quorum)
and an independent offline verifier anyone can run. You are never asked to trust EMILIA.*
