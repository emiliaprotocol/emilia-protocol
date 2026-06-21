# @emilia-protocol/crash-test

**One command. Two acts. The whole protocol becomes obvious.**

```
npx -y @emilia-protocol/crash-test
```

### Act 1 — Authorization (at the county, today)
An AI finance agent proposes a **$2,400,000** grant disbursement to a **new** vendor
bank account. Self-approval is rejected. The **Finance Director** approves on her
device; the **Controller** approves on his. A two-person quorum holds. An
**authorization receipt** is issued.

### Act 2 — Reliance (the auditor's desk, six months later)
The network is down. The EMILIA service is deleted. The database is gone. The
auditor has **one file**. It still verifies — offline, against no one's server —
and a **forged copy is rejected**. The auditor gets a workpaper.

> Act 2 is the product. Act 1 is the setup.

## What you get

The run writes an **Auditor Workpaper Package** to `./emilia-workpaper/`:

- `authorization-receipt.json` — the evidence the auditor keeps.
- `verification-report.md` — an audit-grade determination with a single bolded
  verdict: **PRESENT AND INDEPENDENTLY VERIFIED** or **ABSENT / UNVERIFIABLE — DO
  NOT RELY** — the absence made visible, not a silent gap.

## Verify a receipt yourself (the auditor's path)

```
npx -y @emilia-protocol/crash-test verify ./emilia-workpaper/authorization-receipt.json
```

Exit code `0` = verified, `1` = do not rely. No network, no account, no API key.
The check recomputes the action hash from the action as filed, runs the real
**EP-QUORUM-v1** predicate (`verifyQuorum` from `@emilia-protocol/verify`), and
checks the operator's commit signature.

## What it proves, and does not prove

**Proves:** the named approvers, holding their own device keys, each signed *this
exact action* under the stated policy, in order, before execution — and no party,
including EMILIA, could forge or alter it undetected.

**Does not prove:** absence of collusion or coercion among distinct approvers;
that the displayed action matched intent (presentation integrity); the real-world
identity behind each enrolled approver. Stated, not claimed solved.

## Honesty note

The approver signatures here are **real ES256 device-class (Class A) WebAuthn
assertions**, minted locally so the demo runs without hardware. In production they
originate on each approver's own device. The crash test makes **no network calls** —
that is the entire point of Act 2.

Spec: [draft-schrock-ep-quorum](https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/) ·
[draft-schrock-ep-authorization-receipts](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/)

Apache-2.0
