<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA for Treasury & Payment Controls

Pre-execution accountability for the treasury actions where money moves irreversibly: vendor bank-detail changes, wire releases, and payee onboarding — the actions targeted by business email compromise (BEC) and authorized-push-payment fraud.

> EMILIA proves a named human authorized a specific irreversible action under a stated policy before execution, with a receipt verifiable offline. It does not judge whether the payment was correct; one-time-use and revocation are relying-party server state.

---

## Control area 1 — Vendor bank-account changes (the BEC vector)

| | |
|---|---|
| **Risk** | An attacker (or a manipulated agent) changes a payee's bank details; subsequent legitimate-looking payments are redirected. |
| **Current control failure** | Callback verification is manual and inconsistently performed; the "we verified" step leaves no tamper-evident, action-bound artifact. |
| **EMILIA control** | The bank-detail change is held pre-execution until a named treasury approver signs off on the exact change (old → new) on their device; a one-time receipt is consumed; replay of the same authorization fails. |
| **Evidence generated** | Receipt binding the exact account change, approver identity, policy version, nonce, expiry, and consume event. |
| **Auditor question answered** | "Who authorized changing this payee's account, to these exact details, and was that authorization single-use?" |
| **Integration pattern** | EMILIA Gate on the payee-master write path (ERP/TMS/AP); Observe → Enforce. |

## Control area 2 — Wire / high-value release

| | |
|---|---|
| **Risk** | A high-value wire is released without verifiable, action-bound human authorization at the moment of release. |
| **Current control failure** | Maker-checker flags are operator-state and not cryptographically bound to the exact wire. |
| **EMILIA control** | Amount-tiered approval (single/dual) enforced before release; receipt binds payee, amount, destination, and the approver(s). |
| **Evidence generated** | Per-wire receipt with tier and approver identities bound to exact parameters. |
| **Auditor question answered** | "For this wire, show the required approvals obtained and bound to these exact details before funds moved." |
| **Integration pattern** | Gate on the wire-release API; tiers as hash-pinned policy. |

## Control area 3 — New payee onboarding

| | |
|---|---|
| **Risk** | A fraudulent payee is added and used before controls catch it. |
| **Current control failure** | Onboarding approvals are workflow flags without action-bound, offline-verifiable evidence. |
| **EMILIA control** | Payee creation gated; named approval bound to the payee identity/details; receipt issued. |
| **Evidence generated** | Receipt binding the new payee record to a named approver and policy. |
| **Auditor question answered** | "Who approved adding this payee, under what policy?" |
| **Integration pattern** | Gate on payee-create; observe-mode inventory of additions first. |

---

*Maps EMILIA to common treasury/payment control objectives. Not legal or audit advice; control sufficiency is determined by the entity and its auditors.*
