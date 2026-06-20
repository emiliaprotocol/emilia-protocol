<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA for SOX Controls

How EMILIA Protocol provides pre-execution accountability and audit-grade evidence for the financial-reporting controls (ICFR) most exposed to fraud and error: vendor master changes, payment authorization, and segregation of duties.

> EMILIA proves that a named human authorized a specific irreversible action under a stated policy before it executed, and produces a receipt anyone can verify offline. It does not assert the decision was correct, lawful, or wise, and one-time-use and revocation are relying-party server state.

---

## Control area 1 — Vendor master / payment-destination changes

| | |
|---|---|
| **Risk** | A vendor's bank account is changed (by a person, a compromised account, or an automated/AI process) and payments are redirected — the canonical business-email-compromise and internal-fraud vector. |
| **Current control failure** | IAM proves the actor authenticated; the ticketing/ERP workflow records an "approved" status. Neither proves a *named* authorized human approved *this exact change* before it took effect, and the approval record lives in the same system whose integrity is in question. |
| **EMILIA control** | The change is gated before execution. Policy requires a named approver (and a second approver above a threshold); the approver signs off on the exact change (old account → new account) on their own device; self-approval is rejected; a one-time receipt is consumed. |
| **Evidence generated** | A signed receipt binding actor · authority chain · exact-action hash (the specific account change) · policy version · approver identity · timestamp · nonce · one-time-consume event — verifiable offline with open-source code. |
| **Auditor question answered** | "Who approved this vendor bank-account change, under what policy version, and could that approval be reused or replayed?" → answered from the receipt, independent of the ERP. |
| **Integration pattern** | EMILIA Gate in front of the vendor-master write path (ERP/AP system); Observe mode first (report-only), then Enforce. |

## Control area 2 — Payment / wire authorization

| | |
|---|---|
| **Risk** | A high-value disbursement is released without verifiable proof that an authorized human approved that exact payment. |
| **Current control failure** | "Approved" flags and audit logs are post-hoc and operator-controlled; they don't bind the approval to the exact payment parameters before release. |
| **EMILIA control** | Amount-tiered policy (e.g., single approver under a limit, dual approver above it) enforced pre-release; the receipt binds the exact payee, amount, and destination. |
| **Evidence generated** | Per-payment receipt with the approval tier, both approver identities (where dual), and the exact-action hash. |
| **Auditor question answered** | "Show me, for this wire, the named approvals required and obtained, bound to these exact parameters." |
| **Integration pattern** | Gate on the payment-release API; tiers expressed as hash-pinned policy. |

## Control area 3 — Segregation of duties (SoD)

| | |
|---|---|
| **Risk** | The same individual initiates and approves a financial action. |
| **Current control failure** | SoD is often enforced by role configuration that can drift, and violations surface only in periodic review. |
| **EMILIA control** | Self-approval is rejected by construction at the moment of action — the initiator cannot be the signoff principal; the binding is cryptographic, not configuration. |
| **Evidence generated** | The receipt shows distinct initiator and approver identities bound to the action. |
| **Auditor question answered** | "Prove initiation and approval were performed by different authorized people for this transaction." |
| **Integration pattern** | SoD expressed in policy; enforced in the Gate ceremony. |

---

*This document maps EMILIA controls to common SOX/ICFR objectives. It is not legal, audit, or accounting advice; control design and sufficiency are determined by the entity and its auditors.*
