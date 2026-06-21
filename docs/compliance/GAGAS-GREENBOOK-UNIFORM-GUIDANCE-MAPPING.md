# EP Compliance Mapping: U.S. Government Audit & Internal-Control Standards

**Version:** 1.0
**Date:** 2026-06-21
**Protocol:** EMILIA Protocol v1.0
**Frameworks:** GAO Green Book (Standards for Internal Control in the Federal Government) · GAGAS (Government Auditing Standards / the GAO "Yellow Book") · Uniform Guidance (2 CFR Part 200)

---

## Overview

This document maps the EP **authorization receipt** to the standards U.S. government auditors actually work under — so an auditor can cite EP evidence in an audit program without commissioning a custom legal memo. It is the government counterpart to the existing NIST AI RMF, EU AI Act, and SOC 2 mappings in this directory.

EP provides **independently verifiable evidence that a high-risk action was authorized** — by named, distinct, accountable humans, bound to the exact action, before execution. It is conservative by design: EP **provides evidence relevant to** these controls; it does **not** by itself establish an entity's overall compliance, which remains the auditor's determination.

---

## 1. GAO Green Book — Standards for Internal Control in the Federal Government (GAO-14-704G; 2025 update GAO-25-107721)

Uniform Guidance 2 CFR 200.303 requires recipients of federal awards to maintain internal control aligned with the Green Book (or the COSO framework). EP evidence is most directly relevant to the **Control Activities** component.

| Green Book component / principle | Requirement | EP evidence |
|---|---|---|
| Principle 10 — Control Activities | Management designs control activities (including authorization and approval) to achieve objectives and respond to risks | An EP authorization receipt is cryptographic proof that the designed approval control *actually operated* for one exact high-risk action — bound to the action, the policy version, and the approver(s). |
| Control Activities — segregation of duties | Divide key duties so no single individual controls all aspects of a transaction | EP-QUORUM enforces *distinct* approvers as a fail-closed predicate and bars self-approval (the initiator cannot approve its own action) — provable, not asserted. |
| Control Activities — authorization | Transactions are authorized and executed by personnel acting within their authority | The receipt binds a named approver and role to the exact action; an *ordered* quorum proves a chain of authority (e.g., program officer → authorizing official → inspector general). |
| Principle 11 — Control activities over information systems | Design control activities over the entity's information systems | EP can gate the action at the system of record (execution-side enforcement class) and produces tamper-evident evidence the auditee's own systems cannot alter undetectably. |
| Principles 14–15 — Information & Communication | Use and communicate quality information to achieve objectives | The receipt is portable, offline-verifiable evidence communicable to auditors, oversight bodies, appellants, and the public without trusting the auditee's systems. |
| Principle 16 — Monitoring | Establish monitoring; evaluate and remediate deficiencies | EP observe-mode produces a "would-have-required-signoff" report — a monitoring artifact quantifying, on real traffic, which high-risk actions lacked verifiable authorization. |

The **2025 Green Book update prioritizes fraud and improper-payments risk** — precisely the failure EP addresses: a payment authorized by no accountable, provable human.

---

## 2. GAGAS — Generally Accepted Government Auditing Standards (the GAO "Yellow Book")

GAGAS requires audit evidence to be **sufficient and appropriate**, where appropriateness turns on **relevance and reliability** — and evidence the auditor can obtain or test **independently of the auditee** is the most reliable kind.

An EP receipt is reliable in exactly this sense: the auditor verifies it **offline, with open-source code, without relying on the auditee's systems or representations**, and a forged or altered receipt fails verification deterministically. It supports a **test of the operating effectiveness** of the authorization control over a high-risk action — with evidence that is tamper-evident by construction rather than dependent on the entity's own logs.

---

## 3. Uniform Guidance — 2 CFR Part 200 (federal awards)

| Provision | Requirement | EP evidence |
|---|---|---|
| § 200.303 — Internal controls | Effective internal control over federal awards, aligned with the Green Book / COSO | EP provides verifiable evidence that the authorization control operated for high-risk award actions — disbursements, payee/bank-account changes, caseworker overrides. |
| § 200.302 — Financial management | Effective control and accountability; funds used **solely for authorized purposes**; written procedures for determining allowability | The receipt is per-action proof that an authorized official approved the exact disbursement — "used for authorized purposes" made checkable transaction-by-transaction, not by sampling assertions. |
| Subpart F — Audit Requirements (Single Audit) | Auditors report significant deficiencies / material weaknesses in internal control over compliance for major programs | The **absence** of a receipt for an action that policy gates on signoff is itself evidence the control was bypassed; its **presence** is independently verifiable evidence the control operated. EP turns this control from testimony into checkable evidence. |

---

## What this evidence does — and does not — establish (stated plainly)

**Establishes:** that the required, distinct, authorized humans approved *this exact action*, in order where required, before it executed, with evidence no party — including EMILIA — can forge or alter undetectably; verifiable offline.

**Does not establish:** the *propriety* of the underlying decision; the real-world *identity* behind an enrolled approver (an enrollment / identity-proofing control — e.g., PIV/CAC or Login.gov — layered separately); the entity's *overall* compliance (the auditor's determination); nor the absence of collusion among the required approvers (EP makes such events *attributable*, not impossible).

---

*This mapping is a technical aid for audit planning, not a legal or professional-standards opinion. Frameworks referenced: GAO Green Book (GAO-14-704G; 2025 update GAO-25-107721); GAGAS / Government Auditing Standards (the Yellow Book); 2 CFR Part 200 §§ 200.302–200.303 and Subpart F. Companion mappings: NIST-AI-RMF-MAPPING.md, EU-AI-ACT-MAPPING.md, EMILIA-SOC2-EVIDENCE-MAP.md.*
