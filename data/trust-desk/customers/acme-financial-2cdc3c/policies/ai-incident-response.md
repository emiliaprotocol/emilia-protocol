# AI Incident Response Runbook

**Vendor:** Acme Financial
**Product:** Sentinel KYC AI
**Document version:** 1.0
**Effective date:** 2026-05-30
**Next review:** quarterly
**Owner:** Jane Okafor (security@acmefinancial.example)
**On-call:** security@acmefinancial.example (24/7 for Sev 1–2)

---

## 1. Scope

This runbook covers incidents involving the AI/ML components of Sentinel KYC AI. It extends Acme Financial's general incident response plan (at https://www.emiliaprotocol.ai/trust-desk/c/acme-financial-2cdc3c#incident-response) with AI-specific detection, triage, containment, and notification procedures.

AI-specific incidents include but are not limited to:

- **Prompt injection with impact** (unauthorized data disclosure or unauthorized action).
- **Model-generated data leak** (model returned PII or secrets it should not have had access to).
- **Unauthorized agent tool execution** (agent performed a Tier 2+ action without valid authorization).
- **Model provider incident** (downstream provider's breach, model corruption, or vulnerability).
- **Training data contamination** (customer data inadvertently used in model training).
- **Model behavior degradation** causing material harm (e.g., false-positive AML flags causing frozen accounts).
- **Jailbreak / safety-filter bypass** causing reputational or compliance exposure.
- **Third-party dependency vulnerability** (e.g., LangChain CVE, vector DB compromise).

---

## 2. Severity classification

| Severity | Definition | Example | SLA to customer notification |
|---|---|---|---|
| **SEV-1** | Active exploitation; customer data exposed OR unauthorized action succeeded; regulatory notification required. | Prompt injection led to extraction of another customer's data; agent moved funds without authorization. | 24 hours hours |
| **SEV-2** | High-confidence vulnerability; no confirmed exploitation OR impact limited to one tenant. | Prompt injection proven possible but no evidence of use in production; single-tenant agent misfired. | 48 hours hours |
| **SEV-3** | Defense layer triggered; no bypass. | Injection attempt blocked at input sanitization; audit log shows no customer data or production impact attempts from one source. | No customer notification unless pattern indicates targeted attack |
| **SEV-4** | Functional degradation without security impact. | Model quality drop; elevated error rate. | Status page update only |

Severity is assigned by the on-call Incident Commander at declaration and re-evaluated at each phase.

---

## 3. Detection sources

- **Inline defense telemetry**: input sanitizer flags, output filter blocks, tool-call rejections.
- **Audit log anomaly monitors**: unusual tool-call volume per session, cross-tenant access attempts, new geographic origin.
- **Model provider alerts**: breach or incident notifications from OpenAI, Anthropic, etc.
- **Dependency scanners**: GitHub Security Advisories, Snyk, Semgrep on the AI stack.
- **Customer reports**: inbound via security@Acme Financial.com or support escalation.
- **External security researchers**: via Acme Financial's responsible disclosure program at https://www.emiliaprotocol.ai/trust-desk/c/acme-financial-2cdc3c#disclosures.
- **Red-team findings**: internal or external engagements.

Every detection source routes to the same pager. The on-call receives a structured alert with detection source, severity hint, and initial evidence.

---

## 4. Response phases

### 4.1. Phase 1 — Declare (0–15 min)

- On-call triages the alert and either declares an incident or closes as noise.
- If declared: open a #security-incidents channel, page the Incident Commander rotation, and record the initial severity.
- Incident Commander assigns roles:
  - **IC**: coordinates overall response and makes decisions.
  - **Tech Lead**: drives containment and investigation.
  - **Comms Lead**: drafts customer and regulator notifications.
  - **Scribe**: maintains the incident timeline.
- Status page updated to "investigating" for SEV-1/2.

### 4.2. Phase 2 — Contain (15 min – 2 hours)

Containment is parallel to investigation. Actions in rough priority:

**For prompt-injection incidents:**
- Engage the per-feature kill switch for the affected tool or flow.
- Revoke session tokens for any sessions showing exploitation signals.
- Disable the attacker's tenant / API key if identified and not a customer themselves.

**For unauthorized-agent-action incidents:**
- Engage the per-tier kill switch (Tier 2 or Tier 3 as appropriate).
- Trigger reconciliation on affected resources (payments: freeze; data: snapshot before further changes).
- Lock down the session / user / tenant involved.

**For model-provider incidents:**
- Failover to secondary provider (Anthropic ↔ OpenAI swap).
- Document the provider's incident number and expected resolution.

**For training-data contamination:**
- This is almost always a SEV-1. Halt any training pipeline immediately.
- Identify the scope of contaminated data.
- Engage legal for breach disclosure analysis.

### 4.3. Phase 3 — Investigate (parallel to Contain)

- Collect forensic artifacts: audit logs, session traces, model provider logs (via support ticket if needed), user agents, IP origins.
- Reconstruct the attack path end-to-end.
- Identify:
  - What data was accessed.
  - What actions were taken.
  - What customers were affected.
  - Root cause: defense layer that failed and why.
- Document as the incident progresses in #security-incidents.

### 4.4. Phase 4 — Notify (SLAs per §2)

**Customer notification** (SEV-1/2):
- Named security contact on each affected customer's account (or general contact if none designated).
- Email + in-product banner.
- Content: what happened (plain language), what data was affected (specific), what Acme Financial is doing, what the customer should do (specific actions if any), who to contact for questions.
- Draft reviewed by legal before send.

**Regulatory notification** (as applicable):
- GDPR: within 72 hours of becoming aware, to the relevant supervisory authority.
- US state breach laws: per state-specific deadlines (often 30–60 days; CA, MA, NY have shorter windows).
- FFIEC / sectoral: per the buyer's regulated industry (banking / insurance / broker-dealer / etc.).
- Legal counsel approves every regulatory notification.

**Downstream partner notification**:
- Model providers: notify if incident involved their systems.
- Subprocessors: if incident requires their cooperation.

**Public disclosure**:
- For incidents requiring public disclosure, a post-mortem is published at Acme Financial's trust page at https://www.emiliaprotocol.ai/trust-desk/c/acme-financial-2cdc3c within 72 hours days of resolution.

### 4.5. Phase 5 — Eradicate and recover

- Apply the permanent fix (patch, config change, architectural change).
- Validate the fix against the adversarial test suite.
- Roll back the kill switch only after fix is verified.
- Resume normal operations; update status page.

### 4.6. Phase 6 — Post-mortem

- Blameless post-mortem within 5 business days business days.
- Format: what happened, detection, response timeline, contributing factors, root cause, customer impact, regulatory notifications, follow-up actions.
- Action items tracked in Linear with named owners and deadlines.
- Public summary published on trust page for SEV-1 and selected SEV-2.

---

## 5. Communication templates

### 5.1. Initial customer notification (SEV-1 data disclosure)

```
Subject: Security incident notification — INC-EXAMPLE

Jane Okafor,

We are notifying you of a security incident affecting Sentinel KYC AI that
may have impacted your account.

WHAT HAPPENED
On 2026-05-30 at 00:00 UTC UTC, we detected Sentinel KYC AI for community banks. Our
investigation confirmed the confirmed scope of impact.

WHAT DATA WAS INVOLVED
account data, customer-submitted content, usage metadata belonging to your organization was [READ | MODIFIED | EXPOSED].

WHAT WE HAVE DONE
- isolate affected components, revoke implicated credentials, enable enhanced logging
- preserve logs, reconstruct the action timeline, identify scope of impact
- patch root cause, rotate secrets, validate fix under test, monitor for recurrence

WHAT WE NEED FROM YOU
[SPECIFIC_CUSTOMER_ACTIONS_OR_"No action required on your side"]

We will follow up with a detailed post-mortem within 5 business days business days.

For urgent questions: security@Acme Financial.com or security@acmefinancial.example.

— Jane Okafor, on behalf of Acme Financial
```

### 5.2. Status page update (SEV-2/3)

```
[Investigating] AI reliability incident — INC-EXAMPLE
2026-05-30T05:02:30.232Z

We are investigating elevated error rates in the affected product feature.
Impact: the production AI product surface. No evidence of data compromise at this time.
Next update: within 24 hours of a material change.
```

### 5.3. Post-mortem header

```
# Post-mortem: INC-EXAMPLE — Sentinel KYC AI
Severity: SEV-120
Declared: 2026-05-30T05:02:30.232Z
Resolved: 2026-05-30T05:02:30.232Z
Impact: the production AI product surface
Root cause: Sentinel KYC AI for community banks
```

---

## 6. Roles and contacts

| Role | Name | Contact | Backup |
|---|---|---|---|
| Incident Commander | Jane Okafor | security@acmefinancial.example | Security on-call (secondary) |
| Tech Lead (AI) | Jane Okafor | security@acmefinancial.example | Engineering on-call |
| Security Lead | Jane Okafor | security@acmefinancial.example | Security on-call (secondary) |
| Legal / Regulatory | General Counsel | legal@acmefinancial.example | Outside counsel |
| Customer Comms | designated security contact | security@acmefinancial.example | Communications lead |
| External PR | Communications | press@acmefinancial.example | N/A |

Pager rotation: 24/7 for SEV-1/2; business hours for SEV-3/4. Rotation managed via PagerDuty.

---

## 7. Testing

- **Tabletop exercises**: semi-annual (quarterly recommended). Scenarios rotate through the incident classes in §1.
- **Live fire drills**: semi-annual (annually). Actual kill-switch execution in staging with full on-call rotation.
- **Chaos injection**: synthetic failures in model-provider dependencies run quarterly.

Results logged and used to refine this runbook. Last exercise: 2026-05-30.

---

## 8. Evidence preservation

For any incident rising to SEV-1 or potentially SEV-1:

- Snapshot affected infrastructure before mitigation where feasible.
- Preserve audit logs for 7 years minimum (typically 7 years for financial-services customers).
- Chain of custody maintained per Evidence is collected to a write-once store with documented chain of custody..
- Cooperation with law enforcement per legal counsel.

---

## 9. Verification and attestation

The signed hash of this runbook is published on Acme Financial's AI Trust Page:

> **https://www.emiliaprotocol.ai/trust-desk/c/acme-financial-2cdc3c**

Canonical SHA-256:

> `Available to the requesting party under NDA`

Document attested and timestamped by AI Trust Desk on behalf of Acme Financial.

---

## Signatures

**Prepared by:** Jane Okafor, Security Engineer
**Reviewed by:** Jane Okafor, Incident Commander
**Approved by:** Jane Okafor / Jane Okafor
