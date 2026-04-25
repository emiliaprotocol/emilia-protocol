# AI Subprocessor & Data Flow Map

**Vendor:** {{COMPANY}}
**Product:** {{PRODUCT_NAME}}
**Document version:** 1.0
**Effective date:** {{EFFECTIVE_DATE}}
**Next review:** on subprocessor change or quarterly
**Owner:** {{DATA_OFFICER_NAME}} ({{DATA_OFFICER_EMAIL}})

---

## 1. Purpose

This document lists every third-party service that processes customer data in connection with AI/ML functionality, the data class they receive, their retention policy, their contractual training opt-out, their hosting region, and the data protection agreement governing the relationship. It is intended to answer the buyer question: **"Who sees our data when it flows through your AI, and under what contract?"**

---

## 2. AI subprocessors

### 2.1. Model providers

| Provider | Role | Data received | Retention | Training | Region | DPA |
|---|---|---|---|---|---|---|
| **OpenAI** | Primary LLM (GPT-4o / GPT-4 Turbo) | {{OPENAI_DATA_SCOPE}} | Zero retention (Enterprise) | Opt-out (contractual) | US (default), EU available | OpenAI Enterprise DPA, signed {{OPENAI_DPA_DATE}} |
| **Anthropic** | Fallback / comparison LLM (Claude Sonnet) | {{ANTHROPIC_DATA_SCOPE}} | Zero retention (commercial API) | No training (default) | US | Anthropic Commercial Services Agreement + DPA, signed {{ANTHROPIC_DPA_DATE}} |
| {{OTHER_MODEL_PROVIDER}} | {{ROLE}} | {{DATA_SCOPE}} | {{RETENTION}} | {{TRAINING}} | {{REGION}} | {{DPA}} |

**Customer-controlled override:** Enterprise tier customers may bring their own API key to any of the above providers, in which case no data flows through {{COMPANY}}'s pooled account.

### 2.2. Embedding and retrieval

| Service | Role | Data received | Retention | Region | DPA |
|---|---|---|---|---|---|
| **{{EMBEDDING_PROVIDER}}** | Generates embedding vectors | {{EMBEDDING_INPUT_SCOPE}} | {{EMBEDDING_RETENTION}} | {{EMBEDDING_REGION}} | {{EMBEDDING_DPA}} |
| **{{VECTOR_DB}}** | Stores embeddings for retrieval | Embedding vectors only; no raw text | Per-customer; deleted with source documents | {{VECTOR_DB_REGION}} | {{VECTOR_DB_DPA}} |

**Tenant isolation**: embeddings and retrieval indexes are namespaced by tenant; queries from tenant A cannot retrieve tenant B's vectors.

### 2.3. AI observability, monitoring, and evaluation

| Service | Role | Data received | Retention | DPA |
|---|---|---|---|---|
| **{{OBSERVABILITY_PROVIDER}}** | LLM call traces for debugging and quality monitoring | Prompts and responses, {{REDACTION_STATUS}} | {{OBSERVABILITY_RETENTION}} | {{OBSERVABILITY_DPA}} |
| **{{EVAL_PROVIDER}}** | Offline evaluation and regression testing | Synthetic data + customer data under opt-in only | {{EVAL_RETENTION}} | {{EVAL_DPA}} |

### 2.4. Infrastructure (supporting AI but not model-aware)

| Service | Role | Data received | Retention | Region | DPA |
|---|---|---|---|---|---|
| **AWS (or your primary cloud)** | Compute and storage | Customer data at rest and in transit | Per data-class policy | {{PRIMARY_REGION}} | AWS DPA |
| **{{LOGGING_PROVIDER}}** | Application logs | Redacted log entries; no raw customer content | {{LOG_RETENTION}} | {{LOG_REGION}} | {{LOG_DPA}} |
| **{{ANALYTICS_PROVIDER}}** | Product analytics | Event metadata only; no prompt content | {{ANALYTICS_RETENTION}} | {{ANALYTICS_REGION}} | {{ANALYTICS_DPA}} |

---

## 3. Data flow diagram

```
┌──────────────────┐
│  Customer User   │
└────────┬─────────┘
         │  HTTPS (TLS 1.3)
         ▼
┌──────────────────────────────────────────────┐
│  {{COMPANY}} API gateway                     │
│  — Auth (per §4 Agent Access Control)        │
│  — Rate limiting                             │
│  — Input sanitization + PII redaction        │
└────────┬─────────────────────────────────────┘
         │
         ├────► {{LOGGING_PROVIDER}} (redacted audit log)
         │
         ▼
┌──────────────────────────────────────────────┐
│  {{COMPANY}} AI orchestrator                 │
│  — Prompt assembly (provenance-tagged)       │
│  — Tool-call gating                          │
│  — Output filtering                          │
└────────┬─────────────────────────────────────┘
         │
         │  (retrieval step)                                (inference step)
         ├────► Vector DB ({{VECTOR_DB}})                   ├──► Model provider (OpenAI | Anthropic)
         │       tenant-scoped namespace                    │     zero retention, no training
         │       {{VECTOR_DB_REGION}}                       │     {{MODEL_REGION}}
         │                                                  │
         │                                                  ◄──── model response
         │                                                        (output filter applied)
         ▼
┌──────────────────────────────────────────────┐
│  Response to customer                        │
└──────────────────────────────────────────────┘
```

Detailed interactive version available on request under NDA.

---

## 4. Change control for subprocessors

Adding, removing, or materially changing any subprocessor listed above triggers:

1. **Customer notification** {{CHANGE_NOTIFICATION_WINDOW}} days in advance via {{NOTIFICATION_CHANNEL}}.
2. **Update of this document** with new effective date and change-log entry.
3. **Re-signed attestation** on {{COMPANY}}'s trust page.
4. **Right to terminate** per the customer's master agreement for customers who object to the change.

---

## 5. Regional and cross-border transfer

Default processing region: **{{DEFAULT_REGION}}**.

For customers with regional residency requirements, {{COMPANY}} can configure:

- **EU residency**: all AI calls routed to EU-hosted model endpoints; vector DB in EU region; logs in EU region. Standard Contractual Clauses in place for any residual US transfers.
- **US residency**: {{US_RESIDENCY_NOTES}}
- **{{OTHER_REGION}}**: {{OTHER_REGION_NOTES}}

A customer can request regional configuration at onboarding or at any time thereafter; propagation takes {{REGIONAL_CONFIG_SLA}} business days.

---

## 6. Subprocessor audit rights

Enterprise customers may exercise audit rights per their master agreement. Standard terms:

- {{COMPANY}} provides its most recent SOC 2 Type II report for each audit-relevant subprocessor.
- {{COMPANY}} provides summary pen-test reports on subprocessors under NDA.
- On-site audits are not standard; a remote audit / questionnaire exchange is offered annually.

---

## 7. Verification and attestation

The signed hash of this subprocessor list is published on {{COMPANY}}'s AI Trust Page:

> **{{TRUST_PAGE_URL}}**

Canonical SHA-256:

> `{{DOCUMENT_SHA256_HASH}}`

Each subprocessor change produces a new attestation; prior versions remain accessible in the trust page's change log.

---

## Signatures

**Prepared by:** {{AUTHOR_NAME}}, {{AUTHOR_TITLE}}
**Reviewed by:** {{DATA_OFFICER_NAME}}, {{DATA_OFFICER_TITLE}}
**Approved by:** {{LEGAL_LEAD_NAME}}, {{LEGAL_LEAD_TITLE}}
