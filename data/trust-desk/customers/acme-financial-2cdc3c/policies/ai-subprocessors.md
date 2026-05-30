# AI Subprocessor & Data Flow Map

**Vendor:** Acme Financial
**Product:** Sentinel KYC AI
**Document version:** 1.0
**Effective date:** 2026-05-30
**Next review:** on subprocessor change or quarterly
**Owner:** Jane Okafor (security@acmefinancial.example)

---

## 1. Purpose

This document lists every third-party service that processes customer data in connection with AI/ML functionality, the data class they receive, their retention policy, their contractual training opt-out, their hosting region, and the data protection agreement governing the relationship. It is intended to answer the buyer question: **"Who sees our data when it flows through your AI, and under what contract?"**

---

## 2. AI subprocessors

### 2.1. Model providers

| Provider | Role | Data received | Retention | Training | Region | DPA |
|---|---|---|---|---|---|---|
| **OpenAI** | Primary LLM (GPT-4o / GPT-4 Turbo) | inference only; zero-retention enterprise tier | Zero retention (Enterprise) | Opt-out (contractual) | US (default), EU available | OpenAI Enterprise DPA, signed on file |
| **Anthropic** | Fallback / comparison LLM (Claude Sonnet) | inference only; zero-retention API tier | Zero retention (commercial API) | No training (default) | US | Anthropic Commercial Services Agreement + DPA, signed on file |
| None. | authorized operator | customer-submitted content processed at inference only | duration of contract, then deleted within 30 days | no customer data used for model training without explicit opt-in | United States | executed Data Processing Agreement |

**Customer-controlled override:** Enterprise tier customers may bring their own API key to any of the above providers, in which case no data flows through Acme Financial's pooled account.

### 2.2. Embedding and retrieval

| Service | Role | Data received | Retention | Region | DPA |
|---|---|---|---|---|---|
| **OpenAI** | Generates embedding vectors | customer content for retrieval only | duration of contract | United States | executed DPA with the embedding provider |
| **pgvector (self-hosted)** | Stores embeddings for retrieval | Embedding vectors only; no raw text | Per-customer; deleted with source documents | United States | self-hosted; no third-party DPA required |

**Tenant isolation**: embeddings and retrieval indexes are namespaced by tenant; queries from tenant A cannot retrieve tenant B's vectors.

### 2.3. AI observability, monitoring, and evaluation

| Service | Role | Data received | Retention | DPA |
|---|---|---|---|---|
| **Datadog** | LLM call traces for debugging and quality monitoring | Prompts and responses, sensitive operational details redacted; available under NDA | 30 days | executed DPA with the observability provider |
| **internal evaluation harness** | Offline evaluation and regression testing | Synthetic data + customer data under opt-in only | 90 days | executed DPA with the evaluation provider |

### 2.4. Infrastructure (supporting AI but not model-aware)

| Service | Role | Data received | Retention | Region | DPA |
|---|---|---|---|---|---|
| **AWS (or your primary cloud)** | Compute and storage | Customer data at rest and in transit | Per data-class policy | us-east-1 | AWS DPA |
| **Datadog** | Application logs | Redacted log entries; no raw customer content | 12 months | United States | executed DPA with the logging provider |
| **self-hosted analytics** | Product analytics | Event metadata only; no prompt content | 14 months | United States | executed DPA with the analytics provider |

---

## 3. Data flow diagram

```
┌──────────────────┐
│  Customer User   │
└────────┬─────────┘
         │  HTTPS (TLS 1.3)
         ▼
┌──────────────────────────────────────────────┐
│  Acme Financial API gateway                     │
│  — Auth (per §4 Agent Access Control)        │
│  — Rate limiting                             │
│  — Input sanitization + PII redaction        │
└────────┬─────────────────────────────────────┘
         │
         ├────► Datadog (redacted audit log)
         │
         ▼
┌──────────────────────────────────────────────┐
│  Acme Financial AI orchestrator                 │
│  — Prompt assembly (provenance-tagged)       │
│  — Tool-call gating                          │
│  — Output filtering                          │
└────────┬─────────────────────────────────────┘
         │
         │  (retrieval step)                                (inference step)
         ├────► Vector DB (pgvector (self-hosted))                   ├──► Model provider (OpenAI | Anthropic)
         │       tenant-scoped namespace                    │     zero retention, no training
         │       United States                       │     United States
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

1. **Customer notification** 30 days days in advance via email + in-app.
2. **Update of this document** with new effective date and change-log entry.
3. **Re-signed attestation** on Acme Financial's trust page.
4. **Right to terminate** per the customer's master agreement for customers who object to the change.

---

## 5. Regional and cross-border transfer

Default processing region: **us-east-1**.

For customers with regional residency requirements, Acme Financial can configure:

- **EU residency**: all AI calls routed to EU-hosted model endpoints; vector DB in EU region; logs in EU region. Standard Contractual Clauses in place for any residual US transfers.
- **US residency**: all customer data is processed and stored in US regions
- **none**: no data is processed outside the United States

A customer can request regional configuration at onboarding or at any time thereafter; propagation takes 30 days business days.

---

## 6. Subprocessor audit rights

Enterprise customers may exercise audit rights per their master agreement. Standard terms:

- Acme Financial provides its most recent SOC 2 Type II report for each audit-relevant subprocessor.
- Acme Financial provides summary pen-test reports on subprocessors under NDA.
- On-site audits are not standard; a remote audit / questionnaire exchange is offered annually.

---

## 7. Verification and attestation

The signed hash of this subprocessor list is published on Acme Financial's AI Trust Page:

> **https://www.emiliaprotocol.ai/trust-desk/c/acme-financial-2cdc3c**

Canonical SHA-256:

> `Available to the requesting party under NDA`

Each subprocessor change produces a new attestation; prior versions remain accessible in the trust page's change log.

---

## Signatures

**Prepared by:** Jane Okafor, Security Engineer
**Reviewed by:** Jane Okafor, Data Protection Officer
**Approved by:** General Counsel, General Counsel
