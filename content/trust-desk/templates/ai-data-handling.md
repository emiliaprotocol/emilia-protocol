# AI Data Handling & Model Training Disclosure

**Vendor:** {{COMPANY}}
**Product:** {{PRODUCT_NAME}}
**Document version:** 1.0
**Effective date:** {{EFFECTIVE_DATE}}
**Next review:** {{NEXT_REVIEW_DATE}} (annual or on material change)
**Owner:** {{DATA_OFFICER_NAME}} ({{DATA_OFFICER_EMAIL}})

---

## 1. Purpose and scope

This document discloses, in plain language, exactly what {{COMPANY}} does with customer data when it is processed by an AI/ML system within the {{PRODUCT_NAME}} product surface. It is intended for enterprise buyers (particularly in financial services) whose security, risk, privacy, and compliance teams need to confirm that {{COMPANY}}'s use of AI does not introduce undisclosed data flows, unauthorized training on customer data, or model-based data leakage risk.

This document covers:

- What customer data is processed by AI/ML at inference time.
- Whether any customer data is used in model training, fine-tuning, RAG index construction, embedding, or evaluation.
- What third-party model providers are involved and under what data handling contract.
- How the customer can control, audit, and when appropriate delete AI-related data.

This document does NOT cover:

- Non-AI data flows (addressed in {{COMPANY}}'s general Privacy Policy).
- Security controls protecting AI infrastructure (addressed in the AI Access Control Policy).
- AI-driven decisions about the customer's own end-users (addressed in the AI Usage Disclosure if {{PRODUCT_NAME}} is customer-facing for the buyer's end-users).

---

## 2. Definitions

- **Customer data**: any data that the customer (or their end-users) submits to, generates within, or uploads to {{PRODUCT_NAME}}. Includes prompts, documents, chat history, uploaded files, and any metadata derived from that activity.
- **Inference**: using a model to generate a response to a customer request.
- **Training**: updating model weights using customer data, either for the foundation model itself or for a customer-specific fine-tune.
- **RAG (Retrieval-Augmented Generation)**: the practice of fetching relevant documents from an index at inference time and providing them as context to the model.
- **Embedding**: the numeric vector representation of text or other inputs, stored for retrieval or similarity search.
- **Subprocessor**: a third-party service that processes customer data on {{COMPANY}}'s behalf. For AI purposes this includes model providers (OpenAI, Anthropic, Google, etc.) and infrastructure providers (vector DBs, logging platforms).

---

## 3. What is processed at inference time

The following customer data is transmitted to AI/ML systems during normal product use:

| Data category | Transmitted to | Purpose | Retention at subprocessor |
|---|---|---|---|
| {{DATA_CATEGORY_1}} | {{MODEL_PROVIDER_1}} | {{PURPOSE_1}} | {{RETENTION_1}} |
| {{DATA_CATEGORY_2}} | {{MODEL_PROVIDER_2}} | {{PURPOSE_2}} | {{RETENTION_2}} |
| {{DATA_CATEGORY_3}} | {{MODEL_PROVIDER_3}} | {{PURPOSE_3}} | {{RETENTION_3}} |

Complete the table with every data category × subprocessor combination. A buyer's CISO will ask why a row is missing, so err on the side of listing more, not less.

### 3.1. Data NOT transmitted to AI systems

List explicitly what is excluded. Common exclusions in the fintech context:

- **Bank account numbers, routing numbers, and full card PANs** are redacted before any AI call (either via pre-processing tokenization or regex scrub, depending on product architecture).
- **SSN, EIN, and other government identifiers** are either redacted or, if required for a specific product function, transmitted only to a zero-retention API endpoint (see §5).
- **Raw transaction data with payee/payer PII** is {included | excluded | redacted}; specify which.

If a customer has configured elevated redaction (e.g., for a high-sensitivity workspace), additional categories are excluded. See customer-facing documentation at {{DOCS_REDACTION_URL}}.

---

## 4. What is used for training (and what is NOT)

### 4.1. Foundation model training

{{COMPANY}} **does not train foundation models on customer data.** {{COMPANY}} uses foundation models provided by {{MODEL_PROVIDERS}}, and contracts with each provider specify no training on {{COMPANY}}'s API traffic. Specifically:

- **OpenAI**: API access is via the Enterprise / Team tier or with the `data-retention: zero` header; training opt-out is contractually guaranteed.
- **Anthropic**: API access is via the commercial tier with training opt-out in the commercial agreement (Anthropic's commercial API terms explicitly exclude training on submitted data by default).
- **{{OTHER_PROVIDER}}**: {{OTHER_TERMS}}.

{{COMPANY}} maintains copies of each signed subprocessor agreement and can share them under NDA on request.

### 4.2. Customer-specific fine-tunes

{{EITHER_FINE_TUNE_DISCLOSURE_A_OR_B}}

**Option A (most vendors):**
{{COMPANY}} does not currently offer customer-specific fine-tuned models. All customers use the same base model configuration.

**Option B (if fine-tunes are offered):**
Customer-specific fine-tunes are offered under an explicit written opt-in. When a customer opts in:

- Training data scope, retention, and deletion terms are specified in the customer's fine-tune contract.
- Training data is logically separated from other customers' data at all stages of the pipeline.
- The resulting fine-tuned model is hosted in a dedicated deployment accessible only to the opting customer.
- On contract termination the fine-tuned model weights and training data are deleted within {{DELETION_SLA}} days.

### 4.3. RAG / retrieval indexes

Customer-uploaded documents and customer interaction history MAY be indexed for retrieval-augmented generation, only within that customer's tenant. RAG indexes:

- Are tenant-scoped; a query from customer A cannot retrieve customer B's data.
- Use {{EMBEDDING_MODEL}} for embeddings, with embedding vectors stored in {{VECTOR_DB}} under tenant-isolated namespaces.
- Are updated on {{UPDATE_FREQUENCY}} or on customer request.
- Are deleted within {{DELETION_SLA}} days of customer data deletion request or contract termination.

### 4.4. Evaluation and quality monitoring

{{COMPANY}} uses a combination of synthetic test data and customer data (under {{CONSENT_MODEL}}) to evaluate model quality. Customer data used in evaluation:

- Is anonymized / pseudonymized per §7 before any human review.
- Is never shared outside the {{COMPANY}} quality team.
- Is retained for no longer than {{EVAL_RETENTION}} days.
- Is not used to update production model weights.

---

## 5. Zero-retention / model-provider data handling

For each third-party model provider, {{COMPANY}} contracts for the following default data handling:

| Provider | Retention | Training | Region | Contract type |
|---|---|---|---|---|
| OpenAI | Zero retention (Enterprise tier) or ≤30 days for abuse monitoring | Opt-out | US (default), EU optional | Enterprise DPA |
| Anthropic | Zero retention on commercial API | No training | US (default) | Commercial Services Agreement + DPA |
| {{OTHER}} | {{RETENTION}} | {{TRAINING}} | {{REGION}} | {{CONTRACT}} |

Customer prompts and responses are transmitted to providers over TLS 1.3 and are not stored at {{COMPANY}} beyond the active session unless the customer has explicitly enabled transcript retention (see §6).

---

## 6. Customer controls

Customers can configure the following without a support ticket:

- **Disable AI features entirely** for a workspace or per-user.
- **Enable or disable transcript retention** ({{DEFAULT_RETENTION_STATE}} by default).
- **Request redaction of specific fields** from all AI calls at a workspace level.
- **Download a full audit log** of every AI call attributed to the customer's tenant.

Customers with Enterprise tier or above can additionally:

- **Route AI calls to a specific region** (US / EU / {{OTHER}}).
- **Bring their own API key** for the underlying model provider (disabling {{COMPANY}}'s pooled key entirely).
- **Require human-in-the-loop approval** for AI actions above a configurable risk threshold.

---

## 7. Redaction, anonymization, and data minimization

Before customer data leaves {{COMPANY}}'s boundary to a model provider, the following steps are applied in order:

1. **Structured PII redaction**: regex + ML-based classifier identifies and redacts SSN, EIN, card PAN, routing numbers, and phone numbers.
2. **Custom redaction rules**: customer-configured patterns (e.g., internal customer IDs) are redacted.
3. **Tokenization**: where semantic preservation is required, PII is replaced with stable tokens that can be re-expanded on the return path.
4. **Prompt scoping**: only the minimum fields needed for the task are included in the AI call; full record payloads are never forwarded whole.

Failure of any step fails the AI call closed — the request is not transmitted.

---

## 8. Deletion

Customer data deletion follows the global data-deletion SLA documented in {{COMPANY}}'s DPA, with the following AI-specific addenda:

- **Prompt and response logs**: deleted within {{DELETION_SLA}} days of customer request.
- **RAG index entries**: deleted within {{DELETION_SLA}} days of source document deletion.
- **Embedding vectors**: deleted with the RAG index entry they derive from.
- **Model provider copies**: for providers with any retention window (e.g., OpenAI's 30-day abuse window), {{COMPANY}} submits a deletion request to the provider on behalf of the customer.

Deletion is confirmed in writing to the customer's designated DPO / security contact within {{CONFIRMATION_SLA}} business days of completion.

---

## 9. Cross-border transfers

{{COMPANY}} customer data is processed in {{DEFAULT_REGION}} by default. Transfers to other regions (for model providers hosted elsewhere) are governed by:

- **EU → US**: Standard Contractual Clauses + EU-US Data Privacy Framework certification where the provider holds it.
- **Other**: SCCs or equivalent adequacy mechanism per the destination jurisdiction.

Customers can restrict processing region at the workspace level (see §6).

---

## 10. Incident notification

Data incidents involving AI systems follow the general {{COMPANY}} incident response process (see Incident Response Runbook). The AI-specific reporting SLA:

- **Customer notification for incidents involving customer data**: within {{INCIDENT_NOTIFICATION_SLA}} hours.
- **Regulatory notification where required**: per applicable regulation (GDPR 72h, state breach laws, etc.).

---

## 11. Change control

Material changes to this document — new subprocessor, change in training posture, change in data flow — are:

- Notified to customers {{CHANGE_NOTIFICATION_WINDOW}} days in advance via {{NOTIFICATION_CHANNEL}}.
- Subject to customer right-to-terminate as specified in the master agreement.
- Logged as signed attestations on {{COMPANY}}'s trust page at {{TRUST_PAGE_URL}}.

---

## 12. Verification and attestation

This document is cryptographically attested. The signed hash of this document is published on {{COMPANY}}'s AI Trust Page alongside timestamp, expiration, and signer identity. Buyers can verify document integrity at:

> **{{TRUST_PAGE_URL}}**

The canonical hash (SHA-256 over the NFC-normalized text of this document) is:

> `{{DOCUMENT_SHA256_HASH}}`

Attestation is refreshed on every material change and on annual review.

---

## Signatures

**Prepared by:** {{AUTHOR_NAME}}, {{AUTHOR_TITLE}}
**Reviewed by:** {{REVIEWER_NAME}}, {{REVIEWER_TITLE}} (Security / Privacy / Legal)
**Approved by:** {{EXECUTIVE_NAME}}, {{EXECUTIVE_TITLE}}

_Document attested and timestamped by AI Trust Desk on behalf of {{COMPANY}}._
