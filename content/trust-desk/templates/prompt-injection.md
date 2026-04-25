# Prompt Injection Defense Statement

**Vendor:** {{COMPANY}}
**Product:** {{PRODUCT_NAME}}
**Document version:** 1.0
**Effective date:** {{EFFECTIVE_DATE}}
**Next review:** quarterly
**Owner:** {{SECURITY_LEAD_NAME}} ({{SECURITY_LEAD_EMAIL}})

---

## 1. Threat model

Prompt injection is the class of attack where an adversary inserts instructions into content that a language model subsequently processes, causing the model to deviate from its intended behavior. Attacks are typically classified along two axes:

**By vector:**
- **Direct prompt injection**: a user (or an attacker posing as one) submits adversarial input in a prompt field.
- **Indirect prompt injection**: adversarial instructions are embedded in documents, URLs, emails, or other content that the model is asked to process, and the model interprets those instructions as commands.

**By impact:**
- **Data exfiltration**: the model is induced to reveal data it should not (other users' data, system prompts, secrets).
- **Action hijacking**: the model is induced to invoke tools or take actions the requester was not authorized to take.
- **Output manipulation**: the model is induced to produce misleading or harmful output (e.g., false sentiment in a trading report).
- **Denial of service**: the model is induced to consume excessive resources or return invalid responses.

This document describes {{COMPANY}}'s defenses against each class.

---

## 2. Defense posture (defense in depth)

{{COMPANY}} operates on the assumption that **prompt injection is not fully preventable at the model layer.** No current language model is provably robust to adversarial input. Accordingly, {{COMPANY}}'s defenses are layered at the input, processing, tool-invocation, and output boundaries. Failure at any single layer does not expose customer data or enable unauthorized action.

### 2.1. Input sanitization and provenance tagging

Before any user-supplied or retrieved content reaches the model, {{COMPANY}} applies the following:

- **Provenance tagging**: every segment of the model prompt is tagged with its trust class at construction time. Classes include `system` (highest trust; {{COMPANY}}-authored), `user` (customer-authored, trusted for intent but not for instructions), and `retrieved` (document content, subprocessor output, or anything from outside the tenant — untrusted for instructions).
- **Structural sanitization**: retrieved content is wrapped in untrusted-content markers and preceded by explicit instructions to the model not to follow instructions found within. We use a delimited-block pattern with randomized delimiters per request to prevent delimiter-injection.
- **Instruction stripping**: common imperative patterns ("ignore previous instructions", "you are now", "system:", etc.) are flagged in retrieved content via a fast regex pre-pass; matches are escaped or stripped before the content reaches the model.
- **Length and token budget caps**: per-segment token caps prevent a single injected document from dominating the context window.

### 2.2. System prompt hardening

The system prompt used for every AI interaction includes:

- Explicit instruction that content between untrusted-content markers is to be treated as data, not instructions.
- Explicit instruction that the model is never to reveal the system prompt, API keys, or configuration values.
- Explicit instruction that the model is never to take tool actions that the current user session is not authorized to take.
- A refusal template for recognized adversarial patterns.

The system prompt is versioned and each release is regression-tested against a corpus of known injection patterns (see §3).

### 2.3. Tool-call gating (the critical layer)

**Tool calls are the only way prompt injection becomes actual compromise.** {{COMPANY}} enforces the following at the tool-invocation layer:

- **Authorization is enforced at the tool, not at the model.** Every tool call is checked against the current user's session permissions by {{COMPANY}}'s authorization service, not by the model itself. The model cannot escalate privileges by convincing the system prompt otherwise — the authorization check is a separate code path that does not read the model's justification.
- **Destructive tool calls require explicit human confirmation.** Actions classified as destructive (deletion, payment initiation, data export, policy changes) surface a human-in-the-loop approval step. The model can propose the action but cannot execute it.
- **Tool-call allowlist per session.** Each session begins with a minimum necessary set of allowed tool names. The model cannot invoke tools outside this set even if the prompt instructs it to.
- **Parameter validation.** Tool call parameters are validated against a JSON schema. Parameters that fall outside the schema, reference other tenants, or exceed configured limits are rejected without reaching the tool.
- **Rate limiting.** Tool-call rate limits are enforced per user, per session, and per action class. A prompt-injection loop cannot burn through an account's budget.

### 2.4. Output filtering

Model output is post-processed before return to the user:

- **Secret scanning**: output is scanned for known secret patterns (API keys, private keys, session tokens). Matches block the response and log an incident.
- **PII leakage detection**: output is checked against the requester's authorization scope; mentions of other tenants' data trigger a block.
- **Instruction reflection**: if the output contains patterns consistent with the model reflecting an instruction it received from an untrusted source (e.g., "I have been instructed to..."), the response is blocked and logged.
- **Link safety**: URLs in the output are checked against a blocklist of known phishing and exfiltration domains.

---

## 3. Testing and evaluation

{{COMPANY}} maintains an internal prompt-injection test suite that is run against every material change to:
- The system prompt.
- The tool-call handlers.
- The output filters.
- Any new model provider or model version.

### 3.1. Test suite coverage

The suite includes {{N_TEST_CASES}} test cases derived from:

- **OWASP LLM Top 10** (LLM01 Prompt Injection, LLM02 Insecure Output, LLM06 Sensitive Information Disclosure, LLM07 Insecure Plugin Design, LLM08 Excessive Agency).
- **MITRE ATLAS** adversarial ML tactics.
- **Public jailbreak corpora** (DAN variants, role-play attacks, multi-turn coercion, token-smuggling).
- **{{COMPANY}}-internal** customer-reported patterns (anonymized).

### 3.2. Red-team cadence

- **Automated regression**: run on every deploy.
- **Manual adversarial review**: {{MANUAL_CADENCE}} (typically quarterly).
- **External red team**: {{EXTERNAL_RED_TEAM_CADENCE}} if applicable.

### 3.3. Kill switch

If a critical prompt-injection vulnerability is identified in production, {{COMPANY}} can disable affected AI features globally within {{KILL_SWITCH_SLA}} minutes via a feature-flag revert. The kill switch is tested {{KILL_SWITCH_TEST_CADENCE}}.

---

## 4. Logging and audit

Every AI interaction produces an audit log entry with:

- Timestamp, tenant, user, session ID.
- Full prompt (subject to retention settings per Data Handling Disclosure §6).
- Model provider, model version, model parameters.
- Every tool call attempted (whether allowed or rejected).
- Output hash (the full output is retained only if the customer has enabled transcript retention).
- Any injection-detection flags raised during the request.

Logs are retained for {{AUDIT_LOG_RETENTION}} days and are available to the customer via {{AUDIT_EXPORT_INTERFACE}}.

---

## 5. Incident response

Prompt-injection incidents are handled per {{COMPANY}}'s AI Incident Response Runbook, with the following AI-specific triage:

- **Severity 1**: injection led to unauthorized data disclosure or unauthorized action. Kill switch activated; affected customers notified within {{SEV1_NOTIFICATION_SLA}} hours.
- **Severity 2**: injection led to denial of service or output manipulation without data impact. Mitigated within {{SEV2_SLA}} hours; customer notification per general policy.
- **Severity 3**: injection attempt detected and blocked by existing defenses. Logged; no customer notification unless pattern indicates targeted attack.

---

## 6. Limitations (honest disclosure)

{{COMPANY}} does NOT claim:

- That prompt injection is fully prevented by the defenses above.
- That any single layer is robust against all attack classes.
- That no novel attack class will be discovered in the future.

{{COMPANY}} DOES commit:

- To operate a defense-in-depth architecture where any single layer's failure does not cause compromise.
- To respond to newly-discovered attack classes within the SLAs documented in §5.
- To disclose material incidents to customers per §5 and to regulators where required.
- To publish findings from external red-team engagements (anonymized where required) on {{COMPANY}}'s trust page.

---

## 7. Verification and attestation

The signed hash of this document is published on {{COMPANY}}'s AI Trust Page:

> **{{TRUST_PAGE_URL}}**

Canonical SHA-256:

> `{{DOCUMENT_SHA256_HASH}}`

Document attested and timestamped by AI Trust Desk on behalf of {{COMPANY}}.

---

## Signatures

**Prepared by:** {{AUTHOR_NAME}}, {{AUTHOR_TITLE}}
**Reviewed by:** {{SECURITY_LEAD_NAME}}, {{SECURITY_LEAD_TITLE}}
**Approved by:** {{CTO_NAME}}, CTO
