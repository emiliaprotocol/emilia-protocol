# EMILIA Evidence-Capability Mapping to the EU AI Act

**Version:** 2.0
**Date:** 2026-07-17
**Regulation:** Regulation (EU) 2024/1689
**Status:** Engineering crosswalk, not legal advice or a compliance determination

## 1. Scope

This document maps technical evidence produced by EMILIA to selected EU AI Act
assessment questions. It does not say that deploying EMILIA satisfies an
Article, that every action needs a receipt, or that EMILIA determines whether a
system is high-risk.

The strongest fit is narrow:

- **Article 12:** action-level logging and traceability evidence;
- **Article 14:** evidence that a configured human-authorization or refusal
  control operated before a specific action;
- **Articles 9, 11, and 15:** supporting engineering evidence about the
  authorization control itself.

Articles 10 and 13 require controls EMILIA does not provide.

## 2. Current application timeline

The Commission's current AI Act implementation page states:

- the Act entered into force on **1 August 2024**;
- prohibited practices and AI-literacy duties applied from **2 February 2025**;
- governance and general-purpose AI duties applied from **2 August 2025**;
- transparency rules apply from **August 2026**;
- rules for Annex III high-risk systems apply from **2 December 2027**;
- rules for high-risk systems integrated into regulated products apply from
  **2 August 2028**.

Primary source:
<https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai>.
Classification, provider/deployer role, exceptions, and applicable duties are
fact-specific and should be confirmed with qualified counsel.

## 3. What the evidence establishes

For an `EP-RECEIPT-v1` Trust Receipt verified against relying-party-pinned keys,
the verifier can establish:

1. the Action Object has not changed since it was signed;
2. each approval context commits to that action and a stated policy digest;
3. each signoff verifies under the pinned approver key;
4. initiator exclusion, distinct approvers, and the declared threshold hold;
5. the receipt is included under a signed log checkpoint;
6. issuance, signing, and commitment fall within the declared windows.

In strict Class-A mode, the verifier also checks the WebAuthn relying-party ID
and user-presence/user-verification flags. The Gate can reserve and consume a
receipt once, bind execution fields to the authorized action, and append allow
and refuse decisions to a tamper-evident evidence log.

These properties do **not** establish:

- that a key was correctly enrolled to a legal identity;
- that the person understood the display or was free from coercion;
- that the action was wise, lawful, safe, fair, or accurate;
- that every relevant action was routed through the Gate;
- that retained records satisfy a deployment's full retention duties;
- that the AI system as a whole complies with the Act.

## 4. Article-by-article capability map

| Provision | Evidence fit | What EMILIA can contribute | What remains outside or deployment-specific |
|---|---|---|---|
| **Art. 9 - risk management** | Supporting | Versioned action policy digest; fail-closed refusal reasons; adversarial and fault-schedule tests for the authorization control | Risk identification, proportionality, residual-risk acceptance, lifecycle governance, and system-level testing |
| **Art. 10 - data governance** | Outside scope | A receipt can bind a digest of a referenced dataset or assessment | Data relevance, representativeness, bias, collection practices, and data-quality governance |
| **Art. 11 - technical documentation** | Supporting | Public implementation, schemas, vectors, security-case manifest, and explicit model assumptions | System-specific intended purpose, architecture, performance, risk, change, and conformity documentation |
| **Art. 12 - logging** | Direct evidence fit | Signed exact-action authorization records; typed refusals; tamper-evident evidence-log chain; deterministic period reports | Log completeness, durable retention, access control, operational monitoring, and routing every relevant event through the enforcement point |
| **Art. 13 - transparency** | Mostly outside scope | Human-inspectable action and policy references may support an explanation record | Instructions for use, system limitations, user notices, output interpretation, and disclosure duties |
| **Art. 14 - human oversight** | Direct evidence fit | Pre-execution Class-A signoff; exact-action binding; typed refusal/interruption evidence; M-of-N distinct-signoff option; one-time consumption | Oversight design adequacy, competence, authority assignment, automation-bias controls, safe-state design, comprehension, and proportionality |
| **Art. 15 - accuracy, robustness, cybersecurity** | Supporting | Named protocol invariants; signature and binding checks; replay and concurrency tests; fail-closed storage behavior | AI accuracy, model robustness, end-to-end cybersecurity, host compromise, supply-chain governance, and incident response |
| **Art. 26 - deployer duties** | Supporting | Evidence export that a configured authorization control operated over a stated period | Correct use, monitoring, human resources, DPIA/fundamental-rights impact work, incident reporting, and deployer governance |

## 5. Implementation evidence

| Property | Implementation | Re-performable evidence |
|---|---|---|
| Exact-action receipt verification | `packages/verify/index.js` (`verifyTrustReceipt`) | Trust Receipt test and conformance suites |
| Class-A WebAuthn binding | `packages/verify/index.js` strict mode | RP ID, UP, UV, key-window, and policy-hash checks |
| One-time execution | `packages/gate/store.js`, `packages/gate/index.js` | concurrency, crash, response-loss, rollback, and linearizability tests |
| Authorized/executed field agreement | `packages/gate/execution-binding.js` | fail-closed execution-binding tests |
| M-of-N human authorization | `packages/verify/quorum.js` | shared quorum vectors and initiator-exclusion tests |
| Tamper-evident decision log | `packages/gate/evidence.js` | chain re-verification and strict-sink failure tests |
| Article 14 period report | `packages/gate/reports/art14.js` | deterministic pack tests; honesty notice is mandatory |
| Standing grant composition | `packages/verify/consent-grant.js` | grant, revocation, binding, and profile-constraint tests |

Current generated counts and exact model scope live in
`lib/proof-stats.json`, `security/claims.v1.json`, and `PROOF_STATUS.md`.
Those generated artifacts, rather than prose copied into this document, are the
source of truth.

## 6. Recommended use in an assessment

1. Define the consequential action classes and material fields.
2. Document which actions require one approver, Class-A user verification, or a
   distinct-human quorum.
3. Pin the approver directory, policy digest, relying-party ID, log key, and
   any standing-authority or revocation inputs.
4. Demonstrate a valid approval, a human refusal, an altered action, a replay,
   a storage failure, and an execution-field mismatch.
5. Export the receipts, evidence log, and `EP-GATE-ART14-PACK-v1`.
6. Have an independent assessor reproduce verification and separately evaluate
   whether the broader oversight measures are appropriate and proportionate.

## 7. Status language

Use:

> EMILIA produces independently verifiable action-authorization and control-
> operation evidence that can support EU AI Act Articles 12 and 14 assessments.

Do not use:

> EMILIA is EU AI Act compliant, certifies Article 14, or fully satisfies
> Articles 9 through 15.

The underlying protocol documents are active **individual IETF
Internet-Drafts**, not IETF-adopted standards or endorsements. JavaScript,
Python, and Go are same-team ports used for cross-language consistency. External
implementation evidence is reported separately and time-pinned.
