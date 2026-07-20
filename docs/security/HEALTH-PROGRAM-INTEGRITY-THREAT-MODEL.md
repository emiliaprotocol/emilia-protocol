# Health Program Integrity Gate Threat Model

**Component:** `lib/health/program-integrity.js`

**Profile:** synthetic Medi-Cal hospice claim and provider-payment release

**Security objective:** refuse an irreversible health-program effect unless the
exact provider, pseudonymous member, service period, authorization artifact,
amount, currency, and payment destination are covered by current named-reviewer
authority and a single-use execution decision.

## Scope

This model covers the program-integrity engine from action construction through
precheck, provider submission, indeterminate-outcome handling, authenticated
reconciliation, and portable evidence export.

The protected assets are:

- program funds and provider-payment destinations;
- the integrity of provider-enrollment and claim-release decisions;
- the one-to-one binding between human authorization and the material action;
- reviewer accountability and authority provenance;
- the truth of the executor outcome when a provider call times out; and
- the confidentiality of member information outside the system of record.

The engine is a pre-execution accountability control. It is not a claims
adjudicator, a medical-necessity model, a fraud classifier, or a replacement for
Medi-Cal source systems.

## Trust Roots

| Trust root | What the engine may rely on | Required deployment property |
|---|---|---|
| CAID implementation | Canonical action identity for the complete material action | Domain-separated, deterministic canonicalization; caller-supplied CAIDs are recomputed and compared |
| Reviewer authority directory | Reviewer identity, organization, role, scope, validity interval, and revocation state | Relying-party controlled; point-in-time authority evidence is retained |
| Provider and enrollment sources | Provider NPI, standing, enrollment, licensure, and payment-destination facts | Authenticated source adapter with freshness and issuer metadata |
| Authorization-form source | Digest and validity of the required authorization artifact | The raw form and member identity remain in the source system; only the digest and minimum status leave it |
| Capability and operation store | Atomic reserve, commit, and terminal operation state | Durable, tenant-scoped, fail-closed, and safe under concurrent retries |
| Provider reconciliation keys | Authenticity of provider execution observations | Keys are pinned by the relying party; evidence cannot carry its own trust root |
| Evidence log | Decision and outcome ordering, integrity, and export | Durable strict append, fork-aware or externally witnessed where claimed |
| Clock | Expiry, service-period, evidence-freshness, and authority-window checks | Authenticated or deployment-trusted; clock failure refuses rather than extends authority |

The production application process and its service credential remain part of
the trusted computing base. Database constraints and portable evidence limit
route bugs and make later verification possible; they do not make a fully
compromised service tier honest.

## Attacker Goals and Required Refusals

| Attack | Attacker goal | Enforceable refusal |
|---|---|---|
| CAID confusion | Reuse approval from another action type, profile, tenant, or audience | Recompute the profile-scoped CAID from canonical action bytes and require exact equality |
| Amount or destination substitution | Approve a low-value or safe destination, then release more or pay elsewhere | Amount, currency, and destination are mandatory CAID/action-digest fields and are checked again at execution |
| Provider or member swap | Move an approval to another NPI or beneficiary | Provider NPI and pseudonymous member reference are mandatory bindings |
| Service-period mutation | Apply approval to unreviewed dates | Inclusive start and end dates are canonical, validated, and bound |
| Stale authorization | Use an expired form, reviewer grant, provider snapshot, or challenge | Every time-bound input is checked against the relying-party clock; missing or invalid time is a refusal |
| Missing reviewer authority | Treat authentication or a name as authorization | Reviewer authority must resolve from the pinned directory for this action scope and organization |
| Forged reconciliation | Convert an unknown timeout into a paid/executed outcome | Only authenticated, scope-matching provider evidence can resolve `INDETERMINATE` |
| Blind replay after timeout | Submit the same material action again because the first response was lost | Dispatch permanently consumes the execution right; retry is reconciliation only |
| Duplicate or conflicting reconciliation | Rewrite a terminal outcome or create two outcomes | Reconciliation is atomic and terminal; exact duplicate evidence may be idempotent, conflicting evidence refuses |
| Fail-open downgrade | Turn missing dependencies, unknown fields, parse errors, or store failure into allow | Error, absence, ambiguity, and unsupported version all produce a typed refusal or `INDETERMINATE`, never allow |
| PHI leakage | Exfiltrate identity or clinical content through logs or the evidence packet | Only opaque member references, digests, coarse status, and necessary action fields leave the source boundary |
| Evidence ambiguity | Produce a packet that can be interpreted as covering two actions or outcomes | One version, profile, tenant, operation ID, action CAID, action digest, decision, and terminal/indeterminate outcome per packet |

## State and Transition Invariants

The engine must expose a small, explicit state machine:

1. `REFUSED` is non-executable.
2. `READY` means all current preconditions passed and one operation identity was
   reserved for one exact action.
3. Provider dispatch consumes the right to submit. A positive authenticated
   provider result may produce `EXECUTED`.
4. A timeout or ambiguous transport result after dispatch produces
   `INDETERMINATE`, never `READY` and never an inferred success or failure.
5. `INDETERMINATE` can move only to a terminal reconciled state using
   authenticated provider evidence bound to the same provider, environment,
   operation, action CAID, amount, currency, destination, and idempotency key.
6. Terminal states are immutable. A byte-identical reconciliation may return the
   existing result; a different observation must refuse as a conflict.
7. No action mutation can preserve the original CAID or execution reservation.
8. Failure to persist a decision, reservation, dispatch marker, or evidence
   record prevents execution.

The CAID action type is versioned as
`health.medi_cal.hospice_claim_payment.1`. An unversioned action type, a
different terminal version, or a profile/action-type disagreement refuses
before authorization. This is part of the action identity, not display
metadata.

`INDETERMINATE` is a money-safety state. It is not an exception to be swallowed
and not a transient synonym for failed.

## Data-Minimization Boundary

The engine accepts and exports a pseudonymous `member_ref`; it must not accept or
emit a member name, date of birth, address, telephone number, email address,
SSN, Medicare Beneficiary Identifier, diagnosis, free-text clinical note, or
raw authorization form.

Authorization forms and clinical/member records remain in their existing
systems. The evidence packet carries a cryptographic digest, issuer/source
identifier, validity facts, and the exact-action binding needed for later
verification. Logs and exception details follow the same rule.

Pseudonymization is not anonymization. A stable member reference can still be
sensitive and must remain tenant-scoped with retention and access controls.

## Evidence-Packet Requirements

A portable packet is acceptable only if an independent verifier can determine:

- the packet version and program-integrity profile;
- the organization/tenant and operation ID;
- the exact action CAID and action digest;
- the provider NPI, pseudonymous member reference, service period,
  authorization-form digest, amount, currency, and destination;
- which reviewer authority and source snapshots were relied upon, at what time;
- whether execution was refused, executed, or remains indeterminate;
- the single-use reservation/consumption evidence; and
- for reconciliation, the pinned provider key ID, observation digest,
  provider effect reference, and signature-verification result.

Missing duplicate keys, duplicate operation records, conflicting outcomes,
unknown critical fields, unsupported versions, or a mismatch between the packet
summary and signed evidence make the packet unverifiable. A UI label is never
authoritative over the signed/canonical evidence.

## Residual Risks

- A compromised reviewer directory can grant fraudulent authority before the
  engine evaluates it. External directory audit and separation of duties remain
  necessary.
- A malicious or compromised provider source can make false standing,
  enrollment, authorization, or outcome assertions. Independent data sources
  and post-payment review remain necessary.
- A compromised production service credential can fabricate application-layer
  inputs. External verification, witnessed logs, key isolation, and least
  privilege reduce but do not eliminate this risk.
- A valid named reviewer can collude, be coerced, or make a substantively wrong
  decision. The receipt proves accountable authorization, not clinical truth.
- An opaque member reference may be linkable across packets. Deployments should
  use tenant-specific pseudonyms and bounded retention.
- Source freshness windows are policy choices. A technically valid stale
  snapshot can still be operationally unsafe if the relying party configures an
  overly broad window.
- Provider APIs may not expose evidence strong enough to distinguish accepted,
  rejected, and unknown outcomes. The honest result then remains
  `INDETERMINATE`.

## Honest Non-Goals

This control does not:

- determine whether a service was medically necessary or actually delivered;
- detect every fraud pattern or replace statistical anomaly detection;
- prove the real-world identity of a member or provider beyond trusted source
  assertions;
- make EMILIA a claims processor, insurer, custodian, or payment rail;
- eliminate HIPAA, CMIA, Medicaid, procurement, records-retention, or due-process
  obligations;
- guarantee recovery after an erroneous or fraudulent payment; or
- turn a same-team test suite into independent certification.

## Hostile Acceptance Gate

Release is blocked unless executable tests prove refusal under:

1. CAID/profile confusion;
2. amount and destination substitution;
3. provider, member, and service-period mutation;
4. stale authorization and missing reviewer authority;
5. forged provider reconciliation;
6. replay after provider timeout and duplicate/conflicting reconciliation;
7. fail-open/error downgrade attempts;
8. PHI injection into decisions, logs, and exported packets; and
9. missing or conflicting evidence-packet identity/outcome fields.

The focused hostile suite is
`tests/health-program-integrity-hostile.test.js`.
