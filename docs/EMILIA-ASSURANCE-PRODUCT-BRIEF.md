<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Claim-to-Consequence Assurance

**Protocol defines. Apps capture. Gate mediates. Assurance supports independent
re-performance.**

EMILIA Claim-to-Consequence Assurance is the product family that connects claim
verification, portable evidence, deployment review, and the separate Gate
consequence boundary. The **EMILIA Assurance Plane** is the managed evidence and
re-performance service design inside that family, delivered today only inside a
scoped engagement rather than a generally available hosted service. It helps a customer, auditor,
underwriter, or regulator answer a narrower
and more useful question than "is this AI safe?":

> For the supplied decision set and evidence, what verdict does the
> customer-pinned rule recompute, where does it disagree with the recorded
> verdict, and what evidence is missing or unverifiable?

The answer is produced from portable evidence under the relying party's keys and
profile. The package alone does not prove that the supplied set is the complete
production population or reconstruct live runtime state. Those questions require
separately anchored coverage and deployment evidence. This is not a reputation
score, a legal conclusion, or trust in an EMILIA-hosted black box.

## The four layers

| Layer | Job | Commercial boundary |
|---|---|---|
| EMILIA Protocol | Open formats, verification rules, profiles, and conformance vectors | Apache-2.0 and independently reproducible |
| Approver apps | Display the exact material fields and capture a device-bound human decision | Open reference apps and SDKs; production identity and attestation are deployment inputs |
| EMILIA Gate | Refuse a consequential action until admissible authorization evidence exists | Separately scoped customer-controlled implementation; a generally available managed runtime is not operating |
| EMILIA Assurance Plane | Re-perform decisions, detect drift, test conformance, and assemble evidence inside the Claim-to-Consequence Assurance family | Scoped reports, monitoring design, deployment reviews, and support; any future hosted operation or warranty requires a separately approved contract |

## Optional deliverables inside the one current engagement

The only public paid offer is one `$25K`, 90-day, nonproduction
protected-workflow pilot. Depending on the agreed boundary, that single
engagement may include the following deliverables. They are not separate
generally available products, subscriptions, certifications, or production
services.

### EMILIA Claim Assurance

Package one typed claim and its evidence as an `EP-CLAIM-CASE-v1`, re-perform it
with caller-pinned verifier implementations, and produce a deterministic
`EP-ASSURANCE-RECORD-v1`. The record distinguishes `VERIFIED`, `UNVERIFIED`,
`DIVERGED`, and `INDETERMINATE`, binds an optional exact action, and always
carries `authorizes_action: false`.

The open verifier and one synthetic reference record are implemented. Within
the protected-workflow engagement, Claim Assurance can be applied to the
agreed nonproduction or shadow evidence set. A public
customer-record registry, hosted verification service, surveillance programme,
certificate programme, and certification mark are not operating. Managed Claim
Assurance for a real workflow is scoped as part of the paid protected-workflow
engagement, with customer-owned profile and verifier pins.

When a Claim Case is used at Gate, the deployment re-performs the raw case,
checks it against the executor-observed exact action and a whole-case freshness
limit, then treats the result as one additional evidence condition. It never
replaces the Trust Receipt, local policy, durable consumption, or provider-entry
controls.

See [EP-CLAIM-ASSURANCE-SPEC.md](EP-CLAIM-ASSURANCE-SPEC.md).

### EMILIA Conformance

The protected-workflow engagement may run the public accept/refuse suites and hostility corpus against a named
implementation and version. The free path is self-test. The paid path adds a
witnessed procedure, stable input and result digests, a signed statement, and
support resolving failures.

The report says `non-accredited conformance test` unless an independent,
appropriately accredited laboratory performed it.

### EMILIA Deployment Assurance

As an optional pilot deliverable, review the proposed Gate enforcement boundary:

- whether mutating traffic actually passes through the Gate;
- bypass and alternate execution paths;
- issuer, approver, registry, and verifier-key pins;
- policy and assurance-tier configuration;
- replay state, storage failure, and failover behavior;
- evidence retention, export, and integrity;
- active refusal probes and declared coverage.

This is a bounded vendor or customer procedure over the proposed implementation
scope. It is not production activation, complete-path proof, operating
effectiveness, or independent certification.

### EMILIA Continuous Assurance

The pilot may demonstrate one bounded `EP-ASSURANCE-PACKAGE-v1` over the supplied
nonproduction or shadow decision set and re-perform every verdict with
`ep-assure`. This is not a recurring monitoring service. When completeness is in
scope, the procedure must bind that set to an independently anchored census or
system-of-record count. It can report:

- actions that remained admissible under the pinned profile;
- supplied decisions that recompute to refusal under the pinned rule;
- missing or unverifiable evidence;
- runtime-to-re-performance drift;
- reliance on evidence that did not support the runtime's claimed verdict;
- changes in coverage, policy, keys, and software version.

The workpaper leaves the assurer's or auditor's conclusion blank by construction.
EMILIA supplies reproducible evidence and procedures; the independent
professional supplies the opinion.

## Conditional future service

### EMILIA Warranted Gate

No warranty offer or underwriting basis is approved or available today. After a
successful baseline assessment, a separately reviewed future contract could
warrant named Gate behavior for named enforcement points, risk tiers, periods,
and limits. Any such warranty would not cover legal compliance, human perception,
business wisdom, or actions that bypass the protected boundary.

## The first offered commercial profile

**Finance Operations Assurance** is the initial offered profile. It is an
unvalidated commercial hypothesis, not evidence of a paid customer or revenue:

> No accepted exact-action authority and required evidence, no provider entry.

The first profile covers one vendor bank-detail change or payment-release
boundary. Missing, stale, exhausted, invalid, or mismatched authority does not
admit provider entry on a completely mediated covered path. Gate does not prove
bank-detail correctness, payee
identity, fraud absence, provider success, legality, or business wisdom, and it
does not take custody or move money.

MCP and privileged enterprise tool calls remain the free distribution wedge:
developers can install Gate quickly, prove the enforcement loop, and create the
top of the commercial funnel.

## How the business meters value

Verification remains open and free. Future separately contracted managed
services would price the operational burden and risk surface:

- protected enforcement boundaries and workflows;
- protected decision volume and risk tier;
- reporting and re-performance cadence;
- evidence-retention period;
- directory, policy, SIEM, GRC, and auditor integrations;
- support and response commitments;
- any separately contracted warranty limit.

Do not charge per refusal. A business model that earns more when a control allows
more actions creates the wrong incentive.

## Certification boundary

EMILIA does not currently certify its own Gate, and no public accredited EMILIA
certificate programme or mark is operating. EMILIA can own and steward a future
scheme's criteria, schemas, vectors, record format, registry and resolver rules,
surveillance workflow, status transitions, mark policy, licensing, and hosted
operations. An independent assessor or conformity assessment body retains its
own assessment conclusion, impartiality, competence, and any accreditation
claim. Software output does not become an independent opinion by being
relabelled.

See [EP-CERTIFICATION-SCHEME.md](EP-CERTIFICATION-SCHEME.md) for the exact
conformance and certification boundary.

## Honest limits

- Gate prevents only at enforcement points where mediation is complete.
- A valid authorization does not make an action correct, safe, wise, or lawful.
- Device attestation reduces display and app-integrity risk; it does not prove
  human perception.
- Offline re-performance proves what the evidence supports under a pinned rule;
  it cannot reconstruct live state that was never recorded.
- EMILIA is not the customer's trust root. Customers pin their own keys,
  profiles, and acceptance rules.
