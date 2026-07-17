<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Assurance

**Protocol proves. Apps capture. Gate prevents. Assurance makes the deployment
defensible.**

EMILIA Assurance is the managed evidence and re-performance plane above EMILIA
Gate. It helps a customer, auditor, underwriter, or regulator answer a narrower
and more useful question than "is this AI safe?":

> For this population of consequential actions, did the deployed control require
> the evidence the customer pinned, refuse when that evidence was missing, and
> leave a record an independent party can recompute?

The answer is produced from portable evidence under the relying party's keys and
profile. It is not a reputation score, a legal conclusion, or trust in an
EMILIA-hosted black box.

## The four layers

| Layer | Job | Commercial boundary |
|---|---|---|
| EMILIA Protocol | Open formats, verification rules, profiles, and conformance vectors | Apache-2.0 and independently reproducible |
| Approver apps | Display the exact material fields and capture a device-bound human decision | Open reference apps and SDKs; production identity and attestation are deployment inputs |
| EMILIA Gate | Refuse a consequential action until admissible authorization evidence exists | Managed or customer-hosted enforcement, policy, integrations, and fleet operation |
| EMILIA Assurance | Re-perform decisions, detect drift, test conformance, and assemble evidence | Managed reports, monitoring, deployment reviews, support, and narrowly scoped warranties |

## What customers can buy now

### EMILIA Conformance

Run the public accept/refuse suites and hostility corpus against a named
implementation and version. The free path is self-test. The paid path adds a
witnessed procedure, stable input and result digests, a signed statement, and
support resolving failures.

The report says `non-accredited conformance test` unless an independent,
appropriately accredited laboratory performed it.

### EMILIA Deployment Assurance

Review one or more Gate enforcement boundaries:

- whether mutating traffic actually passes through the Gate;
- bypass and alternate execution paths;
- issuer, approver, registry, and verifier-key pins;
- policy and assurance-tier configuration;
- replay state, storage failure, and failover behavior;
- evidence retention, export, and integrity;
- active refusal probes and declared coverage.

This is a deployment assessment by the vendor or customer. It is not independent
certification.

### EMILIA Continuous Assurance

On an agreed cadence, build an `EP-ASSURANCE-PACKAGE-v1` over the protected
decision population and re-perform every verdict with `ep-assure`. Report:

- actions that remained admissible under the pinned profile;
- refusals where the control operated as designed;
- missing or unverifiable evidence;
- runtime-to-re-performance drift;
- reliance on evidence that did not support the runtime's claimed verdict;
- changes in coverage, policy, keys, and software version.

The workpaper leaves the assurer's or auditor's conclusion blank by construction.
EMILIA supplies reproducible evidence and procedures; the independent
professional supplies the opinion.

### EMILIA Warranted Gate

After a successful baseline assessment, a separate contract may warrant named
Gate behavior for named enforcement points, risk tiers, periods, and limits. The
warranty does not cover legal compliance, human perception, business wisdom, or
actions that bypass the protected boundary.

## The first paid profile

**Adverse Determination Assurance** is the first paid vertical:

> No AI-assisted adverse medical-necessity determination executes without
> admissible evidence that the required qualified, licensed professional
> reviewed that specific determination.

Missing or indeterminate evidence blocks the adverse determination, not care.
The safe fallback is manual review or the patient-protective path configured by
the payer. EMILIA does not determine medical necessity.

MCP and privileged enterprise tool calls remain the free distribution wedge:
developers can install Gate quickly, prove the enforcement loop, and create the
top of the commercial funnel.

## How the business meters value

Verification remains open and free. Managed services price the operational
burden and risk surface:

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

EMILIA does not certify its own Gate. A future open certification scheme can be
operated by an independent body with the required competence, impartiality,
review, decision, surveillance, appeals, suspension, and withdrawal procedures.
EMILIA may steward public criteria and vectors and supply evidence tooling, while
the independent body controls the certification decision and mark.

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
