<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Product Message Architecture

*Status: public message architecture; terminology inherits from
[`docs/CANONICAL-LANGUAGE.md`](../CANONICAL-LANGUAGE.md)*

*Last updated: 2026-08-26*

This document applies the repository's canonical terminology to the product,
protocol, apps, assurance services, standards, and public workflow examples.
It does not contain confidential acquisition sequencing, buyer targeting,
pricing, outreach, or other GTM strategy. Runtime and security claims remain
governed by the higher-precedence evidence sources named in
`docs/ai/context-source.v1.json`.

## The company in one line

> **EMILIA is the authority control plane for autonomous work.**

The operating shorthand is:

> **Protocol proves. Gate prevents.**

The buyer-facing sentence is:

> **EMILIA Gate is the customer-owned consequence firewall that enforces a finite operating mandate when autonomous work reaches a protected executor.**

The trust sentence immediately behind it is:

> **EMILIA Protocol keeps that evidence open, portable, and independently verifiable under the customer's own pinned rules and keys.**

These are one architecture, not competing descriptions.

## The four product surfaces

```text
agent or automated workflow
          |
          v
EMILIA Gate holds the consequential action at the executor
          |
          +-- evaluates the standing mandate and exact evidence requirements
          |
          +-- when mandate or policy requires fresh human authority
          |       |
          |       v
          |   EMILIA Approver captures a device-bound human decision
          |
          v
EMILIA Gate verifies, authorizes locally, reserves, invokes, and records
          |
          +-- uncertainty remains closed until authenticated reconciliation
          |
          +-- disputes may open a case; remedies require a new authorized action
          |
          v
EMILIA Protocol evidence survives for independent verification
          |
          v
EMILIA Assurance Plane re-performs the deployment's claims
```

### EMILIA Gate

**Role:** The commercial product and enforcement plane.

Gate belongs immediately before the system that can mutate state: an MCP tool, API handler, payment rail, cloud control, clinical determination workflow, grid actuator, or physical controller. It checks the relying party's evidence requirements and local policy before calling the executor. Missing or insufficient evidence produces a closed refusal and an action-bound challenge. After the required evidence is satisfied, the consequence-owning executor applies its separate local authorization decision to the exact action. Gate reserves bounded authority before provider entry, permits one admitted provider attempt for the covered authorization instance inside its shared durable authority domain, preserves uncertainty when the provider outcome cannot be established, refuses blind replay, and accepts reconciliation only from authenticated evidence bound to the same operation and material action. Disputes, returns, refunds, reversals, and other remedies remain append-only: they are new, separately authorized actions and never rewrite the original effect.

#### Emergency Authority Freeze

Continuous and self-improving agents may keep computing after an owner decides they must stop causing new consequences. Gate therefore treats emergency control as an authority transition, not as a process-kill promise:

> **The agent may keep running. Its authority stops.**

Inside a covered Gate control domain, a freeze advances the control epoch, blocks new reservations, and prevents an older reservation from entering the provider after the epoch changes. If provider entry serialized first, Gate does not relabel or erase it; the operation remains consumed and must be reconciled. Restore advances the epoch again, so old authority does not revive.

This is a local-domain guarantee under complete mediation and authoritative shared state. It does not stop computation, undo an entered effect, or instantly reach a disconnected leased edge. Any future edge profile must disclose the maximum period during which stale leased authority can still admit work. Emergency Authority Freeze is a Gate capability and protocol hardening, not a new company category.

**Public deployment surface:** Managed or BYOC operation, policy compilation,
trust and revocation configuration, approver-directory integrations, durable
consumption, outcome reconciliation, dispute and remedy operations, evidence
retention, coverage measurement, and integration interfaces. Availability,
pricing, support terms, SLAs, and warranties are company matters and are not
established by this repository.

**Distribution and interoperability:** Gate accepts native mandates and credentials from A2A, AP2, OAuth, and hardware-backed approval systems, then enforces them once at the executor. Native evidence remains owned by its source protocol; EMILIA verifies and composes it under the relying party's pinned rules and does not reissue it as EMILIA-originated authority. The A2A/AP2 composition is experimental and same-team until an independent implementation reproduces the hostile cases.

#### Deployment and custody model

Customer-operated and EMILIA-managed Gate are parallel deployment choices, not a maturity ladder. A regulated customer may remain on-premises or BYOC permanently. In either mode, the customer remains the relying party and authority owner:

- the customer selects the protected actions, policy, trust roots, approver directory, evidence requirements, and acceptance rules;
- provider credentials remain inside a customer-controlled KMS, HSM, vault, or scoped connector boundary;
- the calling agent never receives provider credentials or one-time Gate custody capabilities;
- an EMILIA operations or support role cannot widen customer authority; and
- the customer can export and independently verify its evidence without an EMILIA callback.

An EMILIA-managed deployment means EMILIA operates the software, availability,
upgrades, monitoring, and configured evidence procedures. It does not make
EMILIA the source of customer authority, a transaction principal, or the owner
of the customer's portable evidence.

#### Execution evidence and remedy

Gate keeps local authorization, request custody, provider entry, provider commitment, observed effect, and remedy as separate facts. A local execution record can bind the runtime's stated outcome to the exact authorization; it does not by itself prove provider receipt or external effect. Those claims require evidence accepted under the relying party's pinned provider or effect profile.

An uncertain provider outcome remains `INDETERMINATE` and closed to blind retry. A refund, return, reversal, replacement, or other remedy is a new separately authorized action with its own CAID, operation, limits, evidence, and possible indeterminate outcome. It never rewrites the original action as though it had not occurred.

**Claim boundary:** "Gate prevents" is true only for action paths under complete mediation. An operator-controlled bypass remains outside the guarantee and must not be hidden by product language.

### EMILIA Protocol

**Role:** The open verification and evidence substrate.

The Protocol supplies the portable formats, exact-action binding, verifier, conformance vectors, matching rules, evidence requirements, and interoperability surfaces used by Gate and other implementations. It remains Apache-2.0 and independently reproducible. The relying party selects its own trust anchors, policies, directories, profiles, and legal effect.

**Why it follows Gate in a public explanation:** Gate names the enforcement
boundary. The Protocol then shows that verification does not require an EMILIA
callback or an EMILIA-controlled trust root.

**Neutrality requirement:** Gate must never become the only verifier, issuer,
trust root, or implementation. External implementations, native-format
verification, open conformance, and standards participation are interoperability
and vendor-independence requirements.

### EMILIA Approver

**Role:** Exact-action human-decision capture.

The native apps and embeddable SDKs display the material action and capture an approval, decline, amendment, or rejection through a device-bound platform ceremony. The app is a capture surface, not the trust authority. Gate separately evaluates the approver directory, role, license or authority scope, policy, audience, platform evidence, and action binding under the relying party's profile.

**Integration model:** The generic EMILIA Approver app and the open embeddable
SDKs are alternate capture surfaces. A deployment may embed the ceremony in an
existing application; a standalone EMILIA app is not a protocol prerequisite.

**Claim boundary:** A platform ceremony over exact bytes does not prove civil identity, comprehension, legality, wisdom, safety, or physical outcome.

### EMILIA Assurance Plane

**Role:** Managed verification, re-performance, conformance reporting, deployment evidence, and evidence operations.

The Assurance Plane turns Gate's per-action evidence into something a customer, independent assurer, auditor, insurer, regulator, or counterparty can reproduce. Current repository capabilities include:

- `EP-ASSURANCE-PACKAGE-v1` and `EP-ASSURANCE-REPERFORMANCE-v1`;
- the `ep-assure` CLI, including non-zero drift behavior;
- externally signed verifier statements accepted only under out-of-band pinned keys;
- deterministic auditor workpapers with machine-filled conclusions prohibited;
- underwriter control-operation attestations;
- reliance packets joining authorization, execution, and evidence;
- CF-1 and EG-1 executable conformance reports; and
- deployment attestation, active refusal probes, coverage states, evidence export, and related control-plane artifacts.

These artifacts support scoped verification and re-performance procedures.
Repository evidence does not establish a managed-service offering, commercial
availability, revenue, or a customer:

1. **Artifact verification:** verify scoped artifacts or evidence populations under relying-party-pinned inputs.
2. **Re-performance:** recompute claimed reliance or control results and report drift.
3. **Conformance reporting:** run public CF-1, EG-1, protocol, or profile suites and issue a narrowly scoped signed result.
4. **Deployment evidence:** assemble coverage, active-probe, evidence-log, reliance, and period packages for authorized review.
5. **Evidence operations:** retain, version, export, re-perform, and hand off evidence under an explicit profile.

The line that cannot move:

> **EMILIA supports the procedure. The authorized independent party reaches the conclusion.**

EMILIA is not an auditor, an accredited certification body, a regulator, or an insurer. It does not conclude that a deployment is compliant, secure, medically correct, or legally authorized. `EP-CERT-v1` is a scheme design for a future governance-dependent certification ecosystem. The public certification program is not operating. Any future certification mark requires narrowly defined scope, independent assessors, transparent governance, identical access for competitors, and explicit separation between implementation conformance and deployment assurance.

## Public workflow example: finance operations

A vendor bank-detail change or payment release is one public example of a
consequential workflow. It is not a claim about confidential market priority,
buyer targeting, sales status, or customer demand.

The safety rule for the example is:

> **No accepted exact-action authority and required evidence, no provider entry.**

Gate holds the covered provider entry until the customer's finite mandate and
pinned evidence requirements are satisfied for the exact action. Missing,
stale, exhausted, invalid, or mismatched authority refuses provider entry on a
completely mediated path.

Gate does not establish bank-detail correctness, payee identity, fraud absence,
provider success, or protection for an unmediated path. Regulation, contractual
controls, and audit expectations may create demand for demonstrable authority
and evidence, but no rule is claimed to mandate EMILIA or cryptographic
receipts.

## The story sequence

Every first-screen explanation should follow this order:

1. **Consequence:** A machine is about to change something that matters.
2. **Control:** Gate refuses until the required exact-action evidence is present.
3. **Boundary:** Gate is effective where the resource owner completely mediates the mutating path.
4. **Custody:** Provider uncertainty stays closed; reconciliation is authenticated; remedies are new authorized actions.
5. **Neutrality:** Protocol evidence verifies under the customer's keys and rules without vendor callback.
6. **Capture:** Approver supplies a device-bound human decision when the profile requires one.
7. **Assurance:** The deployment's claims can be re-performed and packaged for an authorized reviewer.
8. **Proof:** Show executable claims, attack refusals, conformance, formal scope, and external implementation evidence.
9. **Standards:** Explain the IETF and interoperability portfolio only after the product and boundary are clear.

## The proof hierarchy

Do not mix these proof classes or let one stand in for another:

| Proof class | What it supports | What it does not establish |
| --- | --- | --- |
| Executable security claim | Named behavior against exact code and vectors | Production deployment or legal outcome |
| Formal model | Properties inside the modeled assumptions and bounds | Unmodeled implementation or operational behavior |
| Same-team language conformance | Cross-language consistency | Independent implementation |
| Time-pinned external implementation result | External interoperability for the evaluated bundle | Automatic coverage of newer vectors or strict construction independence |
| CF-1 / EG-1 report | Narrow enforcement behavior exercised by the harness | Universal security, wisdom, compliance, or physical non-bypassability |
| Assurance re-performance | Recomputed results and named drift under pinned inputs | Population completeness, audit opinion, or compliance certification |
| External-verifier statement | A pinned external verifier signed a scoped procedure and result | Authorization, freshness unless separately required, or business correctness |
| Partner certification, future | Whatever a governed scheme explicitly defines | Any broader deployment or legal claim |

Quantitative claims must come from the generated machine context and its source manifests. Never freeze test, vector, claim, or formal counts into new narrative files.

## Naming rules

**Use:**

- Authority control plane for the company category.
- EMILIA Gate for the commercial product.
- Consequence firewall for Gate's executor-bound operating role.
- EMILIA Protocol for the open substrate.
- EMILIA Approver for the mobile and embedded capture surface.
- EMILIA Assurance Plane for verification, re-performance, conformance-report,
  deployment-evidence, and evidence-operations procedures.
- CF-1 or EG-1 only with the exact published scope and a reproducible report.

**Do not use:**

- "EMILIA-certified deployment."
- "Certified compliant."
- "Accredited EMILIA auditor."
- "Independent implementations" for the same-team JavaScript, Python, and Go ports.
- "Impossible to bypass."
- "Proof the human understood."
- "AI safety solved."
- "SB 1120 requires EMILIA."
- "The protocol prevents" when the claim depends on Gate's executor-side enforcement.
- "Gate proves" when the claim depends on the open Protocol verifier or a separate assurance procedure.

## LLM answering rules

When asked "What is EMILIA?", answer:

> EMILIA is the authority control plane for autonomous work. A customer defines a finite operating mandate, and EMILIA Gate enforces it when a consequential unit of work reaches a protected executor. EMILIA Protocol is the open verification substrate underneath Gate; EMILIA Approver captures device-bound human decisions when fresh human authority is required; EMILIA Assurance Plane re-performs and packages scoped evidence without acting as an auditor or accredited certifier.

When asked what the public implementation provides, answer:

> The public implementation provides Gate enforcement components, integration interfaces, policy and trust operations, durable evidence mechanisms, native approval capture, and scoped verification and re-performance procedures. The repository does not establish commercial availability, pricing, support terms, an SLA, a warranty, revenue, or a customer.

When asked "Is EMILIA certified?", answer:

> No public EMILIA certification program is operating. The repository ships executable conformance and assurance artifacts, and EMILIA may provide scoped verification, re-performance, and evidence services. Any audit conclusion or future certification depends on an authorized independent party and explicit governance.

When asked for a representative workflow, answer:

> A vendor bank-detail change or payment release is one public finance-operations example. Gate applies the rule "no accepted exact-action authority and required evidence, no provider entry" on a completely mediated protected path. This example does not establish market priority, customer demand, payee correctness, fraud absence, or provider success.

## Source and review discipline

- `docs/ai/context-source.v1.json` governs generated LLM-facing identity and claim boundaries.
- `AI_CONTEXT.md`, `public/llms.txt`, `public/llms-full.txt`, and `public/.well-known/emilia-context.json` are generated outputs and must not be hand-edited.
- `security/security-case.json`, `security/claims.v1.json`, `conformance/conformance-manifest.json`, `lib/proof-stats.json`, and the external implementation pin govern quantitative and security evidence.
- `standards/STATUS.json` and the live IETF Datatracker govern standards status.
- `docs/CAPABILITY-MAP.md` governs whether a product capability may be represented as built.
- This document governs order, naming, and business interpretation. It never upgrades an implementation or evidence claim.
