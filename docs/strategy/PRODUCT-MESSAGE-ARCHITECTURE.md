<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Product Message Architecture

*Status: canonical public-message doctrine*

*Last updated: 2026-07-17*

This document keeps the product, protocol, apps, assurance services, standards, and vertical profiles in one coherent company story. It governs public repository narrative, machine-facing context, marketing architecture, decks, product documentation, and future copy reviews. Runtime and security claims remain governed by the higher-precedence evidence sources named in `docs/ai/context-source.v1.json`.

## The company in one line

> **Protocol proves. Gate prevents.**

The buyer-facing sentence is:

> **EMILIA Gate is the consequence firewall that prevents AI agents and other machine actors from taking consequential actions on protected executor paths without verifiable authority.**

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
          +-- challenges for exact evidence
          |
          v
EMILIA Approver captures a device-bound human decision
          |
          v
EMILIA Gate verifies, authorizes locally, consumes once, and executes
          |
          v
EMILIA Protocol evidence survives for independent verification
          |
          v
EMILIA Assurance Plane re-performs the deployment's claims
```

### EMILIA Gate

**Role:** The commercial product and enforcement plane.

Gate belongs immediately before the system that can mutate state: an MCP tool, API handler, payment rail, cloud control, clinical determination workflow, grid actuator, or physical controller. It checks the relying party's evidence requirements and local policy before calling the executor. Missing or insufficient evidence produces a closed refusal and an action-bound challenge. Accepted evidence authorizes only the exact action and is consumed once.

**What customers buy:** Managed or BYOC operation, policy compilation, trust and revocation configuration, approver-directory integrations, durable consumption, evidence retention, deployment coverage, integrations, support, SLA, and a separately contracted warranty where offered.

**Claim boundary:** "Gate prevents" is true only for action paths under complete mediation. An operator-controlled bypass remains outside the guarantee and must not be hidden by product language.

### EMILIA Protocol

**Role:** The open verification and evidence substrate.

The Protocol supplies the portable formats, exact-action binding, verifier, conformance vectors, matching rules, evidence requirements, and interoperability surfaces used by Gate and other implementations. It remains Apache-2.0 and independently reproducible. The relying party selects its own trust anchors, policies, directories, profiles, and legal effect.

**Why it belongs one beat behind Gate:** Gate gives a buyer a product that can be deployed now. The Protocol answers the buyer's next question: "Why should we trust a startup or accept its evidence?" The answer is that verification does not require an EMILIA callback or an EMILIA-controlled trust root.

**Neutrality requirement:** Gate must never become the only verifier, issuer, trust root, or implementation. External implementations, partner evidence rows, native-format verification, open conformance, and standards participation are commercial moat protection, not charity.

### EMILIA Approver

**Role:** Exact-action human-decision capture.

The native apps and embeddable SDKs display the material action and capture an approval, decline, amendment, or rejection through a device-bound platform ceremony. The app is a capture surface, not the trust authority. Gate separately evaluates the approver directory, role, license or authority scope, policy, audience, platform evidence, and action binding under the relying party's profile.

**Distribution model:** Use the generic EMILIA Approver app for pilots and demonstrations. Let enterprises embed the open SDKs into the applications their clinicians, treasury staff, government operators, or control-room personnel already use. Do not make adoption of a standalone EMILIA app a prerequisite.

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

These support real paid services today:

1. **Verification service:** verify scoped artifacts or evidence populations under customer-pinned inputs.
2. **Re-performance service:** recompute claimed reliance or control results and report drift.
3. **Conformance report service:** run public CF-1, EG-1, protocol, or profile suites and issue a narrowly scoped signed result.
4. **Deployment-evidence service:** assemble coverage, active-probe, evidence-log, reliance, and period packages for customer and third-party review.
5. **Evidence operations:** retention, key and profile versioning, export, scheduled re-performance, drift alerts, and partner handoff.

The line that cannot move:

> **EMILIA supports the procedure. The authorized independent party reaches the conclusion.**

EMILIA is not an auditor, an accredited certification body, a regulator, or an insurer. It does not conclude that a deployment is compliant, secure, medically correct, or legally authorized. `EP-CERT-v1` is a scheme design for a future governance-dependent certification ecosystem. The public certification program is not operating. Any future certification mark requires narrowly defined scope, independent assessors, transparent governance, identical access for competitors, and explicit separation between implementation conformance and deployment assurance.

## The acquisition strategy

### Free wedge: privileged MCP tool calls

This is the adoption on-ramp:

1. An agent calls a consequential MCP tool.
2. The protected tool refuses with an evidence challenge.
3. A human or authorized service supplies the required evidence.
4. The tool executes the exact action once.
5. Replay, substitution, and tampering are refused.

The value is speed, developer visibility, integrations, and installed surface. It is not assumed to carry the first enterprise contract.

### First paid wedge: payer adverse medical-necessity determinations

The paid entry rule is:

> **No valid licensed-review evidence, no adverse determination.**

An AI-supported workflow may recommend a denial, delay, or modification. Gate holds the adverse determination until the relying party can verify that a qualified licensed reviewer evaluated the exact case, material facts, proposed outcome, and criteria version under the payer's own rule.

Missing or invalid evidence must block the adverse determination and route to a lawful human-review or patient-protective fallback. "Fail closed" must never be used to mean "withhold medically necessary care."

Regulatory requirements create urgency for demonstrable qualified review, but the marketing claim must remain exact: no statute should be described as mandating EMILIA, cryptographic receipts, or this particular mechanism.

### Later expansion

Payments, government disbursement, code and cloud administration, grid operations, Model-to-Matter, and physical autonomy remain important profiles. They establish that Gate is horizontal infrastructure. They should not be presented as simultaneous opening markets.

## The story sequence

Every first-screen explanation should follow this order:

1. **Consequence:** A machine is about to change something that matters.
2. **Control:** Gate refuses until the required exact-action evidence is present.
3. **Boundary:** Gate is effective where the resource owner completely mediates the mutating path.
4. **Neutrality:** Protocol evidence verifies under the customer's keys and rules without vendor callback.
5. **Capture:** Approver supplies a device-bound human decision when the profile requires one.
6. **Assurance:** The deployment's claims can be re-performed and packaged for an authorized reviewer.
7. **Proof:** Show executable claims, attack refusals, conformance, formal scope, and external implementation evidence.
8. **Standards:** Explain the IETF and interoperability portfolio only after the product and boundary are clear.

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

- EMILIA Gate for the commercial product.
- Consequence Firewall for the product category.
- EMILIA Protocol for the open substrate.
- EMILIA Approver for the mobile and embedded capture surface.
- EMILIA Assurance Plane for managed verification, re-performance, conformance reporting, and evidence operations.
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

> EMILIA Gate is the commercial consequence firewall for consequential machine actions. It blocks a protected executor until the action satisfies the relying party's evidence and policy requirements. EMILIA Protocol is the open verification substrate underneath it; EMILIA Approver captures device-bound human decisions; EMILIA Assurance Plane re-performs and packages scoped evidence without acting as an auditor or accredited certifier.

When asked "What does the company sell?", answer:

> Managed and BYOC Gate enforcement, integrations, policy and trust operations, durable evidence services, native approval capture, support and SLA, plus scoped verification and re-performance services. The open verifier, formats, and conformance vectors remain reproducible.

When asked "Is EMILIA certified?", answer:

> No public EMILIA certification program is operating. The repository ships executable conformance and assurance artifacts, and EMILIA may provide scoped verification, re-performance, and evidence services. Any audit conclusion or future certification depends on an authorized independent party and explicit governance.

When asked "What is the first market?", answer:

> Privileged MCP tool calls are the free adoption wedge. The first paid wedge is payer AI-assisted adverse medical-necessity determination, using the rule "no valid licensed-review evidence, no adverse determination." Payments and physical systems are later expansions.

## Source and review discipline

- `docs/ai/context-source.v1.json` governs generated LLM-facing identity and claim boundaries.
- `AI_CONTEXT.md`, `public/llms.txt`, `public/llms-full.txt`, and `public/.well-known/emilia-context.json` are generated outputs and must not be hand-edited.
- `security/security-case.json`, `security/claims.v1.json`, `conformance/conformance-manifest.json`, `lib/proof-stats.json`, and the external implementation pin govern quantitative and security evidence.
- `standards/STATUS.json` and the live IETF Datatracker govern standards status.
- `docs/CAPABILITY-MAP.md` governs whether a product capability may be represented as built.
- This document governs order, naming, and business interpretation. It never upgrades an implementation or evidence claim.
