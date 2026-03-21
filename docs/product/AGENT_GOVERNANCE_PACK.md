# EP Agent Governance Pack

Vertical policy and control pack for AI agent execution governance.

## Overview

The EP Agent Governance Pack provides reference policies, control
configurations, and compliance mappings for governing AI agent actions.
It addresses the trust-enforcement problem that emerges when autonomous
or semi-autonomous agents perform actions with real-world consequences:
executing transactions, modifying records, sending communications,
accessing sensitive data, or interacting with external systems.

The core problem is accountability. When a human performs a high-risk
action, the action is attributed to that human. When an agent performs
the same action, the accountability chain is ambiguous unless explicitly
constructed. Who authorized the agent to act? What were the boundaries
of that authorization? Was a human accountable for the specific action,
or only for the general delegation? If something goes wrong, who is
responsible?

EP's handshake-before-action model provides the mechanism. The Agent
Governance Pack provides the specific policies and configurations that
map this mechanism to agent execution patterns.

This pack runs on EP Cloud or EP Enterprise. It does not modify the
protocol kernel.

---

## Capabilities

### Action Risk Classes

The Agent Governance Pack defines a risk classification framework for
agent actions:

- **Low risk:** Actions that are easily reversible, affect only the
  requesting user, and have minimal downstream consequences. Examples:
  reading data, generating summaries, formatting outputs.
- **Medium risk:** Actions that modify state but are reversible with
  effort, or that affect a limited scope. Examples: updating a draft
  document, scheduling a meeting, modifying a non-production
  configuration.
- **High risk:** Actions that are difficult to reverse, affect other
  parties, or involve significant resources. Examples: sending
  external communications, modifying financial records, deploying
  code to production.
- **Critical risk:** Actions that are irreversible, affect many
  parties, or carry legal or financial liability. Examples: executing
  financial transactions, submitting regulatory filings, deleting
  production data, signing contracts.

Risk classes are assigned per action type in EP policies. The
classification determines what verification is required before the
action executes.

**Why it matters:** Not all agent actions carry the same risk. A
blanket "always require human approval" approach degrades agent
utility. A blanket "always allow" approach creates unacceptable risk.
Risk classification enables proportional control.

### Accountable Signoff Thresholds

Each risk class maps to a signoff requirement:

- **Low risk:** No handshake required. The agent executes under its
  delegated authority. Action is logged for audit.
- **Medium risk:** Lightweight handshake. The agent initiates a
  handshake that verifies the agent's delegation is valid, the
  action is within scope, and the policy version is current. No
  human intervention required if delegation is valid.
- **High risk:** Accountable Signoff required. A named human must
  review the specific action the agent intends to take and provide
  attestation before execution. The human's identity, the action
  details, and the attestation are bound in the handshake.
- **Critical risk:** Enhanced Accountable Signoff. Dual human signoff
  or senior-authority signoff required. The agent cannot proceed
  until the required human attestations are collected.

Thresholds are configurable per organization, per agent, per action
type, and per context. An action that is medium-risk in a sandbox
environment may be critical-risk in production.

**Connection to the kernel:** Signoff thresholds are implemented as
EP policy rules. The handshake's `action_type` and contextual
attributes (environment, scope, value) are evaluated against policy
rules to determine the required verification level. Accountable
Signoff uses the hosted challenge-delivery and attestation-collection
mechanisms from EP Cloud.

### Tool-Use Control Packs

Agents interact with external systems through tools (APIs, functions,
integrations). The Agent Governance Pack provides policies that govern
which tools require what level of signoff:

- **Tool classification:** Each tool available to an agent is
  classified by risk. Tool classifications can be defined globally
  or per-agent.
- **Tool-specific policies:** A tool that sends email might require
  Accountable Signoff. A tool that reads a knowledge base might
  require no signoff. A tool that executes a database write might
  require signoff above a row-count threshold.
- **Tool composition controls:** When an agent chains multiple tools
  in sequence, the composite risk may exceed the risk of individual
  tools. Policies can define escalation rules for multi-tool
  sequences.
- **New tool onboarding:** Adding a new tool to an agent's toolkit
  is itself a controlled action. The tool must be classified and
  its signoff requirements defined before the agent can invoke it.

### Delegated Autonomy Levels

The Agent Governance Pack defines a spectrum of autonomy levels for
agent operation:

- **Full auto:** The agent operates within its delegation without
  per-action human involvement. Appropriate for low-risk actions
  within well-defined boundaries.
- **Supervised:** The agent operates autonomously but a human
  receives real-time notification of actions taken. The human can
  intervene to halt or reverse actions. Appropriate for medium-risk
  actions.
- **Human-gated:** The agent prepares and proposes actions but
  cannot execute until a human explicitly approves each action
  through Accountable Signoff. Appropriate for high-risk actions.
- **Human-executed:** The agent provides analysis and
  recommendations but the human performs the action themselves.
  The agent cannot execute. Appropriate for critical-risk actions
  or regulatory contexts requiring direct human execution.

Autonomy levels are configured per agent, per action type, per
environment, and per risk class. An agent might operate in full-auto
mode for data retrieval and human-gated mode for data modification.

### Human-Responsibility Flows

When an agent performs a high-risk action, a named human must own the
outcome. The Agent Governance Pack enforces this through
human-responsibility flows:

- **Named accountability:** High-risk and critical-risk agent actions
  are attributed to a specific named human, not to "the system" or
  "the agent." The human's identity is bound to the handshake.
- **Informed consent:** The accountable human is presented with the
  specific action the agent intends to take, the context, and the
  potential consequences. The attestation records that the human
  reviewed this information.
- **Responsibility cannot be delegated to the agent:** A policy that
  says "the agent decides" is not valid for high-risk actions. A
  human must decide. The agent can recommend, but the handshake
  requires human attestation.
- **Post-action accountability:** The handshake record permanently
  links the human to the action. If the action causes harm, the
  accountability chain is documented.

**Why it matters:** Regulatory frameworks (EU AI Act, NIST AI RMF)
increasingly require that high-risk AI actions have identifiable
human accountability. EP provides the mechanism to enforce and
evidence this requirement.

### Principal-to-Agent Attribution Chain

When an agent acts, the Agent Governance Pack maintains a complete
attribution chain from the human principal through any intermediary
delegations to the specific agent action:

- **Principal identification:** The human or organizational entity
  that authorized the agent's operation is identified and bound
  to the agent's delegation.
- **Delegation chain:** If the agent's authority was delegated
  through multiple levels (e.g., organization -> team lead ->
  agent operator -> agent), each delegation link is recorded.
- **Action attribution:** Each agent action is attributed both to
  the agent (as executor) and to the principal chain (as authority
  source).
- **Chain verification:** At handshake verification time, the
  entire attribution chain is validated. If any link in the chain
  has been revoked or expired, the handshake fails.

**Connection to the kernel:** Attribution chains are implemented
through the handshake party model and the authority registry.
`resolveAuthority()` validates each link in the chain during
handshake verification. The chain is recorded in the handshake
record and in `protocol_events`.

### Reference Policy Configurations

Pre-built policy configurations for common agent governance scenarios:

- **Customer service agent:** Read access is full-auto. Account
  modifications require supervised mode. Refunds above threshold
  require human-gated signoff. Account closure requires
  human-executed mode.
- **Code deployment agent:** Code review and testing are full-auto.
  Staging deployment is supervised. Production deployment is
  human-gated. Rollback is supervised (to enable rapid response).
- **Data analysis agent:** Data reading and analysis are full-auto.
  Report generation is supervised. Data modification or deletion
  is human-gated. External data sharing is human-executed.
- **Financial operations agent:** Balance inquiries are full-auto.
  Internal transfers below threshold are supervised. External
  transfers are human-gated. Large external transfers require
  dual human signoff.

These configurations are starting points adapted to each
organization's risk tolerance and regulatory requirements.

### EU AI Act and NIST AI RMF Mapping

The Agent Governance Pack documents how EP's controls map to emerging
AI governance frameworks:

**EU AI Act alignment:**

- **Human oversight (Article 14):** EP's Accountable Signoff provides
  the mechanism for human oversight of high-risk AI actions.
  Handshake records provide evidence of human review and approval.
- **Transparency (Article 13):** The attribution chain documents
  who authorized the agent, under what delegation, and with what
  constraints.
- **Record-keeping (Article 12):** EP's append-only event log
  provides the automatic logging of events required by the Act.
- **Risk management (Article 9):** Risk classification and
  proportional controls demonstrate a risk management system.

**NIST AI RMF alignment:**

- **GOVERN function:** EP policies and RBAC provide the governance
  structures the framework requires.
- **MAP function:** Risk classification maps agent capabilities to
  organizational risk tolerance.
- **MEASURE function:** Policy analytics provide metrics on agent
  behavior and control effectiveness.
- **MANAGE function:** Accountable Signoff and autonomy levels
  provide the control mechanisms for managing identified risks.

These mappings are informational. They do not constitute legal
compliance. Organizations should conduct their own compliance
assessment with qualified legal counsel.

---

## Relationship to the Protocol Kernel

The Agent Governance Pack does not modify EP's protocol kernel:

- Risk classes and autonomy levels are implemented as EP policy
  rules.
- Accountable Signoff uses the standard handshake lifecycle with
  challenge delivery from EP Cloud.
- Attribution chains use the standard party model and authority
  registry.
- Events are written to the same append-only tables.

The protocol kernel is agent-agnostic. It enforces trust before
action regardless of whether the actor is human or machine. The
Agent Governance Pack provides the configuration layer that makes
this enforcement meaningful in agent-specific contexts.

---

## Deployment

The Agent Governance Pack can be deployed on:

- **EP Cloud:** For organizations running agents in cloud
  environments where hosted trust infrastructure is acceptable.
- **EP Enterprise:** For organizations requiring private
  deployment, custom trust roots, or regulatory-mandated
  infrastructure controls.

The pack is typically deployed alongside EP Cloud or EP Enterprise
as an add-on configuration and policy layer.
