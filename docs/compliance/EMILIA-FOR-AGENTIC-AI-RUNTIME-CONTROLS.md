<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA for Agentic AI Runtime Controls

Pre-execution accountability for autonomous AI agents that call tools and take irreversible actions — the runtime control regulated enterprises need before they let agents touch money, records, or infrastructure. Maps to the human-oversight expectations in the NIST AI RMF and EU AI Act Article 14.

> EMILIA proves a named human authorized a specific irreversible agent action under a stated policy before it executed, with a receipt verifiable offline. Prompt injection can change what an agent *proposes*; it cannot forge the device-bound signoff or the receipt. The absence of a receipt for a gated action is itself a bypass signal.

---

## Control area 1 — Irreversible tool calls

| | |
|---|---|
| **Risk** | An agent (or an injected/hijacked agent) calls a high-risk tool — move money, delete data, change a record, rotate a credential — autonomously. |
| **Current control failure** | Tool-level permissions and OAuth scopes prove the agent *may* call the tool; they don't establish that a named human authorized *this exact call* with these exact parameters. Logs are produced by the acting system. |
| **EMILIA control** | The irreversible call is intercepted at the boundary (e.g., the Model Context Protocol); policy decides allow / allow-with-signoff / deny; when a human is required, a device-bound signoff is bound to the canonical tool-name + argument hash before the call proceeds; fail-closed (no valid receipt → no execution). |
| **Evidence generated** | A receipt binding the exact tool call, the named approver, policy version, nonce, and one-time consumption — verifiable offline by a third party. |
| **Auditor question answered** | "For this agent action, who authorized it, against what policy, and can we prove it without trusting the agent's own logs?" |
| **Integration pattern** | EMILIA Agent Guard / MCP middleware wraps the tool dispatcher; Observe mode classifies which calls would have required signoff before any blocking. |

## Control area 2 — Human oversight that is verifiable (NIST AI RMF / EU AI Act Art. 14)

| | |
|---|---|
| **Risk** | "Human oversight" is required by policy/regulation but implemented as an unfalsifiable attestation. |
| **Current control failure** | A claim that a human reviewed a consequential automated action, with no artifact a third party can verify. |
| **EMILIA control** | Oversight produces verifiable evidence: a named human's approval bound to the exact action, checkable offline, independent of the operating system. |
| **Auditor / regulator question answered** | "Demonstrate that human oversight of this high-risk AI action actually occurred and was bound to the action." |
| **Mapping** | NIST AI RMF GOVERN/MAP human-accountability functions; EU AI Act Article 14 human oversight of high-risk AI. |

## Control area 3 — Delegation & authority for multi-agent chains

| | |
|---|---|
| **Risk** | In agent-to-agent chains, a downstream agent acts beyond the authority actually granted. |
| **Current control failure** | Identity/scope tokens don't carry action-bound, narrowing-only delegation that a verifier can check. |
| **EMILIA control** | Authority-chain integrity with proven acyclicity; the per-action approval composes onto the delegation root; the verifier checks the chain. |
| **Auditor question answered** | "Prove this agent had the authority to take this action within its delegated scope." |
| **Integration pattern** | Provenance-chain verification over the agent's delegation evidence. |

---

*Maps EMILIA to agentic-AI runtime control objectives and to NIST AI RMF / EU AI Act human-oversight expectations. Not legal advice; control sufficiency is determined by the deployer.*
