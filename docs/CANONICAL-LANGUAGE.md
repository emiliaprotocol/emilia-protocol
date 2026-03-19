# EP Canonical Language

This document defines the authoritative vocabulary for all EMILIA Protocol documentation, APIs, SDKs, and product surfaces.

## Core Statements

- **EMILIA Protocol is an open protocol for making, explaining, challenging, and verifying trust decisions about agents, software, and machine counterparties.**
- **MCP tells agents how to use tools. EP tells them whether they should.**
- **The protocol is free. The control plane is paid.**
- **No high-stakes machine action should proceed without a signed EP Commit.**

## Canonical Object Model

The primary evaluation result is a **Trust Decision** (allow/review/deny), not a boolean.

### Trust Decision Object
| Field | Type | Description |
|---|---|---|
| `decision` | `allow \| review \| deny` | The trust verdict |
| `reasons` | `Reason[]` | Structured explanations for the decision |
| `warnings` | `Warning[]` | Non-blocking concerns |
| `appeal_path` | `string \| null` | How to challenge this decision |
| `policy_used` | `PolicyRef` | Which policy version produced this result |
| `confidence` | `number` | Protocol confidence in the decision (0-1) |

### Deprecated Vocabulary
The following terms are **deprecated** and should not appear in new code, docs, or API surfaces:
- `pass: boolean` -> use `decision: 'allow'`
- `fail` -> use `decision: 'deny'`
- `trust_pass` -> use `decision`
- `failures: string[]` -> use `reasons` with `type: 'denial_reason'`
- `compat_score` -> use `confidence` or remove
- `evaluation_result: pass | fail` -> use `decision: allow | review | deny`

### Migration Status
As of v1.1, all public API surfaces (`/api/trust/evaluate`, `/api/needs/broadcast`, `/api/trust/install-preflight`),
the OpenAPI spec, the TypeScript SDK types, and PROTOCOL-STANDARD.md use `TrustDecision` as the canonical object.
Legacy fields (`pass`, `trust_pass`, `failures`) are retained with `deprecated: true` for backward compatibility
and are derived from the canonical `decision` field.

### Enforcement
All PRs that introduce deprecated vocabulary in public API surfaces, docs, or SDK exports must be flagged.
