# EMILIA Protocol

<!-- GitHub repo description: EMILIA Protocol — Trust enforcement for high-risk actions. Open protocol for pre-action binding, policy-bound verification, one-time consumption, and accountable human signoff. -->

[![CI](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml)

EMILIA Protocol enforces trust before high-risk action.

EP verifies whether a specific high-risk action should proceed under a specific authority context, governing policy, and transaction binding.

---

## What EP Does

EP binds actor identity, authority chain, exact action context, policy version/hash, nonce, and expiry into a single verification envelope. Each envelope is consumed exactly once (no replay). When policy demands it, EP requires named human signoff before execution (Accountable Signoff). Every decision produces an immutable event record.

**Core enforcement properties:**

- **Pre-action binding** — actor, authority, action, and policy are bound before execution, not after
- **One-time consumption** — nonce + expiry enforce single-use; replay is structurally impossible
- **Accountable Signoff** — when policy requires it, a named human must approve before the action proceeds
- **Immutable event traceability** — every trust decision, every policy evaluation, every signoff is recorded and cannot be altered

---

## Where It Fits

- **Government fraud prevention** — benefit redirects, payment destination changes, eligibility overrides
- **Financial infrastructure controls** — wire transfers, beneficiary changes, treasury approvals
- **Enterprise privileged actions** — deployment approvals, configuration changes, access escalation
- **AI/agent execution governance** — delegated authority, tool-use binding, autonomous action gates

---

## Product Stack

| Layer | Description |
|-------|-------------|
| **Open Protocol** | Free, forkable, Apache 2.0. The specification. |
| **Open Runtime** | Self-hosted, full control. Run EP on your infrastructure. |
| **EP Cloud** | Managed policy registry, signoff orchestration, event explorer, audit exports. |
| **EP Enterprise** | VPC deployment, data residency, SSO/SCIM. |
| **Vertical Packs** | Government, Financial, Agent Governance. |

---

## Proof Points

| Metric | Value |
|--------|-------|
| Tests | 1,511 across 58 files |
| TLA+ safety theorems | 19 |
| Alloy facts | 32 |
| Alloy assertions | 15 |
| Red team cases | 85 |
| CI quality gates | 16 |
| Write discipline exceptions | 0 |
| Formal verification | TLA+, Alloy, property-based tests |

---

## Quick Start

See [docs/guides/QUICK_START_INTEGRATION.md](docs/guides/QUICK_START_INTEGRATION.md) for a full walkthrough: register a policy, initiate a handshake, present credentials, verify, and gate an action.

### Install

```bash
npm install emilia-protocol
```

### Environment

```bash
export EP_KEY="ep_live_your_key_here"
export EP_BASE="https://emiliaprotocol.ai"
```

### Run Tests

```bash
npm test
```

---

## Architecture

### EP Core

Three interoperable objects:

- **Trust Receipt** — immutable record of a trust-relevant event
- **Trust Profile** — aggregated trust state for an entity
- **Trust Decision** — policy-bound allow/review/deny determination

### EP Extensions

- **Handshake** — binds actor identity, authority, policy, exact action context, nonce, expiry, and one-time consumption into a replay-resistant authorization flow
- **Accountable Signoff** — requires named human ownership before execution when policy demands it

### Three-Plane Architecture

| Plane | Responsibility |
|-------|---------------|
| **Control** | Policy registration, entity management, configuration |
| **Decision** | Trust evaluation, gate checks, handshake verification |
| **Evidence** | Receipt storage, event traceability, audit export |

### Write Path

All mutations flow through a single canonical write path (`protocolWrite`). A runtime write-guard enforces this invariant — no trust-relevant state change bypasses the protocol layer. Zero exceptions across the entire codebase.

---

## MCP Server

The [MCP server](mcp-server/) gives any Claude conversation or agent pipeline direct access to EP trust-decision surfaces. 34 tools covering trust profiles, policy evaluation, handshake verification, signoff orchestration, and pre-action binding.

```bash
npx @emilia-protocol/mcp-server
```

See [mcp-server/README.md](mcp-server/README.md) for configuration and tool reference.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Links

- Homepage: [emiliaprotocol.ai](https://emiliaprotocol.ai)
- GitHub: [github.com/emiliaprotocol/emilia-protocol](https://github.com/emiliaprotocol/emilia-protocol)
- npm: [@emilia-protocol/mcp-server](https://www.npmjs.com/package/@emilia-protocol/mcp-server)
