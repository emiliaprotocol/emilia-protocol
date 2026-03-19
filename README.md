# EMILIA Protocol

[![CI](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/emiliaprotocol/emilia-protocol/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-670%20passing-brightgreen)]()
[![MCP Tools](https://img.shields.io/badge/MCP%20tools-24-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**MCP tells agents how to use tools. EP tells them whether they should.**

---

## What is EP?

EMILIA Protocol is a portable, open behavioral trust layer for machine actors. It computes probabilistic, policy-shaped, contextual, and contestable trust profiles from cryptographically anchored receipts — not binary scores from a single source. Any agent, operator, or host can evaluate a counterparty against a structured trust policy, file a dispute, appeal a decision, and verify the result independently.

EP is not a product. It is a protocol. Apache 2.0.

---

## EP Core / EP Extensions / EP Product Surfaces

EP is a 3-layer system. The core is deliberately small. Everything else is an optional extension or a product surface built on top.

- **EP Core** — The interoperable standard. Three required objects: **Trust Receipt**, **Trust Profile**, **Trust Decision**. If a third party can implement these three objects and interoperate, EP has a real standard. Core also covers the scoring model, policy evaluation, entity identity, and Sybil resistance (Sections 1–6, 9–12, 17 of the Protocol Standard).

- **EP Extensions** — Important but optional capabilities that build on the core. Adopt what you need:
  - Disputes and appeals (full lifecycle, voucher-based adjudication)
  - Delegation and attribution chain (Principal → Agent → Tool)
  - Zero-knowledge proofs (privacy-preserving trust attestation)
  - Auto-receipt generation (passive behavioral data from MCP tool calls)
  - Domain-specific scoring (financial, code_execution, communication, +4)
  - Install preflight adapters (MCP servers, npm, GitHub Apps, Chrome extensions)

- **EP Product Surfaces** — Reference implementations and operator tools. Useful, not required, not part of the standard:
  - Explorer, leaderboards, registry views
  - Operator dashboards and managed adjudication
  - Hosted trust APIs, analytics, and enterprise policy management

A skeptical reader should be able to answer in 30 seconds: Core = the minimum interoperable standard (Receipt, Profile, Decision). Extensions = advanced features you opt into. Product Surfaces = tools built on top, not governed by the spec.

---

## Four Canonical Trust Decisions

EP is decision infrastructure. Every trust evaluation reduces to one of four verbs:

| Decision | Question |
|----------|----------|
| **Install** | Should I install this MCP server? |
| **Connect** | Should I connect this tool? |
| **Delegate** | Should this agent act for this principal? |
| **Transact** | Should I transact with this counterparty? |

---

## Three Core Objects

EP standardizes three interoperable objects:

| Object | What it is | One-line |
|--------|-----------|---------|
| **Trust Receipt** | A portable record of an observed event relevant to trust | What happened |
| **Trust Profile** | A standardized summary of observable trust state | What is known |
| **Trust Decision** | A policy-evaluated result with reasons and appeal path | What to do now |

If a third party can implement these three objects and interoperate, EP has a real standard.

---

## Beachhead: Three winning wedges [Live]

EP does not launch as "universal trust." It launches as the safest way to install and route to machine tools, with a credible appeals system. These are the three concrete problems it solves today:

**1. MCP server trust** — Before a host installs an MCP server, EP runs install preflight: publisher verification, permission class evaluation, provenance tier, and incident history against a host-specific policy. The answer is `allow`, `warn`, or `deny` — with reasons.

**2. Software install preflight** — Same evaluation for npm packages, GitHub Apps, Chrome extensions, and marketplace plugins. Agents making autonomous install decisions need a non-self-reported signal.

**3. Appeals** — Trust systems that can harm a party without recourse are control systems. EP ships a constitutional dispute lifecycle: file → evidence → adjudication → appeal → reversal. Voucher voting, 48-hour procedural window, receipt weight dampening on active disputes.

---

## Quick Install

```bash
# MCP server — add to your agent's mcp config
npx @emilia-protocol/mcp-server
```

```json
{
  "mcpServers": {
    "emilia": {
      "command": "npx",
      "args": ["@emilia-protocol/mcp-server"]
    }
  }
}
```

---

## Primary API Examples

### Trust evaluate — should I transact with this counterparty?

```bash
POST /api/trust/evaluate
{
  "entity_id": "merchant-xyz",
  "policy": "strict"
}

→ {
    "pass": true,
    "score": 87.3,
    "confidence": "confident",
    "profile": {
      "behavioral": { "completion_rate": 94.3, "dispute_rate": 0.7 },
      "signals": { "delivery_accuracy": 89.1, "price_integrity": 99.1 }
    }
  }
```

### Install preflight — should I install this MCP server?

```bash
POST /api/trust/install-preflight
{
  "entity_id": "mcp-server-ep-v1",
  "policy": "mcp_server_safe_v1",
  "context": { "host": "mcp", "permission_class": "bounded_external_access" }
}

→ {
    "decision": "allow",
    "reasons": [
      "publisher_verified",
      "provenance_verified",
      "permission_class_acceptable"
    ]
  }
```

### Zero-knowledge proof — prove a score threshold without revealing counterparties

```bash
POST /api/trust/zk-proof/generate
{
  "entity_id": "merchant-xyz",
  "claim": { "field": "score", "operator": "gte", "threshold": 75 }
}

→ { "proof": "...", "public_inputs": { "claim_satisfied": true } }

POST /api/trust/zk-proof/verify
{ "proof": "...", "public_inputs": { "claim_satisfied": true } }

→ { "valid": true }
```

### Trust gate — pre-action canonical check

```bash
POST /api/trust/gate
{
  "entity_id": "agent-abc",
  "action": "process_payment",
  "value_usd": 500,
  "policy": "strict"
}

→ { "gate": "pass", "score": 81.2, "policy_result": { "pass": true } }
```

---

## How trust accumulates from day one

EP's bootstrap problem is real. Here is how trust signals accumulate before a counterparty has history:

| Signal source | Weight | Notes |
|---|---|---|
| Auto-receipt (opt-in) | ~0.1–0.3x until established | Every tool call generates a behavioral receipt. Opt-in, privacy-preserving. |
| Bilateral confirmations | 0.8x provenance | Both parties confirm the transaction. Stronger than self-attested. |
| Install preflight pass | Context signal | Publisher verification and permission class feed the profile. |
| Principal signal | 0.15x | The human behind the entity carries partial attribution. |

An entity reaches `emerging` confidence once quality-gated effective evidence ≥ 5.0 (3+ unique submitters, unestablished capped at 2.0). Volume alone from synthetic identities cannot cross this barrier — that is by design.

Receipt weight is dampened further by dispute state: 0.3x while a dispute is active, 0.0x if upheld, 1.0x if dismissed.

---

## What's Live, Extensions, and Roadmap

| Component | Status |
|---|---|
| Trust profile + policy evaluation (strict / standard / permissive / discovery) | [Live] |
| Install preflight: MCP servers, GitHub Apps, npm, Chrome extensions [Experimental] | [Live] |
| Dispute + appeals lifecycle (10-state machine, constitutional due process) | [Live] |
| Auto-receipt generation (opt-in, privacy-preserving) | [Live] |
| Trust-graph dispute adjudication (voucher voting, 48h window) | [Live] |
| Receipt weight dampening (0.3x active, 0.0x upheld, 1.0x dismissed) | [Live] |
| Attribution chain (Principal → Agent → Tool, 0.15x principal signal) | [Live] |
| Delegation judgment scoring (excellent / good / fair / poor) | [Live] |
| Zero-knowledge proofs (prove score > threshold, no counterparty reveal) | [Live] |
| Domain-specific scoring (financial, code_execution, communication, +4) | [Live] |
| Trust gate (pre-action canonical check) | [Live] |
| Identity continuity — EP-IX (principals, lineage, whitewashing resistance) | [Live] |
| Blockchain anchoring (Merkle roots → Base L2) | [Live] |
| TypeScript SDK (EPClient, 25 methods, 35+ types) | [Live] |
| Python SDK (async EPClient, 21 methods) | [Live] |
| MCP server (24 tools, 4 resources, 3 prompts) | [Live] |
| 670 tests passing, 28 test files | [Live] |
| Operator applications and registry | [Pilot] |
| Managed adjudication workflows | [Pilot] |
| Oracle verification (Phase 3 provenance) | [Roadmap] |
| GraphQL API | [Roadmap] |
| Mobile SDK | [Roadmap] |
| Webhook streaming | [Roadmap] |

---

## What EP Does Not Do

- Decide morality
- Infer intent beyond presented evidence
- Force one global score interpretation
- Replace identity or authorization standards
- Replace marketplace rules or legal adjudication
- Require full public disclosure of counterparties or transaction details

---

## MCP Tools (24)

Add `npx @emilia-protocol/mcp-server` to any MCP-compatible host. The server exposes 24 tools, 4 resources, and 3 prompts.

**Trust evaluation**
| Tool | What it does |
|---|---|
| `ep_trust_profile` | Full trust profile for any entity |
| `ep_trust_evaluate` | Evaluate entity against a named policy |
| `ep_trust_gate` | Pre-action gate: pass/warn/deny with reasons |
| `ep_domain_score` | Score in a specific domain (financial, code_execution, etc.) |
| `ep_list_policies` | List all available trust policies |

**Install preflight**
| Tool | What it does |
|---|---|
| `ep_install_preflight` | Preflight check for MCP servers, npm packages, GitHub Apps, Chrome extensions |

**Receipts**
| Tool | What it does |
|---|---|
| `ep_submit_receipt` | Submit a trust receipt for a transaction |
| `ep_batch_submit` | Submit multiple receipts in one call |
| `ep_verify_receipt` | Verify a receipt's cryptographic integrity |
| `ep_configure_auto_receipt` | Enable/disable auto-receipt generation per session |

**Disputes and appeals**
| Tool | What it does |
|---|---|
| `ep_dispute_file` | File a dispute against a receipt |
| `ep_dispute_status` | Check dispute status and procedural state |
| `ep_appeal_dispute` | File an appeal on a closed dispute |
| `ep_report_trust_issue` | Report a trust concern (no auth required) |

**Identity and delegation**
| Tool | What it does |
|---|---|
| `ep_register_entity` | Register a new entity |
| `ep_principal_lookup` | Look up a principal and their entities |
| `ep_lineage` | Get entity lineage and continuity chain |
| `ep_create_delegation` | Create a delegation from principal to agent |
| `ep_verify_delegation` | Verify a delegation record |
| `ep_delegation_judgment` | Score a principal's delegation history |

**Zero-knowledge proofs**
| Tool | What it does |
|---|---|
| `ep_generate_zk_proof` | Generate a ZK proof for a score claim |
| `ep_verify_zk_proof` | Verify a ZK proof |

**Discovery**
| Tool | What it does |
|---|---|
| `ep_search_entities` | Search entities by type, name, or score range |
| `ep_leaderboard` | Top entities by trust score within a type |

**Resources:** Entity Trust Profile, Entity Trust Score, Receipt, Delegation Record

**Prompts:** `trust_decision`, `receipt_quality_check`, `install_decision`

---

## Protocol Standard

EP is specified as an implementation-independent standard. 17 sections covering the full protocol. Any conformant implementation must produce identical outputs to the reference conformance fixtures.

[PROTOCOL-STANDARD.md](docs/PROTOCOL-STANDARD.md) — 17 sections:

1. Introduction (motivation, design principles, terminology)
2. Entity Identity
3. Receipt Format
4. Trust Scoring
5. Sybil Resistance
6. Policy Evaluation
7. Delegation Chain
8. Dispute Lifecycle
9. Security Properties
10. Implementation Requirements
11. Versioning
12. Governance
13. Privacy and Zero-Knowledge Proofs
14. Dispute Adjudication Standard
15. Attribution Chain Standard
16. Auto-Receipt Generation
17. Conformance Requirements

**Falsifiable by design:** anyone can run `npx vitest run` and `python3 conformance/verify_hashes.py` to verify the evaluator produces canonical outputs. Trust that cannot be independently verified is not trust.

---

## Conformance and Testing

| Suite | Tests | What it covers |
|---|---|---|
| `tests/scoring.test.js` | 21 | v1 scoring, effective evidence, Sybil resistance |
| `tests/scoring-v2.test.js` | 14 | v2 trust profiles, policy evaluation, anomaly detection |
| `tests/protocol.test.js` | 36 | Hash determinism, confidence semantics, context fallback |
| `tests/integration.test.js` | 19 | Route-level: provenance, context, disputes, software policies |
| `tests/adversarial.test.js` | 14 | Sybil farms, reciprocal loops, cluster collusion, trust farming |
| `tests/e2e-flows.test.js` | 15 | Full lifecycle: register → receipts → profile → policy → dispute → reversal |
| `tests/attribution.test.js` | — | Attribution chain: Principal→Agent→Tool signal weighting |
| `tests/auto-receipt.test.js` | — | Auto-receipt generation and opt-in mechanics |
| `tests/blockchain.test.js` | — | Merkle anchoring to Base L2 |
| `tests/delegation-judgment.test.js` | — | Delegation scoring, grade thresholds, graceful degradation |
| `tests/dispute-adjudication.test.js` | — | Voucher voting, weight dampening, procedural states |
| `tests/signatures.test.js` | — | Cryptographic receipt signatures |
| `tests/zk-proofs.test.js` | — | ZK proof generation and verification |
| `conformance/conformance.test.js` | 26 | Canonical hash vectors, scoring fixtures, policy replay |

**Cross-language:** `conformance/verify_hashes.py` produces identical SHA-256 outputs to the JavaScript reference — the protocol is language-independent.

```bash
npm test
# or
npx vitest run
python3 conformance/verify_hashes.py
```

670 tests passing across 28 test files.

---

## SDKs

### TypeScript

```bash
npm install @emilia-protocol/sdk
```

```typescript
import { EPClient } from '@emilia-protocol/sdk';

const ep = new EPClient({ baseUrl: 'https://emiliaprotocol.ai', apiKey: 'ep_live_...' });

const profile = await ep.getTrustProfile('merchant-xyz');
const result  = await ep.evaluate('merchant-xyz', 'strict');
const check   = await ep.installPreflight('mcp-server-ep-v1', 'mcp_server_safe_v1');
const proof   = await ep.generateZkProof('merchant-xyz', { field: 'score', operator: 'gte', threshold: 75 });
```

25 methods, 35+ types. See [sdks/typescript/README.md](sdks/typescript/README.md).

### Python

```bash
pip install emilia-protocol
```

```python
from emilia_protocol import EPClient

ep = EPClient(base_url="https://emiliaprotocol.ai", api_key="ep_live_...")

profile = await ep.get_trust_profile("merchant-xyz")
result  = await ep.evaluate("merchant-xyz", "strict")
check   = await ep.install_preflight("mcp-server-ep-v1", "mcp_server_safe_v1")
```

21 methods, fully async. See [sdks/python/README.md](sdks/python/README.md).

---

## Running Locally

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
npm install
cp .env.example .env
# Add Supabase and optionally Upstash Redis credentials
npm run dev
```

Requires a Supabase-compatible HTTP API (hosted or self-hosted with PostgREST). A raw Postgres container is not sufficient.

```bash
# Docker
export NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
export SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
docker compose up --build
```

### CLI

```bash
npx @emilia-protocol/cli profile merchant-xyz
npx @emilia-protocol/cli evaluate merchant-xyz --policy strict
npx @emilia-protocol/cli preflight mcp-server-xyz --policy mcp_server_safe_v1
npx @emilia-protocol/cli dispute receipt_abc --reason fraudulent_receipt
npx @emilia-protocol/cli appeal disp_xyz --reason "Resolution was incorrect because..."
```

Set `EP_BASE_URL` and `EP_API_KEY` for non-default endpoints.

---

## Canonical Paths

| What | Where |
|---|---|
| Scoring engine | `lib/scoring-v2.js` |
| Canonical evaluator | `lib/canonical-evaluator.js` |
| Canonical writer | `lib/canonical-writer.js` |
| Dispute state machine | `lib/procedural-justice.js` |
| Protocol specification | `docs/PROTOCOL-STANDARD.md` |
| Conformance fixtures | `conformance/fixtures.json` |
| Policy definitions | `lib/scoring-v2.js` → `TRUST_POLICIES` |
| OpenAPI spec | `openapi.yaml` |
| MCP server | `mcp-server/index.js` |
| CLI | `cli/bin/ep.mjs` |

### Internal Routes (not part of the public API)

These routes require privileged authentication (`CRON_SECRET`) and are excluded from the public API surface. They are tagged `x-internal: true` in `openapi.yaml`.

| Route | Access | Purpose |
|---|---|---|
| `GET /api/cron/expire` | cron | Expire stale bilateral confirmations, escalate overdue disputes |
| `POST /api/blockchain/anchor` | cron | Anchor unanchored receipts to Base L2 via Merkle tree |
| `POST /api/disputes/resolve` | operator | Operator resolves a dispute |
| `POST /api/disputes/appeal/resolve` | operator | Operator resolves an appeal |

---

## Docs

- [Protocol Standard](docs/PROTOCOL-STANDARD.md) — implementation-independent specification
- [EP Core RFC](docs/EP-CORE-RFC.md) — original protocol RFC
- [EP-SX Software Trust](docs/EP-SX-SOFTWARE-TRUST.md) — install preflight specification
- [EP-IX Identity Continuity](docs/EP-IX-IDENTITY-CONTINUITY.md) — principal binding, whitewashing resistance
- [Security](SECURITY.md) — threat model, mitigations, cryptographic specs
- [Contributing](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Conformance Fixtures](conformance/fixtures.json) — canonical test vectors

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Protocol changes require a spec update to [PROTOCOL-STANDARD.md](docs/PROTOCOL-STANDARD.md) alongside any implementation change.

## License

Apache 2.0
