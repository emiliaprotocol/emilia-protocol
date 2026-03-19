# EMILIA Protocol Python SDK

**Portable trust for machine counterparties.**

The EMILIA Protocol Python SDK gives agents, services, and developers
programmatic access to EP trust profiles, policy evaluation, receipt
submission, disputes, delegations, identity continuity, and more.

[![PyPI](https://img.shields.io/pypi/v/emilia-protocol)](https://pypi.org/project/emilia-protocol/)
[![Python](https://img.shields.io/pypi/pyversions/emilia-protocol)](https://pypi.org/project/emilia-protocol/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

---

## Installation

```bash
pip install emilia-protocol
```

Requires Python 3.9+ and [`httpx`](https://www.python-httpx.org/) (installed automatically).

---

## Quick start

```python
import asyncio
import emilia_protocol as ep

async def main():
    async with ep.EPClient(api_key="ep_live_...") as client:
        # 1. Pull the canonical trust profile
        profile = await client.trust_profile("merchant-xyz")
        print(profile.current_confidence)   # "established"
        print(profile.receipt_count)        # 1 482

        # 2. Evaluate against a policy before high-value actions
        result = await client.trust_evaluate(
            "merchant-xyz",
            policy="strict",
            context={"category": "electronics", "value_band": "high"},
        )
        if result["decision"] == "allow":
            print("Good to go.")

asyncio.run(main())
```

---

## Authentication

Set your API key via the environment variable (recommended):

```bash
export EP_API_KEY="ep_live_..."
```

Or pass it directly to the client:

```python
client = ep.EPClient(api_key="ep_live_...")
```

Read-only endpoints (trust profiles, leaderboard, entity search, dispute status,
policy listing) require no authentication.  Write endpoints (submit receipt, file
dispute, appeal, create delegation) require an API key.

---

## Async context manager (recommended)

```python
async with ep.EPClient() as client:
    profile = await client.trust_profile("my-agent")
```

The context manager ensures the underlying connection pool is closed cleanly.

---

## Sync usage pattern

Wrap any coroutine with `asyncio.run()` for scripts and notebooks:

```python
import asyncio, emilia_protocol as ep

async def check(entity_id: str):
    async with ep.EPClient() as client:
        return await client.trust_profile(entity_id)

profile = asyncio.run(check("merchant-xyz"))
print(profile.current_confidence)
```

---

## Error handling

```python
from emilia_protocol import EPError

try:
    profile = await client.trust_profile("unknown-entity")
except EPError as e:
    print(e)          # human-readable message
    print(e.status)   # HTTP status code, e.g. 404
    print(e.code)     # machine-readable error code (if provided by API)
```

All network timeouts and connection failures are also wrapped in `EPError`.

---

## Environment variables

| Variable      | Description                               | Default                       |
|---------------|-------------------------------------------|-------------------------------|
| `EP_API_KEY`  | Your EP API key (`ep_live_...`)           | *(none — required for writes)* |
| *(none)*      | Base URL is hard-coded to production      | `https://emiliaprotocol.ai`   |

Override the base URL programmatically for testing:

```python
client = ep.EPClient(base_url="http://localhost:3000")
```

---

## API reference

### Trust Profile & Evaluation

#### `trust_profile(entity_id)`

The canonical trust read surface. Returns an `EntityTrustProfile` dataclass
with behavioral rates, signal scores, provenance composition, anomaly alerts,
confidence level, and dispute summary. **Use this before transacting with any
counterparty or installing any software.**

```python
profile = await client.trust_profile("merchant-xyz")

print(profile.current_confidence)           # "established" | "emerging" | "pending" | …
print(profile.historical_establishment)     # True/False
print(profile.receipt_count)

if profile.trust_profile:
    print(profile.trust_profile.behavioral.completion_rate)
    print(profile.trust_profile.signals.delivery_accuracy)
    print(profile.trust_profile.provenance.bilateral_rate)

if profile.anomaly:
    print(f"ANOMALY: {profile.anomaly.type} — {profile.anomaly.alert}")
```

#### `trust_evaluate(entity_id, policy, context)`

Policy-gated evaluation. Returns a Trust Decision (allow/review/deny) with specific failure reasons.

```python
result = await client.trust_evaluate(
    "merchant-xyz",
    policy="strict",                      # "strict" | "standard" | "permissive" | "discovery"
    context={"category": "furniture", "geo": "US-CA"},
)

print(result["decision"])       # "allow" | "review" | "deny"
print(result["confidence"])     # "established"
print(result["reasons"])        # ["insufficient_evidence", …]
print(result["warnings"])       # ["anomaly_detected", …]
```

#### `trust_gate(entity_id, action, policy, value_usd, delegation_id)`

Pre-action trust gate for agent decision loops.

```python
gate = await client.trust_gate(
    "merchant-xyz",
    action="purchase",
    policy="standard",
    value_usd=450.00,
)

if gate["decision"] == "allow":
    await checkout()
elif gate["decision"] == "review":
    await human_review()
else:
    raise RuntimeError("Trust gate denied.")
```

#### `domain_score(entity_id, domains)`

Domain-specific trust scores.

```python
scores = await client.domain_score(
    "my-agent",
    domains=["financial", "delegation", "code_execution"],
)
```

#### `install_preflight(entity_id, policy, context)`

EP-SX: Software install trust check.

```python
result = await client.install_preflight(
    "mcp-server-ep-v1",
    policy="mcp_server_safe_v1",
    context={
        "host": "mcp",
        "permission_class": "bounded_external_access",
    },
)

print(result["decision"])       # "allow" | "review" | "deny"
print(result["reasons"])        # list of reason strings
print(result["confidence"])
print(result["software_meta"]["publisher_verified"])
```

---

### Entities

#### `register_entity(entity_id, display_name, entity_type, description, capabilities)`

Register a new entity. Public — no API key required. **Save the returned API key
immediately; it will not be shown again.**

```python
result = await client.register_entity(
    entity_id="my-cool-agent",
    display_name="My Cool Agent",
    entity_type="agent",
    description="Handles e-commerce checkout flows autonomously.",
    capabilities=["checkout", "purchase", "refund"],
)

api_key = result["api_key"]     # ep_live_... — save this!
entity  = result["entity"]
```

Valid `entity_type` values:
`"agent"` · `"merchant"` · `"service_provider"` · `"github_app"` ·
`"github_action"` · `"mcp_server"` · `"npm_package"` · `"chrome_extension"` ·
`"shopify_app"` · `"marketplace_plugin"` · `"agent_tool"`

#### `search_entities(query, entity_type)`

```python
results = await client.search_entities(
    "shopify checkout automation",
    entity_type="merchant",
)
for entity in results["entities"]:
    print(entity["entity_id"], entity["confidence"])
```

#### `leaderboard(limit, entity_type)`

```python
top = await client.leaderboard(limit=20, entity_type="agent")
for entry in top["leaderboard"]:
    print(f"#{entry['rank']} {entry['display_name']} ({entry['entity_id']})")
```

---

### Receipts

#### `submit_receipt(...)`

```python
receipt = await client.submit_receipt(
    entity_id="merchant-xyz",
    transaction_ref="order-8812",           # unique external reference
    transaction_type="purchase",            # "purchase" | "service" | "task_completion" | "delivery" | "return"
    agent_behavior="completed",             # strongest signal — "completed" | "retried_same" | "retried_different" | "abandoned" | "disputed"
    delivery_accuracy=97,                   # 0–100
    product_accuracy=100,
    price_integrity=100,
    return_processing=None,
    claims={
        "delivered": True,
        "on_time": True,
        "price_honored": True,
        "as_described": True,
    },
    evidence={"tracking_url": "https://track.example.com/8812"},
    context={"category": "electronics", "geo": "US-CA"},
)

print(receipt["receipt"]["receipt_id"])     # ep_rcpt_...
print(receipt["receipt"]["receipt_hash"])
```

#### `batch_submit(receipts)`

Submit up to 50 receipts atomically.

```python
result = await client.batch_submit([
    {
        "entity_id": "merchant-a",
        "transaction_ref": "t-001",
        "transaction_type": "purchase",
        "agent_behavior": "completed",
    },
    {
        "entity_id": "merchant-b",
        "transaction_ref": "t-002",
        "transaction_type": "service",
        "agent_behavior": "abandoned",
    },
])
```

#### `verify_receipt(receipt_id)`

```python
v = await client.verify_receipt("ep_rcpt_abc123")
print(v["verified"])    # True
print(v["anchored"])    # True — included in on-chain Merkle root
```

---

### Disputes & Appeals

#### `file_dispute(receipt_id, reason, description, evidence)`

```python
dispute = await client.file_dispute(
    receipt_id="ep_rcpt_abc123",
    reason="fraudulent_receipt",            # see DisputeReason below
    description="This receipt was not submitted by us.",
    evidence={"screenshot": "https://..."},
)
print(dispute["dispute_id"])               # ep_disp_...
print(dispute["response_deadline"])
```

Valid `reason` values:
`"fraudulent_receipt"` · `"inaccurate_signals"` · `"identity_dispute"` ·
`"context_mismatch"` · `"duplicate_transaction"` · `"coerced_receipt"` · `"other"`

#### `dispute_status(dispute_id)`

```python
status = await client.dispute_status("ep_disp_xyz")
print(status["status"])         # "pending" | "upheld" | "reversed" | "dismissed"
print(status["resolution"])
```

#### `appeal_dispute(dispute_id, reason, evidence)`

```python
appeal = await client.appeal_dispute(
    dispute_id="ep_disp_xyz",
    reason="The resolution ignored the delivery confirmation screenshot.",
    evidence={"screenshot_url": "https://..."},
)
print(appeal["appeal_id"])
```

#### `report_trust_issue(entity_id, report_type, description, contact_email)`

No authentication required. For human escalation paths.

```python
report = await client.report_trust_issue(
    entity_id="merchant-xyz",
    report_type="harmed_by_trusted_entity",
    description="They charged me twice and refused to refund.",
    contact_email="alice@example.com",
)
print(report["report_id"])
```

Valid `report_type` values:
`"wrongly_downgraded"` · `"harmed_by_trusted_entity"` · `"fraudulent_entity"` ·
`"inaccurate_profile"` · `"other"`

---

### Delegation

#### `create_delegation(principal_id, agent_entity_id, scope, ...)`

Authorise an agent to act on behalf of a principal.

```python
delegation = await client.create_delegation(
    principal_id="ep_principal_abc",
    agent_entity_id="my-agent-v1",
    scope=["purchase", "service"],
    max_value_usd=500.00,
    expires_at="2026-12-31T23:59:59Z",
    constraints={"geo": "US"},
)
delegation_id = delegation["delegation_id"]
```

#### `verify_delegation(delegation_id, action_type)`

```python
result = await client.verify_delegation(
    "ep_del_abc123",
    action_type="purchase",
)
assert result["valid"]
```

---

### Identity Continuity (EP-IX)

#### `principal_lookup(principal_id)`

```python
data = await client.principal_lookup("ep_principal_abc")
principal = data["principal"]
print(principal["display_name"], principal["status"])

for entity in data.get("entities", []):
    print(entity["entity_id"], entity["entity_type"])

for binding in data.get("bindings", []):
    print(binding["binding_type"], binding["binding_target"])
```

#### `lineage(entity_id)`

Detect suspicious continuity gaps or trust whitewashing.

```python
lineage = await client.lineage("merchant-xyz-v2")

for pred in lineage.get("predecessors", []):
    print(f"← {pred['from']} ({pred['reason']}) [{pred['status']}]")

for succ in lineage.get("successors", []):
    print(f"→ {succ['to']} ({succ['reason']}) [{succ['status']}]")
```

---

### Policies

#### `list_policies()`

Discover available trust policies.

```python
data = await client.list_policies()
for policy in data["policies"]:
    print(f"{policy['name']} [{policy['family']}]")
    print(f"  {policy['description']}")
    print(f"  min confidence: {policy.get('min_confidence', 'n/a')}")
```

---

## Type reference

| Type | Values |
|------|--------|
| `EntityType` | `"agent"` `"merchant"` `"service_provider"` `"github_app"` `"github_action"` `"mcp_server"` `"npm_package"` `"chrome_extension"` `"shopify_app"` `"marketplace_plugin"` `"agent_tool"` |
| `AgentBehavior` | `"completed"` `"retried_same"` `"retried_different"` `"abandoned"` `"disputed"` |
| `TransactionType` | `"purchase"` `"service"` `"task_completion"` `"delivery"` `"return"` |
| `TrustPolicy` | `"strict"` `"standard"` `"permissive"` `"discovery"` |
| `TrustDecision` | `"allow"` `"review"` `"deny"` |
| `DisputeReason` | `"fraudulent_receipt"` `"inaccurate_signals"` `"identity_dispute"` `"context_mismatch"` `"duplicate_transaction"` `"coerced_receipt"` `"other"` |
| `ReportType` | `"wrongly_downgraded"` `"harmed_by_trusted_entity"` `"fraudulent_entity"` `"inaccurate_profile"` `"other"` |
| `TrustDomain` | `"financial"` `"code_execution"` `"communication"` `"delegation"` `"infrastructure"` `"content_creation"` `"data_access"` |

---

## Development

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol
cd emilia-protocol/sdks/python
pip install -e ".[dev]"
```

---

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [EP Core RFC](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)
- [Conformance Vectors](https://github.com/emiliaprotocol/emilia-protocol/tree/main/conformance)
- [MCP Server](https://github.com/emiliaprotocol/emilia-protocol/tree/main/mcp-server)

---

Apache 2.0 — Copyright EMILIA Protocol contributors.
