# EMILIA Protocol Python SDK

The EMILIA Protocol Python SDK provides portable trust evaluation and appeals for counterparties, software, and machine actors.

## Install

```bash
pip install emilia-protocol
```

## Usage

```python
from emilia_protocol import EmiliaClient

ep = EmiliaClient(
    base_url="https://emiliaprotocol.ai",
    api_key="ep_live_...",  # Only needed for write operations
)

# Trust profile — the canonical read surface
profile = ep.get_trust_profile("merchant-xyz")

# Policy evaluation — pass/fail with reasons
result = ep.evaluate_trust(
    entity_id="merchant-xyz",
    policy="strict",
    context={"category": "furniture", "geo": "US-CA"},
)

# Install preflight — should I install this plugin?
preflight = ep.install_preflight(
    entity_id="mcp-server-ep-v1",
    policy="mcp_server_safe_v1",
    context={"host": "mcp", "permission_class": "bounded_external_access"},
)

# File a dispute
ep.file_dispute(
    receipt_id="ep_rcpt_...",
    reason="fraudulent_receipt",
    description="This transaction never occurred.",
)

# Legacy: compatibility score (use trust profiles instead)
score = ep.get_score("merchant-xyz")
```

## Methods

| Method | Description |
|--------|-------------|
| `get_trust_profile(entity_id)` | Full trust profile — behavioral rates, signals, provenance, disputes |
| `evaluate_trust(entity_id, policy, context)` | Evaluate against a trust policy. Returns pass/fail with reasons. |
| `install_preflight(entity_id, policy, context)` | EP-SX: Should I install this? Returns allow/review/deny. |
| `file_dispute(receipt_id, reason, description)` | File a formal dispute against a receipt |
| `report_trust_issue(entity_id, report_type, description)` | Human appeal — no auth required |
| `submit_receipt(...)` | Submit a transaction receipt |
| `get_score(entity_id)` | Legacy: compatibility score only |

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [GitHub](https://github.com/emiliaprotocol/emilia-protocol)
- [EP Core RFC v1.1](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)

Apache 2.0
