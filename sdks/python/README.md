# EMILIA Protocol Python SDK

> **Status: Reference SDK — source-distributed in this repo.** Not yet published to PyPI. Ready to package once EP reaches external pilot stage. Publishing status may vary by release.

The EMILIA Protocol Python SDK provides trust profiles, policy evaluation, install preflight, disputes, and appeals for counterparties, software, and machine actors.

## Install from source

```bash
cd sdks/python
pip install -e .
```

## Usage

```python
from emilia_protocol import EmiliaClient

ep = EmiliaClient(
    base_url="https://emiliaprotocol.ai",
    api_key="ep_live_...",
)

profile = ep.get_trust_profile("merchant-xyz")

result = ep.evaluate_trust(
    entity_id="merchant-xyz",
    policy="strict",
    context={"category": "furniture", "geo": "US-CA"},
)

preflight = ep.install_preflight(
    entity_id="mcp-server-ep-v1",
    policy="mcp_server_safe_v1",
    context={"host": "mcp", "permission_class": "bounded_external_access"},
)
```

## Methods

- `get_trust_profile(entity_id)` — canonical trust profile read surface
- `evaluate_trust(entity_id, policy, context)` — evaluate against a trust policy
- `install_preflight(entity_id, policy, context)` — software/plugin install decision
- `submit_receipt(...)` — submit a transaction receipt
- `file_dispute(...)` — file a formal dispute
- `report_trust_issue(...)` — human appeal/reporting path
- `get_score(entity_id)` — legacy compatibility score only

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [EP Core RFC](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)
- [Conformance Vectors](https://github.com/emiliaprotocol/emilia-protocol/tree/main/conformance)

Apache 2.0


## Publish readiness

This SDK is structured to support clean packaging and release workflows. The repository includes GitHub Actions publish workflows for npm or PyPI once the package is ready to be released publicly.
