# EMILIA Protocol TypeScript SDK

> **Status: Reference SDK — source-distributed in this repo.** Not yet published to npm. Ready to package once EP reaches external pilot stage. Publishing status may vary by release.

The EMILIA Protocol TypeScript SDK provides trust profiles, policy evaluation, install preflight, disputes, and appeals for counterparties, software, and machine actors.

## Install from source

```bash
cd sdks/typescript
npm install
npm run build
```

## Usage

```typescript
import { EmiliaClient } from './dist/index.js';

const ep = new EmiliaClient({
  baseUrl: 'https://emiliaprotocol.ai',
  apiKey: 'ep_live_...'
});

const profile = await ep.getTrustProfile('merchant-xyz');

const result = await ep.evaluateTrust({
  entityId: 'merchant-xyz',
  policy: 'strict',
  context: { category: 'furniture', geo: 'US-CA' }
});

const preflight = await ep.installPreflight({
  entityId: 'mcp-server-ep-v1',
  policy: 'mcp_server_safe_v1',
  context: { host: 'mcp', permission_class: 'bounded_external_access' }
});
```

## Methods

- `getTrustProfile(entityId)` — canonical trust profile read surface
- `evaluateTrust({ entityId, policy, context })` — evaluate against a trust policy
- `installPreflight({ entityId, policy, context })` — software/plugin install decision
- `submitReceipt(...)` — submit a transaction receipt
- `fileDispute(...)` — file a formal dispute
- `reportTrustIssue(...)` — human appeal/reporting path
- `getScore(entityId)` — legacy compatibility score only

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [EP Core RFC](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)
- [Conformance Vectors](https://github.com/emiliaprotocol/emilia-protocol/tree/main/conformance)

Apache 2.0


## Publish readiness

This SDK is structured to support clean packaging and release workflows. The repository includes GitHub Actions publish workflows for npm or PyPI once the package is ready to be released publicly.
