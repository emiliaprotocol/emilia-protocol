# EMILIA Protocol TypeScript SDK

The EMILIA Protocol TypeScript SDK provides trust profiles, policy evaluation, install preflight, disputes, and appeals for counterparties, software, and machine actors.

## Install

```bash
npm install @emilia-protocol/sdk
```

## Usage

```typescript
import { EmiliaClient } from '@emilia-protocol/sdk';

const ep = new EmiliaClient({
  baseUrl: 'https://emiliaprotocol.ai',
  apiKey: 'ep_live_...', // Only needed for write operations
});

// Trust profile — the canonical read surface
const profile = await ep.getTrustProfile('merchant-xyz');

// Policy evaluation — pass/fail with reasons
const result = await ep.evaluateTrust({
  entityId: 'merchant-xyz',
  policy: 'strict',
  context: { category: 'furniture', geo: 'US-CA' },
});

// Install preflight — should I install this plugin?
const preflight = await ep.installPreflight({
  entityId: 'mcp-server-ep-v1',
  policy: 'mcp_server_safe_v1',
  context: { host: 'mcp', permission_class: 'bounded_external_access' },
});

// File a dispute
await ep.fileDispute({
  receiptId: 'ep_rcpt_...',
  reason: 'fraudulent_receipt',
  description: 'This transaction never occurred.',
});

// Legacy: compatibility score (use trust profiles instead)
const score = await ep.getScore('merchant-xyz');
```

## Methods

| Method | Description |
|--------|-------------|
| `getTrustProfile(entityId)` | Full trust profile — behavioral rates, signals, provenance, disputes |
| `evaluateTrust({ entityId, policy, context })` | Evaluate against a trust policy. Returns pass/fail with reasons. |
| `installPreflight({ entityId, policy, context })` | EP-SX: Should I install this? Returns allow/review/deny. |
| `fileDispute({ receiptId, reason, description })` | File a formal dispute against a receipt |
| `reportTrustIssue({ entityId, reportType, description })` | Human appeal — no auth required |
| `submitReceipt({ ... })` | Submit a transaction receipt |
| `getScore(entityId)` | Legacy: compatibility score only |

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [GitHub](https://github.com/emiliaprotocol/emilia-protocol)
- [EP Core RFC v1.1](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)

Apache 2.0
