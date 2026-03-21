# EP SDK Design

> **One-liner**: The EP SDK lets you add trust decisions to any workflow in 5
> lines of code.

This document defines the minimal SDK surface for integrating with the
EMILIA Protocol. The SDK wraps the protocol-essential endpoints and hides
HTTP, authentication, and error handling behind a clean TypeScript API.

---

## Minimal API Surface

```typescript
import { EmiliaProtocol } from '@emilia-protocol/sdk';

const ep = new EmiliaProtocol({
  endpoint: 'https://emiliaprotocol.ai',
  apiKey: 'ep_live_...',
});

// 1. Browse policies
const policies = await ep.listPolicies();

// 2. Initiate a handshake
const handshake = await ep.initiateHandshake({
  mode: 'mutual',
  policyId: 'standard',
  parties: [
    { entityRef: 'my-agent', role: 'initiator' },
    { entityRef: 'counterparty', role: 'responder' },
  ],
});

// 3. Present credentials
await ep.present(handshake.id, {
  partyRole: 'initiator',
  presentationType: 'ep_trust_profile',
  claims: { entityId: 'my-agent', entityType: 'agent' },
});

// 4. Verify the handshake
const result = await ep.verify(handshake.id);
// result.result === 'accepted' | 'rejected' | 'partial'

// 5. Gate the action
const gate = await ep.gate({
  entityId: 'counterparty',
  action: 'transact',
  policy: 'standard',
  handshakeId: handshake.id,
});
// gate.decision === 'allow' | 'deny' | 'review'
// gate.commitRef === 'cmt_abc123' (on allow)
```

That is the entire integration. Five method calls from handshake to authorization.

---

## Constructor

```typescript
new EmiliaProtocol(options: {
  endpoint: string;      // EP API base URL
  apiKey: string;        // API key (ep_live_* or ep_test_*)
  timeout?: number;      // Request timeout in ms (default: 10000)
  retries?: number;      // Retry count for transient errors (default: 2)
})
```

The constructor validates the API key format and stores configuration.
No network calls are made until a method is called.

---

## Core Methods

### `listPolicies(): Promise<Policy[]>`

List available trust policies. No authentication required.

```typescript
const policies = await ep.listPolicies();
// [{ name: 'standard', family: 'commerce', minScore: 40, ... }]
```

### `initiateHandshake(params): Promise<Handshake>`

```typescript
const hs = await ep.initiateHandshake({
  mode: 'mutual' | 'one-way' | 'delegated',
  policyId: string,
  parties: Array<{ entityRef: string; role: 'initiator' | 'responder' }>,
  binding?: object,        // Optional binding constraints
  interactionId?: string,  // Optional external reference
});
// Returns: { id, status, mode, policyId, parties, createdAt }
```

### `present(handshakeId, params): Promise<Presentation>`

```typescript
await ep.present(handshakeId, {
  partyRole: string,
  presentationType: 'ep_trust_profile' | 'verifiable_credential' | 'attestation',
  claims: object,
  issuerRef?: string,
  disclosureMode?: 'full' | 'selective' | 'zk',
});
// Returns: { presentationId, partyRole, status, createdAt }
```

### `verify(handshakeId): Promise<VerifyResult>`

```typescript
const result = await ep.verify(handshakeId);
// Returns: { handshakeId, result: 'accepted'|'rejected'|'partial', reasonCodes, evaluatedAt }
```

### `gate(params): Promise<GateDecision>`

```typescript
const decision = await ep.gate({
  entityId: string,
  action: string,
  policy?: 'strict' | 'standard' | 'permissive',
  handshakeId?: string,
  valueUsd?: number,
  delegationId?: string,
});
// Returns: { decision: 'allow'|'deny'|'review', commitRef?, reasons, appealPath }
```

### `getProfile(entityId): Promise<TrustProfile>`

```typescript
const profile = await ep.getProfile('counterparty');
// Returns: { entityId, confidence, score, behavioral, disputes, ... }
```

### `revokeHandshake(handshakeId, reason): Promise<void>`

```typescript
await ep.revokeHandshake(handshakeId, 'Terms changed');
```

---

## Error Handling

The SDK uses typed errors that map to EP problem responses (RFC 9457).

```typescript
import { EmiliaProtocol, EPError, EPAuthError, EPValidationError } from '@emilia-protocol/sdk';

try {
  const gate = await ep.gate({ entityId: 'x', action: 'transact' });
} catch (err) {
  if (err instanceof EPAuthError) {
    // 401 -- API key invalid or expired
    console.error('Auth failed:', err.message);
  } else if (err instanceof EPValidationError) {
    // 400 -- Bad request (missing fields, invalid values)
    console.error('Validation:', err.message, err.field);
  } else if (err instanceof EPError) {
    // Any other EP error (403, 404, 500)
    console.error('EP error:', err.code, err.status, err.message);
  }
}
```

### Error types

| Error Class | HTTP Status | When |
|---|---|---|
| `EPAuthError` | 401 | Invalid or missing API key |
| `EPValidationError` | 400 | Missing required fields, invalid values |
| `EPForbiddenError` | 403 | Entity mismatch, gate required, not a party |
| `EPNotFoundError` | 404 | Entity, handshake, or commit not found |
| `EPError` | Any | Base class for all EP errors |

All errors include:
- `code`: Machine-readable error code (e.g., `"unauthorized"`, `"gate_required"`)
- `status`: HTTP status code
- `message`: Human-readable description

---

## Patterns

### Trust-Then-Act

The most common pattern: check trust before doing something.

```typescript
async function protectedAction(counterpartyId: string) {
  const gate = await ep.gate({
    entityId: counterpartyId,
    action: 'transact',
    policy: 'standard',
  });

  if (gate.decision !== 'allow') {
    throw new Error(`Denied: ${gate.reasons.join(', ')}`);
  }

  // Proceed with the action, storing gate.commitRef as proof
  await doTheAction({ commitRef: gate.commitRef });
}
```

### Full Handshake Flow

When mutual identity verification is required before the trust decision.

```typescript
async function mutualTrustFlow(myEntity: string, counterparty: string) {
  // Initiate
  const hs = await ep.initiateHandshake({
    mode: 'mutual',
    policyId: 'strict',
    parties: [
      { entityRef: myEntity, role: 'initiator' },
      { entityRef: counterparty, role: 'responder' },
    ],
  });

  // Present (both sides)
  await ep.present(hs.id, {
    partyRole: 'initiator',
    presentationType: 'ep_trust_profile',
    claims: { entityId: myEntity },
  });
  // ... responder presents via their own SDK instance ...

  // Verify
  const result = await ep.verify(hs.id);
  if (result.result !== 'accepted') {
    throw new Error(`Handshake ${result.result}: ${result.reasonCodes.join(', ')}`);
  }

  // Gate with handshake binding
  const gate = await ep.gate({
    entityId: counterparty,
    action: 'connect',
    policy: 'strict',
    handshakeId: hs.id,
  });

  return gate;
}
```

### Handling Denials Gracefully

Every denial includes an appeal path. Surface it to the user.

```typescript
const gate = await ep.gate({ entityId: id, action: 'transact' });

if (gate.decision === 'deny') {
  return {
    allowed: false,
    reasons: gate.reasons,
    appealUrl: gate.appealPath,
    message: 'This action was denied by the trust policy. You may appeal this decision.',
  };
}
```

---

## What the SDK Does NOT Include

The SDK intentionally excludes non-protocol endpoints to keep the surface
minimal:

- Entity registration and search (product API)
- Needs marketplace (product API)
- Auto-receipt submission (product API)
- ZK proof generation (product API)
- Health checks and stats (admin API)
- Cron and blockchain anchoring (admin API)
- Waitlist and operator applications (marketing)

These are available via direct HTTP calls to the EP API but are not part of
the trust protocol and do not belong in the SDK.

---

## SDK Size Budget

The SDK should ship as a single file with zero runtime dependencies:

- **Target**: < 5 KB minified + gzipped
- **Dependencies**: 0 (uses native `fetch`)
- **Node.js**: >= 18 (native fetch)
- **Browser**: Any modern browser
- **TypeScript**: Full type definitions included

---

## Future Additions

These methods may be added as the protocol matures, but are explicitly
out of scope for v1:

- `createDelegation()` -- Create a principal-agent delegation
- `verifyDelegation()` -- Verify a delegation's validity
- `submitReceipt()` -- Submit a transaction receipt after action completion
- `fileDispute()` -- File a dispute against an entity

Each addition must pass the bar: "Does an integrator need this to complete
the trust loop?" If not, it stays out.
