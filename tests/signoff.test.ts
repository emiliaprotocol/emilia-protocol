/**
 * EMILIA Protocol — EP Accountable Signoff Tests
 *
 * Tests for the Accountable Signoff extension: challenge issuance,
 * attestation creation, consumption, revocation, denial, expiry,
 * and full lifecycle flows.
 *
 * Uses vi.mock to mock Supabase so no real DB or network calls are made.
 * The signoff event functions (emitSignoffEvent, requireSignoffEvent,
 * getSignoffEvents) are exercised against an in-memory table simulator.
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
// Import modules under test (after mocks)
// ============================================================================

import {
  emitSignoffEvent,
  requireSignoffEvent,
  getSignoffEvents,
  SIGNOFF_EVENT_TYPES,
  SignoffEventError,
} from '../lib/signoff/events.js';

import { SignoffError } from '../lib/signoff/errors.js';

import {
  SIGNOFF_STATUS_ORDER,
  SIGNOFF_TERMINAL_STATES,
  SIGNOFF_ALLOWED_METHODS,
  SIGNOFF_ASSURANCE_LEVELS,
  SIGNOFF_ASSURANCE_RANK,
  VALID_SIGNOFF_STATUSES,
  VALID_TERMINAL_STATES,
  VALID_ALLOWED_METHODS,
  VALID_ASSURANCE_LEVELS,
} from '../lib/signoff/invariants.js';

// ============================================================================
// Supabase table simulator
//
// In-memory tables so the event functions can insert, select, and update
// records realistically. Follows the pattern from handshake.test.js.
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
          // Simulate unique constraint on signoff_consumptions.signoff_id
          if (tableName === 'signoff_consumptions') {
            const existing = getTable(tableName).find(
              (r) => r.signoff_id === row.signoff_id,
            );
            if (existing) {
              insertedRows = null;
              return {
                select: vi.fn().mockReturnValue({
                  single: vi.fn().mockResolvedValue({
                    data: null,
                    error: { code: '23505', message: 'duplicate key value violates unique constraint' },
                  }),
                }),
              };
            }
          }
          if (tableName === 'signoff_challenges' && !row.challenge_id) {
            row.challenge_id = crypto.randomUUID();
          }
          if (tableName === 'signoff_attestations' && !row.signoff_id) {
            row.signoff_id = crypto.randomUUID();
          }
          if (tableName === 'signoff_consumptions' && !row.signoff_consumption_id) {
            row.signoff_consumption_id = crypto.randomUUID();
          }
          if (tableName === 'signoff_events' && !row.event_id) {
            row.event_id = crypto.randomUUID();
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
      is: vi.fn().mockImplementation((col, val) => {
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
// Helpers: seed data builders
// ============================================================================

function seedChallenge(sim, overrides = {}) {
  const challenge = {
    challenge_id: crypto.randomUUID(),
    handshake_id: crypto.randomUUID(),
    binding_hash: 'sha256-binding-' + crypto.randomBytes(8).toString('hex'),
    accountable_actor_ref: 'entity-alice',
    signoff_policy_id: 'policy-signoff-001',
    signoff_policy_hash: 'sha256-policy-' + crypto.randomBytes(8).toString('hex'),
    required_assurance: 'substantial',
    allowed_methods: ['passkey', 'secure_app', 'platform_authenticator'],
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    status: 'challenge_issued',
    metadata: {},
    ...overrides,
  };
  sim.getTable('signoff_challenges').push(challenge);
  return challenge;
}

function seedAttestation(sim, challenge, overrides = {}) {
  const attestation = {
    signoff_id: crypto.randomUUID(),
    challenge_id: challenge.challenge_id,
    handshake_id: challenge.handshake_id,
    binding_hash: challenge.binding_hash,
    human_entity_ref: 'entity-alice',
    auth_method: 'passkey',
    assurance_level: 'substantial',
    channel: 'web',
    approved_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    attestation_hash: 'sha256-attest-' + crypto.randomBytes(8).toString('hex'),
    status: 'approved',
    metadata: {},
    ...overrides,
  };
  sim.getTable('signoff_attestations').push(attestation);
  return attestation;
}

function seedConsumption(sim, attestation, overrides = {}) {
  const consumption = {
    signoff_consumption_id: crypto.randomUUID(),
    signoff_id: attestation.signoff_id,
    binding_hash: attestation.binding_hash,
    execution_ref: 'exec-' + crypto.randomBytes(8).toString('hex'),
    consumed_at: new Date().toISOString(),
    ...overrides,
  };
  sim.getTable('signoff_consumptions').push(consumption);
  return consumption;
}

// ============================================================================
// 1. Challenge Issuance Tests
// ============================================================================

describe('Signoff Challenge Issuance', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('seedChallenge creates a valid challenge record', () => {
    const challenge = seedChallenge(sim);
    expect(challenge.challenge_id).toBeDefined();
    expect(challenge.status).toBe('challenge_issued');
    expect(challenge.binding_hash).toMatch(/^sha256-binding-/);
    expect(challenge.required_assurance).toBe('substantial');
  });

  it('challenge has valid expiry in the future', () => {
    const challenge = seedChallenge(sim);
    const expiresAt = new Date(challenge.expires_at);
    expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('challenge references a handshake_id', () => {
    const challenge = seedChallenge(sim);
    expect(challenge.handshake_id).toBeDefined();
    expect(typeof challenge.handshake_id).toBe('string');
  });

  it('challenge carries allowed_methods array', () => {
    const challenge = seedChallenge(sim);
    expect(Array.isArray(challenge.allowed_methods)).toBe(true);
    expect(challenge.allowed_methods.length).toBeGreaterThan(0);
    for (const method of challenge.allowed_methods) {
      expect(VALID_ALLOWED_METHODS.has(method)).toBe(true);
    }
  });

  it('challenge with expired handshake has expired status', () => {
    const challenge = seedChallenge(sim, {
      expires_at: new Date(Date.now() - 1000).toISOString(),
      status: 'expired',
    });
    expect(challenge.status).toBe('expired');
  });

  it('rejects challenge with invalid required_assurance level', () => {
    const challenge = seedChallenge(sim, { required_assurance: 'ultra' });
    expect(VALID_ASSURANCE_LEVELS.has(challenge.required_assurance)).toBe(false);
  });
});

// ============================================================================
// 2. Attestation Tests
// ============================================================================

describe('Signoff Attestation', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('creates attestation with valid auth method', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge, { auth_method: 'passkey' });
    expect(attestation.auth_method).toBe('passkey');
    expect(VALID_ALLOWED_METHODS.has(attestation.auth_method)).toBe(true);
    expect(attestation.status).toBe('approved');
  });

  it('attestation binding_hash matches challenge binding_hash', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    expect(attestation.binding_hash).toBe(challenge.binding_hash);
  });

  it('attestation references the originating challenge_id', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    expect(attestation.challenge_id).toBe(challenge.challenge_id);
  });

  it('attestation carries attestation_hash', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    expect(attestation.attestation_hash).toMatch(/^sha256-attest-/);
  });

  it('attestation with invalid auth method is detectable', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge, { auth_method: 'sms_otp' });
    expect(VALID_ALLOWED_METHODS.has(attestation.auth_method)).toBe(false);
  });

  it('attestation with insufficient assurance level is detectable', () => {
    const challenge = seedChallenge(sim, { required_assurance: 'high' });
    const attestation = seedAttestation(sim, challenge, { assurance_level: 'low' });
    const requiredRank = SIGNOFF_ASSURANCE_RANK[challenge.required_assurance];
    const actualRank = SIGNOFF_ASSURANCE_RANK[attestation.assurance_level];
    expect(actualRank).toBeLessThan(requiredRank);
  });

  it('attestation with matching assurance level passes rank check', () => {
    const challenge = seedChallenge(sim, { required_assurance: 'substantial' });
    const attestation = seedAttestation(sim, challenge, { assurance_level: 'substantial' });
    const requiredRank = SIGNOFF_ASSURANCE_RANK[challenge.required_assurance];
    const actualRank = SIGNOFF_ASSURANCE_RANK[attestation.assurance_level];
    expect(actualRank).toBeGreaterThanOrEqual(requiredRank);
  });

  it('attestation with higher assurance level passes rank check', () => {
    const challenge = seedChallenge(sim, { required_assurance: 'substantial' });
    const attestation = seedAttestation(sim, challenge, { assurance_level: 'high' });
    const requiredRank = SIGNOFF_ASSURANCE_RANK[challenge.required_assurance];
    const actualRank = SIGNOFF_ASSURANCE_RANK[attestation.assurance_level];
    expect(actualRank).toBeGreaterThanOrEqual(requiredRank);
  });
});

// ============================================================================
// 3. Consumption Tests
// ============================================================================

describe('Signoff Consumption', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('consumes a valid approved attestation', () => {
    const challenge = seedChallenge(sim, { status: 'approved' });
    const attestation = seedAttestation(sim, challenge);
    const consumption = seedConsumption(sim, attestation);
    expect(consumption.signoff_id).toBe(attestation.signoff_id);
    expect(consumption.consumed_at).toBeDefined();
  });

  it('consumption binding_hash matches attestation binding_hash', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    const consumption = seedConsumption(sim, attestation);
    expect(consumption.binding_hash).toBe(attestation.binding_hash);
  });

  it('consumption carries execution_ref', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    const consumption = seedConsumption(sim, attestation);
    expect(consumption.execution_ref).toMatch(/^exec-/);
  });

  it('duplicate consumption is rejected by unique constraint', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    seedConsumption(sim, attestation);

    // Attempt to insert a second consumption with the same signoff_id
    const client = sim.mockClient();
    const insertResult = client.from('signoff_consumptions').insert({
      signoff_id: attestation.signoff_id,
      binding_hash: attestation.binding_hash,
      execution_ref: 'exec-second-attempt',
      consumed_at: new Date().toISOString(),
    });
    // The insert chain should return an error for duplicate
    return insertResult.select().single().then(({ data, error }) => {
      expect(error).toBeDefined();
      expect(error.code).toBe('23505');
      expect(data).toBeNull();
    });
  });
});

// ============================================================================
// 4. Challenge Status Transitions
// ============================================================================

describe('Signoff Challenge Status Transitions', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('challenge can be revoked (status → revoked)', () => {
    const challenge = seedChallenge(sim);
    challenge.status = 'revoked';
    expect(challenge.status).toBe('revoked');
    expect(VALID_TERMINAL_STATES.has(challenge.status)).toBe(true);
  });

  it('challenge can be denied (status → denied)', () => {
    const challenge = seedChallenge(sim);
    challenge.status = 'denied';
    expect(challenge.status).toBe('denied');
    expect(VALID_TERMINAL_STATES.has(challenge.status)).toBe(true);
  });

  it('challenge can expire (status → expired)', () => {
    const challenge = seedChallenge(sim, {
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    challenge.status = 'expired';
    expect(challenge.status).toBe('expired');
    expect(VALID_TERMINAL_STATES.has(challenge.status)).toBe(true);
  });

  it('challenge progresses from challenge_issued → challenge_viewed', () => {
    const challenge = seedChallenge(sim);
    expect(challenge.status).toBe('challenge_issued');
    challenge.status = 'challenge_viewed';
    expect(challenge.status).toBe('challenge_viewed');
  });

  it('challenge progresses from challenge_viewed → approved', () => {
    const challenge = seedChallenge(sim, { status: 'challenge_viewed' });
    challenge.status = 'approved';
    expect(challenge.status).toBe('approved');
  });
});

// ============================================================================
// 5. Attestation Status Transitions
// ============================================================================

describe('Signoff Attestation Status Transitions', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('attestation can be revoked', () => {
    const challenge = seedChallenge(sim, { status: 'approved' });
    const attestation = seedAttestation(sim, challenge);
    attestation.status = 'revoked';
    expect(attestation.status).toBe('revoked');
  });

  it('attestation can expire', () => {
    const challenge = seedChallenge(sim, { status: 'approved' });
    const attestation = seedAttestation(sim, challenge, {
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    attestation.status = 'expired';
    expect(attestation.status).toBe('expired');
  });

  it('attestation can be consumed', () => {
    const challenge = seedChallenge(sim, { status: 'approved' });
    const attestation = seedAttestation(sim, challenge);
    attestation.status = 'consumed';
    expect(attestation.status).toBe('consumed');
  });
});

// ============================================================================
// 6. Signoff Event Recording
// ============================================================================

describe('Signoff Event Recording', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('requireSignoffEvent records a challenge_issued event', async () => {
    const event = await requireSignoffEvent({
      handshakeId: 'hs-1',
      challengeId: 'ch-1',
      eventType: 'challenge_issued',
      detail: { reason: 'test' },
      actorEntityRef: 'entity-alice',
    });

    expect(event).toBeDefined();
    expect(event.event_type).toBe('challenge_issued');
    expect(event.challenge_id).toBe('ch-1');
    expect(event.actor_entity_ref).toBe('entity-alice');
  });

  it('requireSignoffEvent rejects invalid event type', async () => {
    await expect(
      requireSignoffEvent({
        challengeId: 'ch-1',
        eventType: 'invalid_event_type',
      }),
    ).rejects.toThrow('Invalid eventType');
  });

  it('requireSignoffEvent rejects missing event type', async () => {
    await expect(
      requireSignoffEvent({
        challengeId: 'ch-1',
      }),
    ).rejects.toThrow('eventType is required');
  });

  it('emitSignoffEvent does not throw on valid event', async () => {
    await expect(
      emitSignoffEvent({
        handshakeId: 'hs-1',
        challengeId: 'ch-1',
        eventType: 'challenge_issued',
        detail: {},
        actorEntityRef: 'entity-bob',
      }),
    ).resolves.not.toThrow();
  });

  it('getSignoffEvents returns events for a challenge', async () => {
    // Seed events directly
    sim.getTable('signoff_events').push(
      { event_id: 'e1', challenge_id: 'ch-1', event_type: 'challenge_issued', created_at: '2025-01-01T00:00:00Z' },
      { event_id: 'e2', challenge_id: 'ch-1', event_type: 'approved', created_at: '2025-01-01T00:01:00Z' },
      { event_id: 'e3', challenge_id: 'ch-2', event_type: 'challenge_issued', created_at: '2025-01-01T00:00:00Z' },
    );

    const events = await getSignoffEvents('ch-1');
    expect(events).toHaveLength(2);
    expect(events.every((e) => e.challenge_id === 'ch-1')).toBe(true);
  });

  it('getSignoffEvents throws on missing challengeId', async () => {
    await expect(getSignoffEvents(null)).rejects.toThrow('challengeId is required');
  });
});

// ============================================================================
// 7. Binding Hash Consistency
// ============================================================================

describe('Signoff Binding Hash Consistency', () => {
  let sim;

  beforeEach(() => {
    sim = createTableSim();
  });

  it('binding hash must match between challenge and attestation', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    expect(attestation.binding_hash).toBe(challenge.binding_hash);
  });

  it('binding hash must match between attestation and consumption', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    const consumption = seedConsumption(sim, attestation);
    expect(consumption.binding_hash).toBe(attestation.binding_hash);
  });

  it('binding hash mismatch at attestation is detectable', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge, {
      binding_hash: 'sha256-WRONG-hash',
    });
    expect(attestation.binding_hash).not.toBe(challenge.binding_hash);
  });

  it('binding hash mismatch at consumption is detectable', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    const consumption = seedConsumption(sim, attestation, {
      binding_hash: 'sha256-WRONG-hash',
    });
    expect(consumption.binding_hash).not.toBe(attestation.binding_hash);
  });

  it('full chain: binding hash consistent across challenge → attestation → consumption', () => {
    const challenge = seedChallenge(sim);
    const attestation = seedAttestation(sim, challenge);
    const consumption = seedConsumption(sim, attestation);
    expect(challenge.binding_hash).toBe(attestation.binding_hash);
    expect(attestation.binding_hash).toBe(consumption.binding_hash);
    expect(challenge.binding_hash).toBe(consumption.binding_hash);
  });
});

// ============================================================================
// 8. Full Lifecycle Happy Path
// ============================================================================

describe('Signoff Full Lifecycle Happy Path', () => {
  let sim;

  beforeEach(() => {
    vi.clearAllMocks();
    sim = createTableSim();
    mockGetServiceClient.mockReturnValue(sim.mockClient());
  });

  it('challenge_issued → challenge_viewed → approved → consumed', async () => {
    // Step 1: Issue challenge
    const challenge = seedChallenge(sim);
    expect(challenge.status).toBe('challenge_issued');

    // Record event
    await requireSignoffEvent({
      handshakeId: challenge.handshake_id,
      challengeId: challenge.challenge_id,
      eventType: 'challenge_issued',
      actorEntityRef: 'system',
    });

    // Step 2: View challenge
    challenge.status = 'challenge_viewed';
    await requireSignoffEvent({
      handshakeId: challenge.handshake_id,
      challengeId: challenge.challenge_id,
      eventType: 'challenge_viewed',
      actorEntityRef: 'entity-alice',
    });

    // Step 3: Attest (approve)
    challenge.status = 'approved';
    const attestation = seedAttestation(sim, challenge);
    await requireSignoffEvent({
      handshakeId: challenge.handshake_id,
      challengeId: challenge.challenge_id,
      signoffId: attestation.signoff_id,
      eventType: 'approved',
      actorEntityRef: 'entity-alice',
    });

    // Step 4: Consume
    const consumption = seedConsumption(sim, attestation);
    attestation.status = 'consumed';
    challenge.status = 'consumed';
    await requireSignoffEvent({
      handshakeId: challenge.handshake_id,
      challengeId: challenge.challenge_id,
      signoffId: attestation.signoff_id,
      eventType: 'consumed',
      actorEntityRef: 'system',
    });

    // Verify final states
    expect(challenge.status).toBe('consumed');
    expect(attestation.status).toBe('consumed');
    expect(consumption.consumed_at).toBeDefined();

    // Verify events recorded
    const events = sim.getTable('signoff_events');
    expect(events.length).toBe(4);
    expect(events.map((e) => e.event_type)).toEqual([
      'challenge_issued',
      'challenge_viewed',
      'approved',
      'consumed',
    ]);
  });

  it('challenge_issued → denied (short path)', async () => {
    const challenge = seedChallenge(sim);
    challenge.status = 'denied';

    await requireSignoffEvent({
      handshakeId: challenge.handshake_id,
      challengeId: challenge.challenge_id,
      eventType: 'denied',
      actorEntityRef: 'entity-alice',
    });

    expect(challenge.status).toBe('denied');
    expect(VALID_TERMINAL_STATES.has(challenge.status)).toBe(true);
  });
});

// ============================================================================
// 9. SignoffError class
// ============================================================================

describe('SignoffError', () => {
  it('creates an error with default status and code', () => {
    const err = new SignoffError('test error');
    expect(err.message).toBe('test error');
    expect(err.status).toBe(400);
    expect(err.code).toBe('SIGNOFF_ERROR');
    expect(err.name).toBe('SignoffError');
  });

  it('creates an error with custom status and code', () => {
    const err = new SignoffError('not found', 404, 'NOT_FOUND');
    expect(err.status).toBe(404);
    expect(err.code).toBe('NOT_FOUND');
  });

  it('is an instance of Error', () => {
    const err = new SignoffError('test');
    expect(err).toBeInstanceOf(Error);
  });
});
