/**
 * Tests for lib/auto-receipt-config.js AND mcp-server/auto-receipt.js
 *
 * Covers:
 *  1. buildPrivacyFilter — default sensitive field redaction
 *  2. buildPrivacyFilter — custom redact_fields from entity config
 *  3. buildPrivacyFilter — anonymous mode hashes counterparty_id
 *  4. buildPrivacyFilter — nested object redaction
 *  5. buildPrivacyFilter — non-sensitive fields are preserved
 *  6. buildPrivacyFilter — null / missing counterparty_id in anonymous mode
 *  7. buildPrivacyFilter — case-insensitive field matching
 *  8. getAutoReceiptConfig — returns disabled-by-default when entity unknown
 *  9. getAutoReceiptConfig — returns correct shape for known entity
 * 10. setAutoReceiptConfig — persists changes (in-memory fallback path)
 * 11. setAutoReceiptConfig — validates required `enabled` boolean
 * 12. setAutoReceiptConfig — validates privacy_mode enum
 * 13. setAutoReceiptConfig — validates redact_fields is an array
 * 14. DEFAULT_REDACT_FIELDS — contains the protocol-mandated entries
 * 15. AutoReceiptMiddleware.wrap() — returns result unmodified, opts-in behaviour
 * 16. AutoReceiptMiddleware.generateReceiptDraft() — task_type, markers, privacy
 * 17. AutoReceiptMiddleware.redactSensitive() — sensitive field removal
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Mock @/lib/supabase so the tests never hit a real database.
// We expose a controllable mock client whose behaviour individual tests can
// adjust via mockImplementation / mockResolvedValueOnce.
// ---------------------------------------------------------------------------

/** Mutable result the mock supabase client will resolve with. */
let _mockDbResult = { data: null, error: null };

const mockSingle = vi.fn(async () => _mockDbResult);
const mockMaybeSingle = vi.fn(async () => _mockDbResult);
const mockSelect = vi.fn(() => ({ eq: mockEq }));
const mockEq = vi.fn(() => ({ maybeSingle: mockMaybeSingle, select: mockSelect, eq: mockEq }));
const mockUpdate = vi.fn(() => ({ eq: mockEqUpdate }));
const mockEqUpdate = vi.fn(async () => _mockDbResult);

const mockFrom = vi.fn(() => ({
  select: mockSelect,
  update: mockUpdate,
}));

const mockSupabaseClient = { from: mockFrom };

vi.mock('@/lib/supabase', () => ({
  getServiceClient: vi.fn(() => mockSupabaseClient),
}));

// Import after mocks are set up
import {
  buildPrivacyFilter,
  getAutoReceiptConfig,
  setAutoReceiptConfig,
  DEFAULT_REDACT_FIELDS,
} from '../lib/auto-receipt-config.js';

// ---------------------------------------------------------------------------
// Helper: SHA-256 hex of a string (mirrors the internal _hashAnonymous logic)
// ---------------------------------------------------------------------------
function sha256(s) {
  return `anon_sha256_${crypto.createHash('sha256').update(s).digest('hex')}`;
}

// ---------------------------------------------------------------------------
// Helper: build a minimal entity row as Supabase would return it
// ---------------------------------------------------------------------------
function makeEntityRow(overrides = {}) {
  return {
    auto_receipt_enabled: false,
    auto_receipt_config: null,
    updated_at: '2025-01-01T00:00:00.000Z',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Reset mocks between tests
// ---------------------------------------------------------------------------
beforeEach(() => {
  _mockDbResult = { data: null, error: null };
  vi.clearAllMocks();
  // Re-wire chained mock calls after clearAllMocks
  mockEq.mockReturnValue({ maybeSingle: mockMaybeSingle, select: mockSelect, eq: mockEq });
  mockEqUpdate.mockImplementation(async () => _mockDbResult);
  mockUpdate.mockReturnValue({ eq: mockEqUpdate });
  mockSelect.mockReturnValue({ eq: mockEq });
  mockFrom.mockReturnValue({ select: mockSelect, update: mockUpdate });
});

// ============================================================================
// 1. DEFAULT_REDACT_FIELDS protocol contract
// ============================================================================

describe('DEFAULT_REDACT_FIELDS', () => {
  it('contains all protocol-mandated sensitive field names', () => {
    const required = [
      'password', 'token', 'api_key', 'key', 'secret', 'auth',
      'credential', 'private_key', 'access_token', 'refresh_token', 'bearer',
    ];
    for (const field of required) {
      expect(DEFAULT_REDACT_FIELDS).toContain(field);
    }
  });

  it('is immutable (frozen)', () => {
    expect(Object.isFrozen(DEFAULT_REDACT_FIELDS)).toBe(true);
  });
});

// ============================================================================
// 2. buildPrivacyFilter — default sensitive field redaction
// ============================================================================

describe('buildPrivacyFilter — default redaction', () => {
  it('redacts all DEFAULT_REDACT_FIELDS at the top level', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });

    const input = {
      action: 'purchase',
      amount: 99.99,
      password: 'hunter2',
      token: 'tok_abc123',
      api_key: 'sk-super-secret',
      key: 'some-key',
      secret: 'shhh',
      auth: 'Basic xyz',
      credential: 'cred-value',
      private_key: '-----BEGIN RSA PRIVATE KEY-----',
      access_token: 'at_foo',
      refresh_token: 'rt_bar',
      bearer: 'Bearer xyz',
    };

    const result = filter(input);

    // Non-sensitive fields preserved
    expect(result.action).toBe('purchase');
    expect(result.amount).toBe(99.99);

    // All sensitive fields redacted
    for (const field of DEFAULT_REDACT_FIELDS) {
      if (field in input) {
        expect(result[field]).toBe('[REDACTED]');
      }
    }
  });

  it('does not mutate the original input object', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });
    const input = { password: 'secret', amount: 42 };
    const inputCopy = { ...input };

    filter(input);

    expect(input).toEqual(inputCopy);
  });

  it('handles empty input gracefully', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });
    expect(filter({})).toEqual({});
    expect(filter(null)).toBeNull();
    expect(filter(undefined)).toBeUndefined();
  });
});

// ============================================================================
// 3. buildPrivacyFilter — custom redact_fields
// ============================================================================

describe('buildPrivacyFilter — custom redact_fields', () => {
  it('redacts entity-configured custom fields in addition to defaults', () => {
    const filter = buildPrivacyFilter({
      redact_fields: ['billing_ref', 'internal_user_id'],
      privacy_mode: 'standard',
    });

    const input = {
      action: 'api_call',
      billing_ref: 'BR-99999',
      internal_user_id: 'uid-abc',
      password: 'secret',
      public_data: 'visible',
    };

    const result = filter(input);

    expect(result.action).toBe('api_call');
    expect(result.public_data).toBe('visible');
    expect(result.billing_ref).toBe('[REDACTED]');
    expect(result.internal_user_id).toBe('[REDACTED]');
    expect(result.password).toBe('[REDACTED]');
  });

  it('handles empty custom redact_fields array', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });
    const input = { action: 'test', amount: 10 };
    expect(filter(input)).toEqual(input);
  });

  it('custom fields do not override non-sensitive field values', () => {
    const filter = buildPrivacyFilter({ redact_fields: ['safe_field'], privacy_mode: 'standard' });
    const input = { safe_field: 'should be redacted because user configured it', other: 'ok' };
    const result = filter(input);
    expect(result.safe_field).toBe('[REDACTED]');
    expect(result.other).toBe('ok');
  });
});

// ============================================================================
// 4. buildPrivacyFilter — anonymous mode hashes counterparty_id
// ============================================================================

describe('buildPrivacyFilter — anonymous mode', () => {
  it('hashes counterparty_id when privacy_mode is "anonymous"', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'anonymous' });

    const counterpartyId = 'entity-uuid-12345';
    const input = {
      action: 'transfer',
      counterparty_id: counterpartyId,
      amount: 50,
    };

    const result = filter(input);

    // counterparty_id must be replaced with a one-way hash
    expect(result.counterparty_id).not.toBe(counterpartyId);
    expect(result.counterparty_id).toBe(sha256(counterpartyId));
    // Other fields intact
    expect(result.action).toBe('transfer');
    expect(result.amount).toBe(50);
  });

  it('anonymous mode hash is deterministic (same input → same hash)', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'anonymous' });
    const input = { counterparty_id: 'stable-entity-id' };

    const r1 = filter(input);
    const r2 = filter(input);
    expect(r1.counterparty_id).toBe(r2.counterparty_id);
  });

  it('anonymous mode hash differs for different counterparty_ids', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'anonymous' });
    const r1 = filter({ counterparty_id: 'entity-A' });
    const r2 = filter({ counterparty_id: 'entity-B' });
    expect(r1.counterparty_id).not.toBe(r2.counterparty_id);
  });

  it('anonymous hash is prefixed with "anon_sha256_"', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'anonymous' });
    const result = filter({ counterparty_id: 'some-entity' });
    expect(result.counterparty_id).toMatch(/^anon_sha256_[a-f0-9]{64}$/);
  });

  it('standard mode does NOT hash counterparty_id', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });
    const input = { counterparty_id: 'entity-plain' };
    expect(filter(input).counterparty_id).toBe('entity-plain');
  });

  it('anonymous mode with null counterparty_id does not throw', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'anonymous' });
    const input = { counterparty_id: null, action: 'test' };
    const result = filter(input);
    // null counterparty_id left as-is (nothing to hash)
    expect(result.counterparty_id).toBeNull();
    expect(result.action).toBe('test');
  });

  it('anonymous mode with missing counterparty_id does not throw', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'anonymous' });
    const input = { action: 'no-counterparty' };
    expect(() => filter(input)).not.toThrow();
    expect(filter(input).action).toBe('no-counterparty');
  });
});

// ============================================================================
// 5. buildPrivacyFilter — nested object redaction
// ============================================================================

describe('buildPrivacyFilter — nested redaction', () => {
  it('redacts sensitive keys nested inside plain objects', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });

    const input = {
      metadata: {
        label: 'visible',
        token: 'nested-secret-token',
      },
      top_level: 'ok',
    };

    const result = filter(input);

    expect(result.top_level).toBe('ok');
    expect(result.metadata.label).toBe('visible');
    expect(result.metadata.token).toBe('[REDACTED]');
  });
});

// ============================================================================
// 6. buildPrivacyFilter — case-insensitive matching
// ============================================================================

describe('buildPrivacyFilter — case-insensitive matching', () => {
  it('redacts uppercase and mixed-case sensitive field names', () => {
    const filter = buildPrivacyFilter({ redact_fields: [], privacy_mode: 'standard' });

    const input = {
      PASSWORD: 'hunter2',
      Token: 'tok_XYZ',
      API_KEY: 'sk-123',
      safe: 'visible',
    };

    const result = filter(input);

    expect(result.PASSWORD).toBe('[REDACTED]');
    expect(result.Token).toBe('[REDACTED]');
    expect(result.API_KEY).toBe('[REDACTED]');
    expect(result.safe).toBe('visible');
  });

  it('custom redact_fields are matched case-insensitively', () => {
    const filter = buildPrivacyFilter({ redact_fields: ['MySecret'], privacy_mode: 'standard' });

    expect(filter({ MySecret: 'val' }).MySecret).toBe('[REDACTED]');
    expect(filter({ MYSECRET: 'val' }).MYSECRET).toBe('[REDACTED]');
    expect(filter({ mysecret: 'val' }).mysecret).toBe('[REDACTED]');
  });
});

// ============================================================================
// 7. getAutoReceiptConfig — default config when entity not found
// ============================================================================

describe('getAutoReceiptConfig — default config', () => {
  it('returns disabled-by-default when entity row does not exist', async () => {
    _mockDbResult = { data: null, error: null }; // maybeSingle returns null for unknown entity

    const config = await getAutoReceiptConfig('unknown-entity');

    expect(config.enabled).toBe(false);
    expect(Array.isArray(config.redact_fields)).toBe(true);
    expect(config.redact_fields).toHaveLength(0);
    expect(config.privacy_mode).toBe('standard');
    expect(typeof config.last_updated).toBe('string');
  });

  it('throws if entityId is missing', async () => {
    await expect(getAutoReceiptConfig(undefined)).rejects.toThrow('entityId is required');
    await expect(getAutoReceiptConfig('')).rejects.toThrow('entityId is required');
  });

  it('falls back to in-memory default when DB reports a missing column error (42703)', async () => {
    _mockDbResult = { data: null, error: { code: '42703', message: 'column not found' } };

    const config = await getAutoReceiptConfig('entity-42703');
    expect(config.enabled).toBe(false);
    expect(config.privacy_mode).toBe('standard');
  });

  it('falls back to in-memory default when DB reports a missing table error (42P01)', async () => {
    _mockDbResult = { data: null, error: { code: '42P01', message: 'relation not found' } };

    const config = await getAutoReceiptConfig('entity-42P01');
    expect(config.enabled).toBe(false);
  });
});

// ============================================================================
// 8. getAutoReceiptConfig — returns correct shape for known entity
// ============================================================================

describe('getAutoReceiptConfig — known entity', () => {
  it('returns enabled config with correct shape', async () => {
    _mockDbResult = {
      data: makeEntityRow({
        auto_receipt_enabled: true,
        auto_receipt_config: { redact_fields: ['billing_ref'], privacy_mode: 'anonymous' },
        updated_at: '2025-06-01T12:00:00.000Z',
      }),
      error: null,
    };

    const config = await getAutoReceiptConfig('entity-known');

    expect(config.enabled).toBe(true);
    expect(config.redact_fields).toEqual(['billing_ref']);
    expect(config.privacy_mode).toBe('anonymous');
    expect(config.last_updated).toBe('2025-06-01T12:00:00.000Z');
  });

  it('handles entity row with null auto_receipt_config gracefully', async () => {
    _mockDbResult = {
      data: makeEntityRow({ auto_receipt_enabled: true, auto_receipt_config: null }),
      error: null,
    };

    const config = await getAutoReceiptConfig('entity-null-cfg');

    expect(config.enabled).toBe(true);
    expect(config.redact_fields).toEqual([]);
    expect(config.privacy_mode).toBe('standard');
  });

  it('defaults invalid privacy_mode values to "standard"', async () => {
    _mockDbResult = {
      data: makeEntityRow({
        auto_receipt_enabled: true,
        auto_receipt_config: { privacy_mode: 'supersecret' },
      }),
      error: null,
    };

    const config = await getAutoReceiptConfig('entity-bad-mode');
    expect(config.privacy_mode).toBe('standard');
  });
});

// ============================================================================
// 9. setAutoReceiptConfig — persists changes (via in-memory fallback)
// ============================================================================

describe('setAutoReceiptConfig — persistence', () => {
  it('stores and retrieves config through the in-memory fallback (DB column error)', async () => {
    // Both write and read fail at the column level → in-memory path
    _mockDbResult = { data: null, error: { code: '42703', message: 'column not found' } };

    const entityId = `test-entity-mem-${Date.now()}`;

    const saved = await setAutoReceiptConfig(entityId, {
      enabled: true,
      redact_fields: ['my_field'],
      privacy_mode: 'anonymous',
    });

    expect(saved.enabled).toBe(true);
    expect(saved.redact_fields).toEqual(['my_field']);
    expect(saved.privacy_mode).toBe('anonymous');
    expect(typeof saved.last_updated).toBe('string');

    // Subsequent getAutoReceiptConfig should return the in-memory value
    const retrieved = await getAutoReceiptConfig(entityId);
    expect(retrieved.enabled).toBe(true);
    expect(retrieved.redact_fields).toEqual(['my_field']);
    expect(retrieved.privacy_mode).toBe('anonymous');
  });

  it('returns updated config when DB write succeeds', async () => {
    // Write succeeds (no error)
    _mockDbResult = { data: null, error: null };

    const saved = await setAutoReceiptConfig('entity-db-ok', {
      enabled: false,
      redact_fields: [],
      privacy_mode: 'standard',
    });

    expect(saved.enabled).toBe(false);
    expect(saved.redact_fields).toEqual([]);
    expect(saved.privacy_mode).toBe('standard');
  });

  it('applies defaults for optional parameters', async () => {
    _mockDbResult = { data: null, error: null };

    const saved = await setAutoReceiptConfig('entity-defaults', { enabled: true });
    expect(saved.redact_fields).toEqual([]);
    expect(saved.privacy_mode).toBe('standard');
  });
});

// ============================================================================
// 10. setAutoReceiptConfig — input validation
// ============================================================================

describe('setAutoReceiptConfig — input validation', () => {
  it('throws if entityId is missing', async () => {
    await expect(setAutoReceiptConfig('', { enabled: true })).rejects.toThrow('entityId is required');
    await expect(setAutoReceiptConfig(undefined, { enabled: true })).rejects.toThrow('entityId is required');
  });

  it('throws if enabled is not a boolean', async () => {
    await expect(
      setAutoReceiptConfig('entity-x', { enabled: 'yes' })
    ).rejects.toThrow('enabled must be a boolean');

    await expect(
      setAutoReceiptConfig('entity-x', { enabled: 1 })
    ).rejects.toThrow('enabled must be a boolean');

    await expect(
      setAutoReceiptConfig('entity-x', { enabled: null })
    ).rejects.toThrow('enabled must be a boolean');
  });

  it('throws if redact_fields is not an array', async () => {
    await expect(
      setAutoReceiptConfig('entity-x', { enabled: true, redact_fields: 'billing_ref' })
    ).rejects.toThrow('redact_fields must be an array');
  });

  it('throws if privacy_mode is an invalid enum value', async () => {
    await expect(
      setAutoReceiptConfig('entity-x', { enabled: true, privacy_mode: 'stealth' })
    ).rejects.toThrow("privacy_mode must be 'standard' or 'anonymous'");
  });

  it('accepts valid privacy_mode values', async () => {
    _mockDbResult = { data: null, error: null };
    await expect(
      setAutoReceiptConfig('entity-x', { enabled: true, privacy_mode: 'standard' })
    ).resolves.toBeDefined();
    await expect(
      setAutoReceiptConfig('entity-x', { enabled: true, privacy_mode: 'anonymous' })
    ).resolves.toBeDefined();
  });
});

// ============================================================================
// 11. Integration: filter built from config persists through round-trip
// ============================================================================

describe('Config → filter round-trip', () => {
  it('a filter built from a saved config correctly redacts its custom fields', async () => {
    _mockDbResult = { data: null, error: { code: '42703', message: 'column not found' } };

    const entityId = `round-trip-${Date.now()}`;

    await setAutoReceiptConfig(entityId, {
      enabled: true,
      redact_fields: ['my_secret_field'],
      privacy_mode: 'standard',
    });

    const config = await getAutoReceiptConfig(entityId);
    const filter = buildPrivacyFilter(config);

    const result = filter({
      action: 'tool_call',
      my_secret_field: 'should-be-gone',
      password: 'also-gone',
      visible: 'keep-me',
    });

    expect(result.my_secret_field).toBe('[REDACTED]');
    expect(result.password).toBe('[REDACTED]');
    expect(result.visible).toBe('keep-me');
    expect(result.action).toBe('tool_call');
  });

  it('anonymous config round-trip hashes counterparty_id end-to-end', async () => {
    _mockDbResult = { data: null, error: { code: '42703', message: 'column not found' } };

    const entityId = `anon-round-trip-${Date.now()}`;
    const counterpartyId = 'ep_entity_real_id';

    await setAutoReceiptConfig(entityId, {
      enabled: true,
      redact_fields: [],
      privacy_mode: 'anonymous',
    });

    const config = await getAutoReceiptConfig(entityId);
    const filter = buildPrivacyFilter(config);

    const result = filter({ counterparty_id: counterpartyId, amount: 100 });

    expect(result.counterparty_id).toBe(sha256(counterpartyId));
    expect(result.amount).toBe(100);
  });
});

// ============================================================================
// 15. AutoReceiptMiddleware — mcp-server/auto-receipt.js
// ============================================================================

import { AutoReceiptMiddleware } from '../mcp-server/auto-receipt.js';

describe('AutoReceiptMiddleware.wrap()', () => {
  let middleware;

  beforeEach(() => {
    middleware = new AutoReceiptMiddleware({
      epApiUrl: 'https://api.emiliaprotocol.com',
      epApiKey: 'ep_live_test_key_abc123',
      optIn: true,
      entityId: 'test-mcp-server',
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the original tool result unmodified', async () => {
    const handler = vi.fn().mockResolvedValue({ status: 'ok', data: [1, 2, 3] });
    const wrapped = middleware.wrap('ep_test_tool', handler);
    const result = await wrapped({ entity_id: 'some-entity' });
    expect(result).toEqual({ status: 'ok', data: [1, 2, 3] });
  });

  it('re-throws errors from the handler without swallowing them', async () => {
    const handler = vi.fn().mockRejectedValue(new Error('tool failed'));
    const wrapped = middleware.wrap('ep_failing_tool', handler);
    await expect(wrapped({})).rejects.toThrow('tool failed');
  });

  it('does NOT enqueue a receipt when optIn is false', async () => {
    const offMiddleware = new AutoReceiptMiddleware({ optIn: false });
    const enqueueSpy = vi.spyOn(offMiddleware, '_enqueue');

    const handler = vi.fn().mockResolvedValue('result');
    const wrapped = offMiddleware.wrap('ep_some_tool', handler);
    await wrapped({});

    expect(enqueueSpy).not.toHaveBeenCalled();
  });

  it('DOES submit a receipt async when optIn is true', async () => {
    const enqueueSpy = vi.spyOn(middleware, '_enqueue');
    const handler = vi.fn().mockResolvedValue('result');
    const wrapped = middleware.wrap('ep_opted_in_tool', handler);
    await wrapped({ some_param: 'value' });

    expect(enqueueSpy).toHaveBeenCalledOnce();
  });

  it('submits receipt even when handler throws (failure is a trust signal)', async () => {
    const enqueueSpy = vi.spyOn(middleware, '_enqueue');
    const handler = vi.fn().mockRejectedValue(new Error('tool error'));
    const wrapped = middleware.wrap('ep_error_tool', handler);

    await expect(wrapped({})).rejects.toThrow('tool error');
    expect(enqueueSpy).toHaveBeenCalledOnce();
  });

  it('throws TypeError when handler is not a function', () => {
    expect(() => middleware.wrap('ep_bad_tool', 'not a function')).toThrow(TypeError);
    expect(() => middleware.wrap('ep_bad_tool', null)).toThrow(TypeError);
  });
});

// ============================================================================
// 16. AutoReceiptMiddleware.generateReceiptDraft()
// ============================================================================

describe('AutoReceiptMiddleware.generateReceiptDraft()', () => {
  let middleware;

  beforeEach(() => {
    middleware = new AutoReceiptMiddleware({ optIn: true, entityId: 'test-mcp-server' });
  });

  it('includes toolName in context.task_type', () => {
    const draft = middleware.generateReceiptDraft('ep_trust_profile', {}, { ok: true }, 50, null);
    expect(draft.context.task_type).toBe('ep_trust_profile');
  });

  it('marks auto_generated: true', () => {
    const draft = middleware.generateReceiptDraft('ep_tool', {}, null, 10, null);
    expect(draft.auto_generated).toBe(true);
  });

  it('marks provenance as "unilateral"', () => {
    const draft = middleware.generateReceiptDraft('ep_tool', {}, null, 10, null);
    expect(draft.provenance).toBe('unilateral');
  });

  it('sets outcome.completed true when no error', () => {
    const draft = middleware.generateReceiptDraft('ep_tool', {}, { data: 1 }, 100, null);
    expect(draft.outcome.completed).toBe(true);
    expect(draft.outcome.error_occurred).toBe(false);
  });

  it('sets outcome.completed false when handler threw', () => {
    const err = new TypeError('Something went wrong');
    const draft = middleware.generateReceiptDraft('ep_tool', {}, null, 100, err);
    expect(draft.outcome.completed).toBe(false);
    expect(draft.outcome.error_occurred).toBe(true);
    expect(draft.outcome.error_type).toBe('TypeError');
  });

  it('does not include raw output contents — only metadata', () => {
    const sensitiveOutput = { secret_data: 'top-secret', user_id: 'user-abc' };
    const draft = middleware.generateReceiptDraft('ep_tool', {}, sensitiveOutput, 50, null);
    const draftStr = JSON.stringify(draft);
    expect(draftStr).not.toContain('top-secret');
    expect(draft.outcome.output_type).toBe('object');
    expect(typeof draft.outcome.output_size_chars).toBe('number');
  });

  it('sets counterparty_id to "auto" for unilateral receipts', () => {
    const draft = middleware.generateReceiptDraft('ep_tool', {}, null, 10, null);
    expect(draft.counterparty_id).toBe('auto');
  });

  it('generates unique transaction_ref per call', () => {
    const d1 = middleware.generateReceiptDraft('ep_tool', {}, null, 10, null);
    const d2 = middleware.generateReceiptDraft('ep_tool', {}, null, 10, null);
    expect(d1.transaction_ref).not.toBe(d2.transaction_ref);
  });
});

// ============================================================================
// 17. AutoReceiptMiddleware.redactSensitive()
// ============================================================================

describe('AutoReceiptMiddleware.redactSensitive()', () => {
  let middleware;

  beforeEach(() => {
    middleware = new AutoReceiptMiddleware({ optIn: true });
  });

  it('removes "password" field', () => {
    const result = middleware.redactSensitive({ password: 'hunter2', username: 'alice' });
    expect(result.password).toBe('[REDACTED]');
    expect(result.username).toBe('alice');
  });

  it('removes "api_key" field', () => {
    const result = middleware.redactSensitive({ api_key: 'sk-abc123', endpoint: '/api/v1' });
    expect(result.api_key).toBe('[REDACTED]');
    expect(result.endpoint).toBe('/api/v1');
  });

  it('removes "token" field', () => {
    const result = middleware.redactSensitive({ token: 'eyJhbGciOiJIUzI1NiJ9', user_id: 'u-1' });
    expect(result.token).toBe('[REDACTED]');
    expect(result.user_id).toBe('u-1');
  });

  it('handles nested objects — redacts sensitive keys at any depth', () => {
    const input = {
      config: { database: { password: 'db-pass', host: 'localhost' }, api_key: 'nested-key' },
      name: 'my-service',
    };
    const result = middleware.redactSensitive(input);
    expect(result.config.database.password).toBe('[REDACTED]');
    expect(result.config.database.host).toBe('localhost');
    expect(result.config.api_key).toBe('[REDACTED]');
    expect(result.name).toBe('my-service');
  });

  it('preserves non-sensitive fields', () => {
    const input = { entity_id: 'my-entity', task_type: 'search', count: 42 };
    const result = middleware.redactSensitive(input);
    expect(result.entity_id).toBe('my-entity');
    expect(result.task_type).toBe('search');
    expect(result.count).toBe(42);
  });

  it('does not mutate the original object', () => {
    const original = { password: 'secret', name: 'test' };
    const copy = { ...original };
    middleware.redactSensitive(original);
    expect(original.password).toBe('secret');
    expect(original).toEqual(copy);
  });
});
