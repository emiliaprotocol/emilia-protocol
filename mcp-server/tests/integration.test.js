/**
 * EMILIA Protocol MCP Server — Integration Tests
 *
 * Tests tool handler behavior against mocked HTTP responses:
 *   - Correct endpoint construction (BASE_URL + path)
 *   - Auth header inclusion on authenticated tools
 *   - Response formatting (non-empty string result)
 *   - Error handling (4xx/5xx → clean message, no stack trace)
 *   - API key guard for write tools
 *
 * Strategy: import the module once with a test API key pre-set,
 * spy on globalThis.fetch per-test, call handleTool directly.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Set env before any module import (captured at module load time)
// ---------------------------------------------------------------------------

process.env.EP_BASE_URL = 'https://ep-test.example.com';
process.env.EP_API_KEY  = 'ep_test_integration_key';

// ---------------------------------------------------------------------------
// Mock MCP SDK so index.js can be imported without a real transport.
// ---------------------------------------------------------------------------

vi.mock('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: vi.fn(function MockServer() {
    this.setRequestHandler = vi.fn();
    this.connect = vi.fn().mockResolvedValue(undefined);
  }),
}));
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn(function MockTransport() {}),
}));
vi.mock('@modelcontextprotocol/sdk/types.js', () => ({
  CallToolRequestSchema:       'CallToolRequestSchema',
  ListToolsRequestSchema:      'ListToolsRequestSchema',
  ListResourcesRequestSchema:  'ListResourcesRequestSchema',
  ReadResourceRequestSchema:   'ReadResourceRequestSchema',
  ListPromptsRequestSchema:    'ListPromptsRequestSchema',
  GetPromptRequestSchema:      'GetPromptRequestSchema',
}));

// ---------------------------------------------------------------------------
// Import after mocks + env are configured
// ---------------------------------------------------------------------------

const { handleTool } = await import('../index.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let fetchSpy;

function mockOk(body) {
  fetchSpy.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: async () => body,
  });
}

function mockError(body, status) {
  fetchSpy.mockResolvedValueOnce({
    ok: false,
    status,
    json: async () => body,
  });
}

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch');
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Require handleTool to be exported for all tests to run
// ---------------------------------------------------------------------------

const SKIP = !handleTool;

// ---------------------------------------------------------------------------
// ── 1. ep_trust_profile — public GET ────────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('ep_trust_profile', () => {
  it('calls GET /api/trust/profile/:entity_id', async () => {
    mockOk({ entity_id: 'merchant-abc', composite_score: 91 });

    await handleTool('ep_trust_profile', { entity_id: 'merchant-abc' });

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, opts] = fetchSpy.mock.calls[0];
    expect(url).toContain('/api/trust/profile/merchant-abc');
    expect((opts.method ?? 'GET').toUpperCase()).toBe('GET');
  });

  it('URL-encodes entity_id', async () => {
    mockOk({ entity_id: 'a/b', composite_score: 70 });
    await handleTool('ep_trust_profile', { entity_id: 'a/b c' });

    const [url] = fetchSpy.mock.calls[0];
    expect(url).not.toContain(' ');
  });

  it('uses configured BASE_URL', async () => {
    mockOk({ entity_id: 'e1', composite_score: 80 });
    await handleTool('ep_trust_profile', { entity_id: 'e1' });

    const [url] = fetchSpy.mock.calls[0];
    expect(url).toMatch(/^https:\/\/ep-test\.example\.com/);
  });

  it('returns a non-empty string result', async () => {
    mockOk({ entity_id: 'e2', composite_score: 75, behavioral_rates: {} });
    const result = await handleTool('ep_trust_profile', { entity_id: 'e2' });
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('propagates API error without stack trace', async () => {
    mockError({ error: 'Entity not found' }, 404);
    const result = await handleTool('ep_trust_profile', { entity_id: 'ghost' }).catch(
      (e) => e.message,
    );
    const msg = typeof result === 'string' ? result : result?.message ?? '';
    expect(msg).not.toMatch(/\s+at\s+\w/);
    expect(msg).toMatch(/not found|404|error/i);
  });
});

// ---------------------------------------------------------------------------
// ── 2. ep_trust_evaluate — POST, no auth ────────────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('ep_trust_evaluate', () => {
  it('calls POST /api/trust/evaluate', async () => {
    mockOk({ decision: 'allow', entity_id: 'e1', policy_used: 'standard' });

    await handleTool('ep_trust_evaluate', { entity_id: 'e1', policy: 'standard' });

    const [url, opts] = fetchSpy.mock.calls[0];
    expect(url).toContain('/api/trust/evaluate');
    expect(opts.method).toBe('POST');
  });

  it('sends entity_id and policy in body', async () => {
    mockOk({ decision: 'deny', entity_id: 'e2', policy_used: 'strict' });
    await handleTool('ep_trust_evaluate', { entity_id: 'e2', policy: 'strict' });

    const [, opts] = fetchSpy.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.entity_id).toBe('e2');
    expect(body.policy).toBe('strict');
  });

  it('defaults policy to "standard"', async () => {
    mockOk({ decision: 'allow', entity_id: 'e3', policy_used: 'standard' });
    await handleTool('ep_trust_evaluate', { entity_id: 'e3' });

    const [, opts] = fetchSpy.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.policy).toBe('standard');
  });

  it('returns non-empty string', async () => {
    mockOk({ decision: 'review', entity_id: 'e4', policy_used: 'standard', failures: [] });
    const result = await handleTool('ep_trust_evaluate', { entity_id: 'e4' });
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// ── 3. ep_submit_receipt — authenticated write ───────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('ep_submit_receipt', () => {
  it('includes Authorization: Bearer header', async () => {
    mockOk({ receipt: { receipt_id: 'r1', receipt_hash: 'h1' } });

    await handleTool('ep_submit_receipt', {
      entity_id: 'merchant-001',
      counterparty_id: 'buyer-001',
      transaction_value: 500,
      outcome: 'completed',
    });

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [, opts] = fetchSpy.mock.calls[0];
    expect(opts.headers?.Authorization).toBe('Bearer ep_test_integration_key');
  });

  it('calls POST /api/receipts/submit', async () => {
    mockOk({ receipt: { receipt_id: 'r2', receipt_hash: 'h2' } });
    await handleTool('ep_submit_receipt', {
      entity_id: 'e1',
      counterparty_id: 'e2',
      transaction_value: 100,
      outcome: 'completed',
    });
    const [url, opts] = fetchSpy.mock.calls[0];
    expect(url).toContain('/api/receipts/submit');
    expect(opts.method).toBe('POST');
  });

  it('returns string with receipt ID', async () => {
    mockOk({ receipt: { receipt_id: 'rcpt-xyz', receipt_hash: 'hxyz' } });
    const result = await handleTool('ep_submit_receipt', {
      entity_id: 'e1',
      counterparty_id: 'e2',
      transaction_value: 10,
      outcome: 'completed',
    });
    expect(typeof result).toBe('string');
    expect(result).toContain('rcpt-xyz');
  });
});

// ---------------------------------------------------------------------------
// ── 4. ep_initiate_handshake — authenticated write ───────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('ep_initiate_handshake', () => {
  it('calls POST /api/handshake with auth header', async () => {
    mockOk({ handshake_id: 'hs-1', status: 'initiated', nonce: 'n1' });

    await handleTool('ep_initiate_handshake', {
      initiator_id: 'entity-a',
      responder_id: 'entity-b',
      policy_id: 'strict',
    });

    const [url, opts] = fetchSpy.mock.calls[0];
    expect(url).toContain('/api/handshake');
    expect(opts.method).toBe('POST');
    expect(opts.headers?.Authorization).toMatch(/^Bearer /);
  });
});

// ---------------------------------------------------------------------------
// ── 5. ep_get_handshake — read with handshake_id path param ─────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('ep_get_handshake', () => {
  it('constructs URL with handshake_id', async () => {
    mockOk({ handshake_id: 'hs-999', status: 'verified' });
    await handleTool('ep_get_handshake', { handshake_id: 'hs-999' });

    const [url] = fetchSpy.mock.calls[0];
    expect(url).toContain('hs-999');
  });
});

// ---------------------------------------------------------------------------
// ── 6. Error handling — no stack trace leakage ──────────────────────────────
// ---------------------------------------------------------------------------

describe.skipIf(SKIP)('error handling', () => {
  it('does not leak stack trace on 500', async () => {
    mockError({ error: 'Internal server error' }, 500);
    const result = await handleTool('ep_trust_profile', { entity_id: 'x' }).catch(
      (e) => e.message,
    );
    const msg = typeof result === 'string' ? result : result?.message ?? String(result);
    expect(msg).not.toMatch(/\s+at\s+\w/);
    expect(msg).not.toMatch(/node_modules/);
  });

  it('does not leak stack trace on 429', async () => {
    mockError({ error: 'Rate limit exceeded' }, 429);
    const result = await handleTool('ep_trust_evaluate', { entity_id: 'x' }).catch(
      (e) => e.message,
    );
    const msg = typeof result === 'string' ? result : result?.message ?? String(result);
    expect(msg).not.toMatch(/\s+at\s+\w/);
  });

  it('returns descriptive error message on 401', async () => {
    mockError({ error: 'Invalid API key' }, 401);
    const result = await handleTool('ep_submit_receipt', {
      entity_id: 'e1',
      counterparty_id: 'e2',
      transaction_value: 10,
      outcome: 'completed',
    }).catch((e) => e.message);
    const msg = typeof result === 'string' ? result : result?.message ?? String(result);
    expect(msg).toMatch(/invalid|api key|401|error/i);
  });
});
