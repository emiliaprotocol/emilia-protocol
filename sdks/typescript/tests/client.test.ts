// ============================================================================
// EMILIA Protocol TypeScript SDK — Unit Tests
// ============================================================================
// All tests use `fetchImpl` injection so no global fetch patching is needed
// for the happy-path suite.  The AbortController / timeout test uses
// vi.stubGlobal because the client falls back to the global fetch when no
// fetchImpl is provided.
// ============================================================================

import { describe, it, expect, vi, beforeEach, type MockedFunction } from 'vitest';
import { EPClient } from '../src/client.js';
import { EPError } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helper – build a mock fetch that resolves with the given payload / status
// ---------------------------------------------------------------------------

type MockFetch = MockedFunction<typeof fetch>;

function makeFetch(payload: unknown, status = 200): MockFetch {
  const mockFn = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(payload),
  } as unknown as Response);
  return mockFn as MockFetch;
}

// Convenience: create an EPClient with a mock fetch already wired in
function makeClient(payload: unknown, status = 200, extraOpts: Record<string, unknown> = {}) {
  const mockFetch = makeFetch(payload, status);
  const client = new EPClient({
    apiKey: 'ep_live_test_key',
    fetchImpl: mockFetch as unknown as typeof fetch,
    ...extraOpts,
  });
  return { client, mockFetch };
}

// ---------------------------------------------------------------------------
// 1. Constructor
// ---------------------------------------------------------------------------

describe('EPClient constructor', () => {
  it('uses the DEFAULT base URL when none is supplied', () => {
    const { client, mockFetch } = makeClient({ entity_id: 'x', display_name: 'X', entity_type: 'agent', current_confidence: 'confident', historical_establishment: true, effective_evidence_current: 1, effective_evidence_historical: 1, compat_score: 80 });
    client.trustProfile('x');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/^https:\/\/emiliaprotocol\.ai\//);
  });

  it('strips a trailing slash from baseUrl', () => {
    const mockFetch = makeFetch({ status: 'ok' });
    const client = new EPClient({
      baseUrl: 'https://example.com/',
      fetchImpl: mockFetch as unknown as typeof fetch,
    });
    client.health();
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://example.com/api/health');
  });

  it('uses a custom base URL', () => {
    const { client, mockFetch } = makeClient({ status: 'ok' });
    const customClient = new EPClient({
      baseUrl: 'https://staging.emiliaprotocol.ai',
      fetchImpl: mockFetch as unknown as typeof fetch,
    });
    customClient.health();
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://staging.emiliaprotocol.ai/api/health');
  });

  it('sends the API key as a Bearer token on authenticated endpoints', async () => {
    const payload = {
      receipt: { receipt_id: 'r1', entity_id: 'e1', receipt_hash: 'h', transaction_ref: 'tx', transaction_type: 'purchase', created_at: '2024-01-01' },
    };
    const { client, mockFetch } = makeClient(payload);
    await client.submitReceipt({ entity_id: 'e1', transaction_ref: 'tx', transaction_type: 'purchase', agent_behavior: 'completed' });
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer ep_live_test_key');
  });

  it('does NOT send Authorization on unauthenticated endpoints', async () => {
    const { client, mockFetch } = makeClient({ policies: [] });
    await client.listPolicies();
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Authorization']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 2. HTTP method / path routing
// ---------------------------------------------------------------------------

describe('HTTP method and path routing', () => {
  it('trustProfile — GET /api/trust/profile/:id', async () => {
    const profile = { entity_id: 'merchant-xyz', display_name: 'XYZ', entity_type: 'merchant', current_confidence: 'confident', historical_establishment: true, effective_evidence_current: 5, effective_evidence_historical: 10, compat_score: 90 };
    const { client, mockFetch } = makeClient(profile);
    const result = await client.trustProfile('merchant-xyz');
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/trust/profile/merchant-xyz');
    expect(init.method ?? 'GET').toBe('GET');
    expect(result.entity_id).toBe('merchant-xyz');
    expect(result.current_confidence).toBe('confident');
  });

  it('trustProfile URL-encodes the entity ID', async () => {
    const { client, mockFetch } = makeClient({});
    await client.trustProfile('some entity/special').catch(() => {});
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('some%20entity%2Fspecial');
  });

  it('trustEvaluate — POST /api/trust/evaluate', async () => {
    const evalResult = { entity_id: 'e1', display_name: 'E1', policy_used: 'standard', decision: 'allow', pass: true, confidence: 'confident', reasons: [], appeal_path: '/appeals' };
    const { client, mockFetch } = makeClient(evalResult);
    const result = await client.trustEvaluate('e1', 'standard', { geo: 'US' });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/trust/evaluate');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.entity_id).toBe('e1');
    expect(body.policy).toBe('standard');
    expect(body.context.geo).toBe('US');
    expect(result.decision).toBe('allow');
  });

  it('trustGate — POST /api/trust/gate', async () => {
    const gateResult = { entity_id: 'agent-v2', action: 'execute_payment', decision: 'allow', policy_used: 'strict', confidence: 'confident' };
    const { client, mockFetch } = makeClient(gateResult);
    const result = await client.trustGate({ entityId: 'agent-v2', action: 'execute_payment', policy: 'strict', valueUsd: 500 });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/trust/gate');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.entity_id).toBe('agent-v2');
    expect(body.value_usd).toBe(500);
    expect(result.decision).toBe('allow');
  });

  it('stats — GET /api/stats', async () => {
    const statsData = { total_entities: 100, trust_surfaces: 5, automated_checks: 200, trust_policies: 8, mcp_tools: 10 };
    const { client, mockFetch } = makeClient(statsData);
    const result = await client.stats();
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/stats');
    expect(init.method ?? 'GET').toBe('GET');
    expect(result.total_entities).toBe(100);
  });

  it('health — GET /api/health', async () => {
    const { client, mockFetch } = makeClient({ status: 'ok' });
    const result = await client.health();
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/health');
    expect(result.status).toBe('ok');
  });

  it('submitReceipt — POST /api/receipts/submit with auth', async () => {
    const receiptPayload = { receipt: { receipt_id: 'r1', entity_id: 'e1', receipt_hash: 'abc', transaction_ref: 'tx1', transaction_type: 'purchase', created_at: '2024-01-01' } };
    const { client, mockFetch } = makeClient(receiptPayload);
    await client.submitReceipt({ entity_id: 'e1', transaction_ref: 'tx1', transaction_type: 'purchase', agent_behavior: 'completed', delivery_accuracy: 98 });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/receipts/submit');
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer ep_live_test_key');
    const body = JSON.parse(init.body as string);
    expect(body.delivery_accuracy).toBe(98);
  });

  it('batchSubmit — POST /api/receipts/batch, slices at 50', async () => {
    const batchResult = { results: [{ entity_id: 'e1', success: true, receipt_id: 'r1' }] };
    const { client, mockFetch } = makeClient(batchResult);
    const many = Array.from({ length: 60 }, (_, i) => ({ entity_id: `e${i}`, transaction_ref: `tx${i}`, transaction_type: 'purchase' as const }));
    await client.batchSubmit(many);
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/receipts/batch');
    const body = JSON.parse(init.body as string);
    expect(body.receipts).toHaveLength(50);
  });

  it('fileDispute — POST /api/disputes/file with auth', async () => {
    const disputeData = { dispute_id: 'dp1', receipt_id: 'r1', status: 'pending', reason: 'fraudulent_receipt', response_deadline: '2024-02-01', _message: 'Dispute filed' };
    const { client, mockFetch } = makeClient(disputeData);
    const result = await client.fileDispute({ receiptId: 'r1', reason: 'fraudulent_receipt', description: 'desc' });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/disputes/file');
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toMatch(/^Bearer /);
    const body = JSON.parse(init.body as string);
    expect(body.receipt_id).toBe('r1');
    expect(result.dispute_id).toBe('dp1');
  });

  it('listPolicies — GET /api/policies (no auth)', async () => {
    const policiesData = { policies: [{ name: 'standard', family: 'core', description: 'Standard policy' }] };
    const { client, mockFetch } = makeClient(policiesData);
    const result = await client.listPolicies();
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/policies');
    expect(init.method ?? 'GET').toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBeUndefined();
    expect(result.policies).toHaveLength(1);
  });

  it('issueCommit — POST /api/commit/issue with auth', async () => {
    const commitResult = { decision: 'allow', commit: { commit_id: 'epc_1', action_type: 'transact', entity_id: 'e1', decision: 'allow', status: 'active', expires_at: '2026-01-01', created_at: '2024-01-01' } };
    const { client, mockFetch } = makeClient(commitResult);
    const result = await client.issueCommit({ action_type: 'transact', entity_id: 'e1', policy: 'strict', max_value_usd: 200 });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/commit/issue');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['Authorization']).toMatch(/^Bearer /);
    expect(result.decision).toBe('allow');
    expect(result.commit.commit_id).toBe('epc_1');
  });

  it('revokeCommit — POST /api/commit/:id/revoke with auth', async () => {
    const revokeResult = { commit_id: 'epc_1', status: 'revoked' as const, revoked_at: '2024-01-02' };
    const { client, mockFetch } = makeClient(revokeResult);
    const result = await client.revokeCommit('epc_1', 'no longer needed');
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/commit/epc_1/revoke');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.reason).toBe('no longer needed');
    expect(result.status).toBe('revoked');
  });
});

// ---------------------------------------------------------------------------
// 3. Query-string parameters
// ---------------------------------------------------------------------------

describe('Query-string parameter handling', () => {
  it('searchEntities appends q, type, min_confidence to URL', async () => {
    const { client, mockFetch } = makeClient({ entities: [] });
    await client.searchEntities('payment', 'agent', 'confident');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('q=payment');
    expect(url).toContain('type=agent');
    expect(url).toContain('min_confidence=confident');
  });

  it('leaderboard caps limit at 50', async () => {
    const { client, mockFetch } = makeClient({ leaderboard: [] });
    await client.leaderboard(100, 'merchant');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('limit=50');
  });

  it('domainScore sends domains as comma-separated query param', async () => {
    const { client, mockFetch } = makeClient({ entity_id: 'e1', domains: {} });
    await client.domainScore('e1', ['financial', 'delegation']);
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('domains=financial%2Cdelegation');
  });

  it('verifyDelegation sends action_type as query param', async () => {
    const delegationData = { delegation_id: 'd1', principal_id: 'p1', agent_entity_id: 'a1', scope: {}, expires_at: '2026-01-01', status: 'active' as const, valid: true };
    const { client, mockFetch } = makeClient(delegationData);
    await client.verifyDelegation('d1', 'purchase');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('action_type=purchase');
  });
});

// ---------------------------------------------------------------------------
// 4. Response parsing and typing
// ---------------------------------------------------------------------------

describe('Response parsing', () => {
  it('confirmReceipt parses confirmed and recorded_at fields', async () => {
    const confirmData = { receipt_id: 'r1', confirmed: true, recorded_at: '2024-06-01T00:00:00Z' };
    const { client } = makeClient(confirmData);
    const result = await client.confirmReceipt('r1', true);
    expect(result.confirmed).toBe(true);
    expect(result.recorded_at).toBe('2024-06-01T00:00:00Z');
  });

  it('lineage parses predecessors and successors arrays', async () => {
    const lineageData = { entity_id: 'e2', predecessors: [{ from: 'e1', reason: 'rebrand', status: 'approved' }], successors: [] };
    const { client } = makeClient(lineageData);
    const result = await client.lineage('e2');
    expect(result.predecessors).toHaveLength(1);
    expect(result.predecessors![0].from).toBe('e1');
  });

  it('principalLookup returns principal with entities and bindings', async () => {
    const lookupData = {
      principal: { principal_id: 'pp1', display_name: 'Acme', principal_type: 'org', status: 'active' },
      entities: [{ entity_id: 'e1', display_name: 'E1', entity_type: 'agent' }],
      bindings: [{ binding_type: 'github_org', binding_target: 'acme', status: 'verified', provenance: 'oauth' }],
    };
    const { client } = makeClient(lookupData);
    const result = await client.principalLookup('pp1');
    expect(result.principal.principal_id).toBe('pp1');
    expect(result.entities).toHaveLength(1);
  });

  it('verifyReceipt returns receipt_id, anchored, verified fields', async () => {
    const verifyData = { receipt_id: 'r1', receipt_hash: 'abc123', anchored: true, verified: true };
    const { client } = makeClient(verifyData);
    const result = await client.verifyReceipt('r1');
    expect(result.verified).toBe(true);
    expect(result.anchored).toBe(true);
  });

  it('bindReceiptToCommit returns status fulfilled and receipt_id', async () => {
    const bindData = { commit_id: 'epc_1', status: 'fulfilled' as const, receipt_id: 'r_abc' };
    const { client } = makeClient(bindData);
    const result = await client.bindReceiptToCommit('epc_1', 'r_abc');
    expect(result.status).toBe('fulfilled');
    expect(result.receipt_id).toBe('r_abc');
  });
});

// ---------------------------------------------------------------------------
// 5. Error handling — 4xx / 5xx responses throw EPError
// ---------------------------------------------------------------------------

describe('EPError thrown on non-2xx responses', () => {
  it('throws EPError on 404 with correct status', async () => {
    const { client } = makeClient({ error: 'Entity not found', code: 'not_found' }, 404);
    await expect(client.trustProfile('no-such-entity')).rejects.toThrow(EPError);
  });

  it('EPError.status reflects the HTTP status code', async () => {
    const { client } = makeClient({ error: 'Not found', code: 'not_found' }, 404);
    let caught: EPError | undefined;
    try {
      await client.trustProfile('no-such-entity');
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught).toBeInstanceOf(EPError);
    expect(caught!.status).toBe(404);
  });

  it('EPError.code reflects the API-level error code', async () => {
    const { client } = makeClient({ error: 'Unauthorized', code: 'unauthorized' }, 401);
    let caught: EPError | undefined;
    try {
      await client.submitReceipt({ entity_id: 'e1', transaction_ref: 'tx', transaction_type: 'purchase' });
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught!.code).toBe('unauthorized');
  });

  it('EPError.message uses the API error string when present', async () => {
    const { client } = makeClient({ error: 'Rate limit exceeded' }, 429);
    let caught: EPError | undefined;
    try {
      await client.stats();
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught!.message).toBe('Rate limit exceeded');
  });

  it('EPError.message falls back to generic when no error field', async () => {
    const { client } = makeClient({ detail: 'something' }, 500);
    let caught: EPError | undefined;
    try {
      await client.stats();
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught!.message).toMatch(/EP API error: 500/);
  });

  it('throws EPError on 403', async () => {
    const { client } = makeClient({ error: 'Forbidden', code: 'forbidden' }, 403);
    await expect(client.listPolicies()).rejects.toMatchObject({ status: 403, code: 'forbidden' });
  });

  it('EPError name is "EPError"', async () => {
    const { client } = makeClient({ error: 'Bad request' }, 400);
    let caught: EPError | undefined;
    try {
      await client.health();
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught!.name).toBe('EPError');
  });
});

// ---------------------------------------------------------------------------
// 6. Missing API key
// ---------------------------------------------------------------------------

describe('Missing API key behavior', () => {
  it('client with no apiKey does not send Authorization header', async () => {
    const mockFetch = makeFetch({ policies: [] });
    const client = new EPClient({ fetchImpl: mockFetch as unknown as typeof fetch });
    await client.listPolicies();
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();
  });

  it('client with empty string apiKey does not send Authorization header', async () => {
    const mockFetch = makeFetch({ policies: [] });
    const client = new EPClient({ apiKey: '', fetchImpl: mockFetch as unknown as typeof fetch });
    await client.listPolicies();
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 7. Timeout / AbortController
// ---------------------------------------------------------------------------

describe('AbortController timeout', () => {
  it('throws EPError with code "timeout" when fetch is aborted', async () => {
    const abortError = new DOMException('The operation was aborted', 'AbortError');
    const mockFetch = vi.fn().mockRejectedValue(abortError) as MockFetch;
    const client = new EPClient({
      apiKey: 'ep_live_key',
      timeout: 1,
      fetchImpl: mockFetch as unknown as typeof fetch,
    });
    let caught: EPError | undefined;
    try {
      await client.health();
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught).toBeInstanceOf(EPError);
    expect(caught!.code).toBe('timeout');
    expect(caught!.message).toMatch(/timed out/i);
  });
});

// ---------------------------------------------------------------------------
// 8. Network errors
// ---------------------------------------------------------------------------

describe('Network error handling', () => {
  it('wraps a generic fetch failure as EPError with code "network_error"', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('DNS lookup failed')) as MockFetch;
    const client = new EPClient({
      fetchImpl: mockFetch as unknown as typeof fetch,
    });
    let caught: EPError | undefined;
    try {
      await client.health();
    } catch (err) {
      caught = err as EPError;
    }
    expect(caught).toBeInstanceOf(EPError);
    expect(caught!.code).toBe('network_error');
    expect(caught!.message).toBe('DNS lookup failed');
  });
});

// ---------------------------------------------------------------------------
// 9. Additional method coverage
// ---------------------------------------------------------------------------

describe('Additional public methods', () => {
  it('registerEntity — POST /api/entities/register', async () => {
    const regData = { entity: { entity_id: 'new-agent', display_name: 'New Agent' }, api_key: 'ep_live_newkey' };
    const { client, mockFetch } = makeClient(regData);
    const result = await client.registerEntity({ entityId: 'new-agent', displayName: 'New Agent', entityType: 'agent', description: 'test', capabilities: ['payment'] });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/entities/register');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.entity_type).toBe('agent');
    expect(result.api_key).toBe('ep_live_newkey');
  });

  it('installPreflight — POST /api/trust/install-preflight', async () => {
    const preflightData = { entity_id: 'mcp-server-1', display_name: 'MCP Server 1', decision: 'allow', policy_used: 'mcp_server_safe_v1', confidence: 'confident', score: 95 };
    const { client, mockFetch } = makeClient(preflightData);
    const result = await client.installPreflight('mcp-server-1', 'mcp_server_safe_v1', { host: 'claude-desktop' });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/trust/install-preflight');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.context?.host).toBe('claude-desktop');
    expect(result.decision).toBe('allow');
  });

  it('createDelegation — POST /api/delegations/create with auth', async () => {
    const delegData = { delegation_id: 'del1', principal_id: 'p1', agent_entity_id: 'a1', scope: {}, expires_at: '2026-12-31', status: 'active' as const };
    const { client, mockFetch } = makeClient(delegData);
    const result = await client.createDelegation({ principalId: 'p1', agentEntityId: 'a1', scope: ['purchase'], maxValueUsd: 1000, expiresAt: '2026-12-31' });
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/delegations/create');
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toMatch(/^Bearer /);
    const body = JSON.parse(init.body as string);
    expect(body.max_value_usd).toBe(1000);
    expect(result.delegation_id).toBe('del1');
  });

  it('legacyScore — GET /api/score/:id', async () => {
    const { client, mockFetch } = makeClient({ entity_id: 'e1', score: 77 });
    const result = await client.legacyScore('e1');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/score/e1');
    expect(result.score).toBe(77);
  });

  it('disputeStatus — GET /api/disputes/:id', async () => {
    const disputeData = { dispute_id: 'dp1', receipt_id: 'r1', status: 'pending' as const, reason: 'other' as const };
    const { client, mockFetch } = makeClient(disputeData);
    const result = await client.disputeStatus('dp1');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/disputes/dp1');
    expect(result.status).toBe('pending');
  });

  it('getCommitStatus — GET /api/commit/:id with auth', async () => {
    const statusData = { commit: { commit_id: 'epc_1', action_type: 'transact', entity_id: 'e1', decision: 'allow', status: 'active', expires_at: '2026-01-01', created_at: '2024-01-01' } };
    const { client, mockFetch } = makeClient(statusData);
    const result = await client.getCommitStatus('epc_1');
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://emiliaprotocol.ai/api/commit/epc_1');
    expect((init.headers as Record<string, string>)['Authorization']).toMatch(/^Bearer /);
    expect(result.commit.commit_id).toBe('epc_1');
  });
});
