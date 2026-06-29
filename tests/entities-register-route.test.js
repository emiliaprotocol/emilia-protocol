// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetGuardedClient = vi.fn();
const mockGenerateEmbedding = vi.fn();
const mockLoggerError = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/providers/embeddings', () => ({
  generateEmbedding: (...args) => mockGenerateEmbedding(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: (...args) => mockLoggerError(...args), info: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/entities/register/route.js');

function request(body, headers = {}) {
  return new Request('https://x.test/api/entities/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

function makeClient(calls) {
  let entityFromCalls = 0;
  return {
    from(table) {
      if (table === 'entities') {
        entityFromCalls += 1;
        if (entityFromCalls === 1) {
          return {
            select() { return this; },
            eq() { return this; },
            single: vi.fn().mockResolvedValue({ data: null, error: { code: 'PGRST116' } }),
          };
        }
        if (entityFromCalls === 2) {
          return {
            select() { return this; },
            eq(_col, value) {
              calls.displayNameKeyLookup = value;
              return this;
            },
            maybeSingle: vi.fn().mockResolvedValue({
              data: calls.existingDisplayNameKey ? { id: 'existing-entity' } : null,
              error: null,
            }),
          };
        }
        return {
          insert(payload) {
            calls.entityInsert = payload;
            return this;
          },
          select() { return this; },
          single: vi.fn(async () => ({
            data: {
              id: 'uuid-entity',
              entity_id: calls.entityInsert.entity_id,
              display_name: calls.entityInsert.display_name,
              entity_type: calls.entityInsert.entity_type,
              status: 'active',
              created_at: '2026-06-28T00:00:00.000Z',
            },
            error: null,
          })),
        };
      }
      if (table === 'api_keys') {
        return {
          insert(payload) {
            calls.apiKeyInsert = payload;
            return Promise.resolve({ error: null });
          },
        };
      }
      throw new Error(`unexpected table ${table}`);
    },
  };
}

describe('POST /api/entities/register hardening', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
    mockGenerateEmbedding.mockReset();
    mockLoggerError.mockReset();
    vi.unstubAllEnvs();
    mockGenerateEmbedding.mockResolvedValue([0.1, 0.2]);
  });

  it('creates org-bound entities so issued keys carry tenant scope', async () => {
    const calls = {};
    mockGetGuardedClient.mockReturnValue(makeClient(calls));

    const res = await POST(request({
      entity_id: 'acme-agent-1',
      display_name: 'Acme Agent',
      entity_type: 'agent',
      description: 'Approves invoices',
      capabilities: ['invoice_approval'],
    }));
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.entity.entity_id).toBe('acme-agent-1');
    expect(calls.entityInsert.organization_id).toBe('acme-agent-1');
    expect(calls.entityInsert.display_name_key).toBe('acmeagent');
    expect(calls.apiKeyInsert.entity_id).toBe('uuid-entity');
  });

  it('rejects normalized display-name collisions before key issuance', async () => {
    const calls = { existingDisplayNameKey: true };
    mockGetGuardedClient.mockReturnValue(makeClient(calls));

    const res = await POST(request({
      entity_id: 'acme-agent-2',
      display_name: ' A.C.M.E.   Agent ',
      entity_type: 'agent',
      description: 'Looks too similar',
      capabilities: ['invoice_approval'],
    }));
    const body = await res.json();

    expect(res.status).toBe(409);
    expect(body.type).toContain('registration_failed');
    expect(calls.displayNameKeyLookup).toBe('acmeagent');
    expect(calls.apiKeyInsert).toBeUndefined();
  });

  it('rejects invalid entity ids before embedding work', async () => {
    mockGetGuardedClient.mockReturnValue(makeClient({}));

    const res = await POST(request({
      entity_id: '../metadata',
      display_name: 'Bad Entity',
      entity_type: 'agent',
      description: 'Bad',
    }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.type).toContain('invalid_entity_id');
    expect(mockGenerateEmbedding).not.toHaveBeenCalled();
  });

  it('rejects oversized declared payloads before JSON parsing work', async () => {
    const res = await POST(request({}, { 'content-length': String(65 * 1024) }));
    const body = await res.json();

    expect(res.status).toBe(413);
    expect(body.type).toContain('payload_too_large');
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('is production-closed unless public entity registration is explicitly enabled', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('EP_ENABLE_PUBLIC_ENTITY_REGISTRATION', '');

    const res = await POST(request({
      entity_id: 'prod-open-mint',
      display_name: 'Prod Open Mint',
      entity_type: 'agent',
    }));
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(body.type).toContain('self_serve_registration_disabled');
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('rejects text/plain posts before parsing or embedding work', async () => {
    const res = await POST(new Request('https://x.test/api/entities/register', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{"entity_id":"plain","display_name":"Plain"}',
    }));
    const body = await res.json();

    expect(res.status).toBe(415);
    expect(body.type).toContain('unsupported_media_type');
    expect(mockGenerateEmbedding).not.toHaveBeenCalled();
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });
});
