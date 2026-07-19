// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const DisputeView = await import('../app/api/disputes/[disputeId]/route.js');
const EntityRoute = await import('../app/api/entity/route.js');
const SandboxProvision = await import('../app/api/pilot/sandbox/provision/route.js');

function jsonReq(body, headers = {}) {
  return new Request('https://www.emiliaprotocol.ai/api/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body ?? {}),
  });
}

function makeInsertClient(calls) {
  function builder(table) {
    const b = {
      insert: vi.fn((payload) => {
        calls.inserts.push({ table, payload });
        return b;
      }),
      select: vi.fn(() => b),
      single: vi.fn(async () => ({ data: { id: `uuid-${table}` }, error: null })),
    };
    return b;
  }
  return { from: (table) => builder(table) };
}

describe('government-launch red-team regressions', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
    vi.unstubAllEnvs();
  });

  it('public dispute view never leaks raw evidence values, even short PII-like values', async () => {
    const dispute = {
      dispute_id: 'disp_1',
      receipt_id: 'tr_1',
      reason: 'fraud',
      description: 'public dispute text',
      evidence: {
        ssn: '123-45-6789',
        case_id: 'A17',
        amount: 25,
        confirmed: true,
        attachments: ['a.pdf'],
        nested: { secret: 'x' },
      },
      status: 'open',
      filed_by_type: 'third_party',
      response: null,
      response_deadline: null,
      entity: { entity_id: 'ent_subject', display_name: 'Subject' },
      filer: { entity_id: 'ent_filer', display_name: 'Filer' },
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
    };
    const chain = {
      select: vi.fn(() => chain),
      eq: vi.fn(() => chain),
      single: vi.fn(async () => ({ data: dispute, error: null })),
    };
    mockGetGuardedClient.mockReturnValue({ from: () => chain });

    const res = await DisputeView.GET(new Request('https://x/api/disputes/disp_1'), {
      params: Promise.resolve({ disputeId: 'disp_1' }),
    });
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(JSON.stringify(body.evidence_summary)).not.toContain('123-45-6789');
    expect(JSON.stringify(body.evidence_summary)).not.toContain('A17');
    expect(JSON.stringify(body.evidence_summary)).not.toContain('25');
    expect(body.evidence_summary).toEqual({
      ssn: '[redacted string — 11 chars]',
      case_id: '[redacted string — 3 chars]',
      amount: '[redacted number]',
      confirmed: '[redacted boolean]',
      attachments: '[redacted array — 1 items]',
      nested: '[redacted object]',
    });
  });

  it('public entity registration creates an org-bound entity so v1 writes can fail closed correctly', async () => {
    const calls = { inserts: [] };
    mockGetGuardedClient.mockReturnValue(makeInsertClient(calls));

    const res = await EntityRoute.POST(jsonReq({ name: 'Gov Pilot Entity' }));
    const body = await res.json();
    const entityInsert = calls.inserts.find((c) => c.table === 'entities').payload;

    expect(res.status).toBe(201);
    expect(entityInsert.organization_id).toBe(body.entity_id);
    expect(entityInsert.private_key_encrypted).toMatch(/^epenc:v1:/);
  });

  it('public entity registration rejects oversized anonymous payloads before database work', async () => {
    const calls = { inserts: [] };
    mockGetGuardedClient.mockReturnValue(makeInsertClient(calls));

    const res = await EntityRoute.POST(jsonReq({ name: 'x' }, { 'content-length': String(9 * 1024) }));
    const body = await res.json();

    expect(res.status).toBe(413);
    expect(body.type).toContain('payload_too_large');
    expect(calls.inserts).toEqual([]);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('public entity registration is production-closed unless explicitly enabled', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('EP_ENABLE_PUBLIC_ENTITY_REGISTRATION', '');

    const res = await EntityRoute.POST(jsonReq({ name: 'Anonymous Key Mint' }));
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(body.type).toContain('self_serve_registration_disabled');
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('public entity registration rejects text/plain form posts before parsing', async () => {
    const res = await EntityRoute.POST(new Request('https://x/api/entity', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{"name":"csrf-style"}',
    }));
    const body = await res.json();

    expect(res.status).toBe(415);
    expect(body.type).toContain('unsupported_media_type');
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('self-serve pilot sandbox keys are born org-bound to the sandbox id', async () => {
    const calls = { inserts: [] };
    mockGetGuardedClient.mockReturnValue(makeInsertClient(calls));

    const res = await SandboxProvision.POST(jsonReq({ org: 'County Benefits Office', vertical: 'gov' }));
    const body = await res.json();
    const entityInsert = calls.inserts.find((c) => c.table === 'entities').payload;
    const keyInsert = calls.inserts.find((c) => c.table === 'api_keys').payload;

    expect(res.status).toBe(201);
    expect(entityInsert.organization_id).toBe(body.sandbox_id);
    expect(entityInsert.private_key_encrypted).toMatch(/^epenc:v1:/);
    expect(keyInsert.permissions).toEqual([]);
    expect(body.try_now.curl).toContain(`"organization_id":"${body.sandbox_id}"`);
  });

  it('self-serve pilot sandbox rejects oversized anonymous payloads before database work', async () => {
    const calls = { inserts: [] };
    mockGetGuardedClient.mockReturnValue(makeInsertClient(calls));

    const res = await SandboxProvision.POST(jsonReq({ org: 'x' }, { 'content-length': String(9 * 1024) }));
    const body = await res.json();

    expect(res.status).toBe(413);
    expect(body.type).toContain('payload_too_large');
    expect(calls.inserts).toEqual([]);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });
});
