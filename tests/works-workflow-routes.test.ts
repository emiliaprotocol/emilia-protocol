// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(), readWorkspace: vi.fn(), readAssignment: vi.fn(),
  commandRecord: vi.fn(), selectProposal: vi.fn(), commandAssignment: vi.fn(),
  markNotificationRead: vi.fn(),
}));
vi.mock('../app/api/works/_write-auth.ts', () => ({ authenticateWorksWrite: mocks.authenticate }));
vi.mock('../lib/works/workflow-store.ts', () => ({
  createSupabaseWorksWorkflowStore: () => ({
    readWorkspace: mocks.readWorkspace, readAssignment: mocks.readAssignment,
    commandRecord: mocks.commandRecord, selectProposal: mocks.selectProposal,
    commandAssignment: mocks.commandAssignment, markNotificationRead: mocks.markNotificationRead,
  }),
}));

const workspaceRoute = await import('../app/api/works/workspace/route.ts');
const workspaceCommands = await import('../app/api/works/workspace/commands/route.ts');
const assignmentsRoute = await import('../app/api/works/assignments/route.ts');
const assignmentRoute = await import('../app/api/works/assignments/[id]/route.ts');
const assignmentCommands = await import('../app/api/works/assignments/[id]/commands/route.ts');
const notificationRead = await import('../app/api/works/workspace/notifications/[id]/read/route.ts');

const ACTOR = '11111111-1111-4111-8111-111111111111';
const BASE = 'https://www.emiliaprotocol.ai/api/works';
const IDEM = 'works-command-0001';

function request(url: string, method = 'GET', body?: unknown) {
  return new Request(url, {
    method,
    headers: body === undefined ? undefined : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

beforeEach(() => {
  process.env.WORKS_V0 = '1';
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.authenticate.mockResolvedValue({ ok: true, actor: { ownerEntityId: ACTOR, displayName: 'Acme' } });
  mocks.readWorkspace.mockResolvedValue({ ok: true, workspace: {
    viewer: { display_name: 'Acme', role: 'buyer' }, profiles: [], listings: [], jobs: [],
    submitted_proposals: [], received_proposals: [], assignments: [], notifications: [],
  } });
});

describe('Works workflow route boundary', () => {
  it('requires Works authentication before reading the private workspace', async () => {
    const authResponse = new Response('unauthorized', { status: 401 });
    mocks.authenticate.mockResolvedValue({ ok: false, response: authResponse });
    const response = await workspaceRoute.GET(request(`${BASE}/workspace`) as any);
    expect(response.status).toBe(401);
    expect(mocks.readWorkspace).not.toHaveBeenCalled();
  });

  it('returns a no-store workspace without owner UUID projection', async () => {
    const response = await workspaceRoute.GET(request(`${BASE}/workspace`) as any);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toContain('private');
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('vary')).toContain('Cookie');
    expect(mocks.readWorkspace).toHaveBeenCalledWith(ACTOR);
    expect(JSON.stringify(await response.json())).not.toContain(ACTOR);
  });

  it('validates every workspace mutation before touching storage', async () => {
    const invalid = await workspaceCommands.POST(request(`${BASE}/workspace/commands`, 'POST', {
      command: 'close_job', record_id: 'job-one', expected_revision: 0,
    }) as any);
    expect(invalid.status).toBe(400);
    expect(mocks.commandRecord).not.toHaveBeenCalled();

    mocks.commandRecord.mockResolvedValue({ ok: false, code: 'revision_conflict', detail: 'Refresh.' });
    const conflict = await workspaceCommands.POST(request(`${BASE}/workspace/commands`, 'POST', {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    }) as any);
    expect(conflict.status).toBe(409);
  });

  it('selects through the authenticated buyer and returns the RPC replay envelope', async () => {
    mocks.selectProposal.mockResolvedValue({ ok: true, result: {
      ok: true, replayed: false, resource: { assignment_id: 'assignment-one' },
    } });
    const body = {
      proposal_id: 'proposal-one', expected_revision: 0, idempotency_key: IDEM,
      scope: 'Work', acceptance_criteria: ['Pass'], terms: 'External terms.',
    };
    const response = await assignmentsRoute.POST(request(`${BASE}/assignments`, 'POST', body) as any);
    expect(response.status).toBe(201);
    expect(mocks.selectProposal).toHaveBeenCalledWith(ACTOR, body);
    expect(await response.json()).toMatchObject({ ok: true, replayed: false });
  });

  it('keeps assignment reads party-private and command-specific', async () => {
    mocks.readAssignment.mockResolvedValue({ ok: true, viewer_role: 'builder', assignment: {
      assignment_id: 'assignment-one', history: [],
    } });
    const context = { params: Promise.resolve({ id: 'assignment-one' }) };
    const read = await assignmentRoute.GET(request(`${BASE}/assignments/assignment-one`) as any, context);
    expect(read.status).toBe(200);
    expect(await read.json()).toMatchObject({ viewer_role: 'builder' });

    mocks.commandAssignment.mockResolvedValue({ ok: true, result: {
      ok: true, replayed: false, resource: { assignment_id: 'assignment-one', state: 'confirmed' },
    } });
    const command = { command: 'builder_confirm', expected_revision: 0, idempotency_key: IDEM };
    const written = await assignmentCommands.POST(
      request(`${BASE}/assignments/assignment-one/commands`, 'POST', command) as any, context,
    );
    expect(written.status).toBe(200);
    expect(mocks.commandAssignment).toHaveBeenCalledWith(ACTOR, 'assignment-one', command);
  });

  it('marks only the authenticated owner notification read with CAS and replay protection', async () => {
    const notificationId = '33333333-3333-4333-8333-333333333333';
    const command = { expected_revision: 0, idempotency_key: IDEM };
    mocks.markNotificationRead.mockResolvedValue({ ok: true, result: {
      ok: true, replayed: false, resource: {
        notification_id: notificationId, revision: 1, read_at: '2026-09-07T22:00:00Z',
      },
    } });
    const response = await notificationRead.POST(
      request(`${BASE}/workspace/notifications/${notificationId}/read`, 'POST', command) as any,
      { params: Promise.resolve({ id: notificationId }) },
    );
    expect(response.status).toBe(200);
    expect(mocks.markNotificationRead).toHaveBeenCalledWith(ACTOR, notificationId, command);
  });

  it('404s every workflow route before authentication when Works is disabled', async () => {
    delete process.env.WORKS_V0;
    const context = { params: Promise.resolve({ id: 'assignment-one' }) };
    expect((await workspaceRoute.GET(request(`${BASE}/workspace`) as any)).status).toBe(404);
    expect((await assignmentRoute.GET(request(`${BASE}/assignments/assignment-one`) as any, context)).status).toBe(404);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });
});
