// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const database = vi.hoisted(() => ({ getServiceClient: vi.fn() }));
vi.mock('../lib/supabase.js', () => ({ getServiceClient: database.getServiceClient }));

import {
  createSupabaseWorksWorkflowStore,
  getWorksPublicWorkflowStates,
} from '../lib/works/workflow-store.ts';

const ACTOR = '11111111-1111-4111-8111-111111111111';
const IDEM = 'works-command-0001';

function workspace(overrides: Record<string, unknown> = {}) {
  return {
    viewer: { display_name: 'Acme', role: 'buyer' }, profiles: [], listings: [], jobs: [],
    submitted_proposals: [], received_proposals: [], assignments: [], notifications: [],
    ...overrides,
  };
}

function assignment(overrides: Record<string, unknown> = {}) {
  const revision = typeof overrides.revision === 'number' ? overrides.revision : 0;
  return {
    assignment_id: 'assignment-one', job_id: 'job-one', proposal_id: 'proposal-one',
    builder_id: 'builder-one', listing_id: null, state: 'proposed', revision,
    scope: 'Bounded work', acceptance_criteria: ['Evidence attached'], terms: 'External terms',
    frozen: { job: {}, proposal: {} }, delivery: null, outcome: null,
    history: Array.from({ length: revision + 1 }, (_, index) => ({
      actor_role: index === 0 ? 'buyer' : 'builder',
      command: index === 0 ? 'proposal_selected' : 'builder_confirm',
      revision: index, at: '2026-09-07T22:00:00Z', summary: null, reason: null, delivery: null,
    })),
    created_at: '2026-09-07T22:00:00Z', updated_at: '2026-09-07T22:00:00Z',
    ...overrides,
  };
}

describe('Works workflow production adapter', () => {
  const rpc = vi.fn();

  beforeEach(() => {
    rpc.mockReset();
    database.getServiceClient.mockReturnValue({ rpc });
  });

  afterEach(() => vi.unstubAllEnvs());

  it('binds workspace reads to the authenticated actor UUID', async () => {
    rpc.mockResolvedValue({ data: workspace(), error: null });
    const result = await createSupabaseWorksWorkflowStore().readWorkspace(ACTOR);
    expect(rpc).toHaveBeenCalledExactlyOnceWith('read_works_workspace', {
      p_actor_entity_id: ACTOR,
    });
    expect(result).toEqual({ ok: true, workspace: workspace() });
  });

  it('fails closed if any private custody UUID leaks into an RPC projection', async () => {
    rpc.mockResolvedValue({ data: workspace({
      jobs: [{ record: { opportunity_id: 'job-one', owner_entity_id: ACTOR },
        workflow: { state: 'open', revision: 0, updated_at: null } }],
    }), error: null });
    await expect(createSupabaseWorksWorkflowStore().readWorkspace(ACTOR))
      .resolves.toMatchObject({ ok: false, code: 'store_invalid' });
  });

  it('passes CAS and idempotency inputs to one record-command RPC', async () => {
    const response = { ok: true, replayed: false, resource: {
      record_id: 'job-one', collection: 'opportunities',
      workflow: { state: 'closed', revision: 1, updated_at: '2026-09-07T22:00:00Z' },
    } };
    rpc.mockResolvedValue({ data: response, error: null });
    const result = await createSupabaseWorksWorkflowStore().commandRecord(ACTOR, {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    });
    expect(rpc).toHaveBeenCalledExactlyOnceWith('command_works_record', {
      p_actor_entity_id: ACTOR, p_command: 'close_job', p_record_id: 'job-one',
      p_expected_revision: 0, p_idempotency_key: IDEM,
    });
    expect(result).toEqual({ ok: true, result: response });
  });

  it('maps PostgreSQL conflict classes without returning database detail', async () => {
    rpc.mockResolvedValue({ data: null, error: { code: 'EWREV', message: 'private row detail' } });
    await expect(createSupabaseWorksWorkflowStore().commandRecord(ACTOR, {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toEqual({ ok: false, code: 'revision_conflict', detail: 'The record changed. Refresh and retry.' });

    rpc.mockResolvedValue({ data: null, error: { code: 'EWIDM', message: 'private request bytes' } });
    await expect(createSupabaseWorksWorkflowStore().commandRecord(ACTOR, {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'idempotency_conflict' });
  });

  it('uses the job revision as the proposal-selection award fence', async () => {
    rpc.mockResolvedValue({ data: { ok: true, replayed: false, resource: {
      assignment_id: 'assignment-one', job_id: 'job-one', proposal_id: 'proposal-one',
      builder_id: 'builder-one', listing_id: null, state: 'proposed', revision: 0,
      scope: 'Work', acceptance_criteria: ['Pass'], terms: 'External',
      frozen: { job: {}, proposal: {} }, delivery: null, outcome: null,
      history: [{ actor_role: 'buyer', command: 'proposal_selected', revision: 0,
        at: '2026-09-07T22:00:00Z', summary: null, reason: null, delivery: null }],
      created_at: '2026-09-07T22:00:00Z', updated_at: '2026-09-07T22:00:00Z',
    } }, error: null });
    await createSupabaseWorksWorkflowStore().selectProposal(ACTOR, {
      proposal_id: 'proposal-one', expected_revision: 4, idempotency_key: IDEM,
      scope: 'Work', acceptance_criteria: ['Pass'], terms: 'External',
    });
    expect(rpc).toHaveBeenCalledWith('select_works_proposal', expect.objectContaining({
      p_actor_entity_id: ACTOR, p_proposal_id: 'proposal-one', p_expected_revision: 4,
    }));
  });

  it('marks a notification read through its owner-scoped CAS RPC', async () => {
    const notificationId = '33333333-3333-4333-8333-333333333333';
    rpc.mockResolvedValue({ data: { ok: true, replayed: false, resource: {
      notification_id: notificationId, read_at: '2026-09-07T22:00:00Z', revision: 1,
    } }, error: null });
    const result = await createSupabaseWorksWorkflowStore().markNotificationRead(
      ACTOR, notificationId, { expected_revision: 0, idempotency_key: IDEM },
    );
    expect(rpc).toHaveBeenCalledWith('mark_works_notification_read', {
      p_actor_entity_id: ACTOR, p_notification_id: notificationId,
      p_expected_revision: 0, p_idempotency_key: IDEM,
    });
    expect(result).toMatchObject({ ok: true, result: { replayed: false } });
  });

  it('maps every database refusal without exposing database messages', async () => {
    const expected = [
      ['EWTRN', 'invalid_transition'],
      ['EW403', 'forbidden'],
      ['EW404', 'not_found'],
      ['22023', 'invalid_command'],
      ['XX000', 'store_unavailable'],
    ] as const;
    const store = createSupabaseWorksWorkflowStore();
    for (const [databaseCode, publicCode] of expected) {
      rpc.mockResolvedValueOnce({ data: null, error: { code: databaseCode, message: 'private row detail' } });
      const result = await store.commandRecord(ACTOR, {
        command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
      });
      expect(result).toMatchObject({ ok: false, code: publicCode });
      expect(JSON.stringify(result)).not.toContain('private row detail');
    }
    rpc.mockRejectedValueOnce(new Error('private transport detail'));
    await expect(store.commandRecord(ACTOR, {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'store_unavailable' });
  });

  it('fails closed for invalid actors and when only the file fixture is configured', async () => {
    const store = createSupabaseWorksWorkflowStore();
    await expect(store.readWorkspace('not-a-database-uuid'))
      .resolves.toMatchObject({ ok: false, code: 'invalid_actor' });
    expect(rpc).not.toHaveBeenCalled();

    vi.stubEnv('WORKS_DATA_DIR', '/tmp/not-a-production-store');
    database.getServiceClient.mockClear();
    const fileMode = createSupabaseWorksWorkflowStore();
    await expect(fileMode.readWorkspace(ACTOR))
      .resolves.toMatchObject({ ok: false, code: 'store_unavailable' });
    expect(database.getServiceClient).not.toHaveBeenCalled();
  });

  it('returns assignments only to a valid party projection', async () => {
    const store = createSupabaseWorksWorkflowStore();
    await expect(store.readAssignment('bad-actor', 'assignment-one'))
      .resolves.toMatchObject({ ok: false, code: 'not_found' });
    await expect(store.readAssignment(ACTOR, '../assignment'))
      .resolves.toMatchObject({ ok: false, code: 'not_found' });
    expect(rpc).not.toHaveBeenCalled();

    rpc.mockResolvedValueOnce({ data: null, error: null });
    await expect(store.readAssignment(ACTOR, 'assignment-one'))
      .resolves.toMatchObject({ ok: false, code: 'not_found' });
    rpc.mockResolvedValueOnce({ data: { viewer_role: 'buyer', assignment: assignment() }, error: null });
    await expect(store.readAssignment(ACTOR, 'assignment-one')).resolves.toEqual({
      ok: true, viewer_role: 'buyer', assignment: assignment(),
    });
    rpc.mockResolvedValueOnce({ data: {
      viewer_role: 'buyer', assignment: assignment({ frozen: { job: { owner_entity_id: ACTOR }, proposal: {} } }),
    }, error: null });
    await expect(store.readAssignment(ACTOR, 'assignment-one'))
      .resolves.toMatchObject({ ok: false, code: 'store_invalid' });
  });

  it('binds assignment lifecycle evidence and rejects malformed returned history', async () => {
    const store = createSupabaseWorksWorkflowStore();
    rpc.mockResolvedValueOnce({ data: { ok: true, replayed: false, resource: assignment({
      state: 'delivery_submitted', revision: 1,
      delivery: { url: 'https://example.com/evidence', summary: 'Ready', submitted_at: '2026-09-07T22:00:00Z' },
    }) }, error: null });
    const command = {
      command: 'submit_delivery' as const, expected_revision: 0, idempotency_key: IDEM,
      delivery_url: 'https://example.com/evidence', summary: 'Ready',
    };
    await expect(store.commandAssignment(ACTOR, 'assignment-one', command))
      .resolves.toMatchObject({ ok: true, result: { resource: { state: 'delivery_submitted' } } });
    expect(rpc).toHaveBeenCalledWith('command_works_assignment', {
      p_actor_entity_id: ACTOR, p_assignment_id: 'assignment-one', p_command: 'submit_delivery',
      p_expected_revision: 0, p_idempotency_key: IDEM,
      p_payload: { delivery_url: 'https://example.com/evidence', summary: 'Ready' },
    });

    rpc.mockResolvedValueOnce({ data: { ok: true, replayed: false, resource: assignment({
      history: [{ actor_role: 'buyer', command: 'proposal_selected', revision: 2,
        at: '2026-09-07T22:00:00Z', summary: null, reason: null, delivery: null }],
    }) }, error: null });
    await expect(store.commandAssignment(ACTOR, 'assignment-one', {
      command: 'cancel', expected_revision: 0, idempotency_key: IDEM, reason: 'No longer needed',
    })).resolves.toMatchObject({ ok: false, code: 'store_invalid' });
  });

  it('validates public state rows and never forwards invalid identifiers', async () => {
    const store = createSupabaseWorksWorkflowStore();
    await expect(store.readPublicStates('opportunities', ['../job']))
      .resolves.toMatchObject({ ok: false, code: 'invalid_id' });
    expect(rpc).not.toHaveBeenCalled();

    const rows = [{ record_id: 'job-one', workflow: {
      state: 'open', revision: 0, updated_at: '2026-09-07T22:00:00Z',
    } }];
    rpc.mockResolvedValueOnce({ data: rows, error: null });
    await expect(store.readPublicStates('opportunities', ['job-one']))
      .resolves.toEqual({ ok: true, states: rows });
    rpc.mockResolvedValueOnce({ data: [{ ...rows[0], owner_entity_id: ACTOR }], error: null });
    await expect(store.readPublicStates('opportunities', ['job-one']))
      .resolves.toMatchObject({ ok: false, code: 'store_invalid' });
  });

  it('rejects malformed selection and notification projections', async () => {
    const store = createSupabaseWorksWorkflowStore();
    rpc.mockResolvedValueOnce({ data: { ok: true, replayed: false, resource: assignment({
      delivery: { url: 'http://example.com', summary: 'unsafe', submitted_at: '2026-09-07T22:00:00Z' },
    }) }, error: null });
    await expect(store.selectProposal(ACTOR, {
      proposal_id: 'proposal-one', expected_revision: 0, idempotency_key: IDEM,
      scope: 'Work', acceptance_criteria: ['Pass'], terms: 'External',
    })).resolves.toMatchObject({ ok: false, code: 'store_invalid' });

    await expect(store.markNotificationRead(ACTOR, 'not-a-uuid', {
      expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'not_found' });
    rpc.mockResolvedValueOnce({ data: { ok: true, replayed: false, resource: {
      notification_id: '33333333-3333-4333-8333-333333333333', read_at: null, revision: 1,
    } }, error: null });
    await expect(store.markNotificationRead(ACTOR, '33333333-3333-4333-8333-333333333333', {
      expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'store_invalid' });
  });

  it('validates every nested private-workspace collection before returning it', async () => {
    const malformed = [
      workspace({ profiles: [null] }),
      workspace({ listings: [{ record: {}, workflow: null }] }),
      workspace({ received_proposals: [{ job: null, record: {}, workflow: {
        state: 'submitted', revision: 0, updated_at: null,
      } }] }),
      workspace({ assignments: [{ viewer_role: 'admin', assignment: assignment() }] }),
      workspace({ notifications: [{
        notification_id: '33333333-3333-4333-8333-333333333333', kind: 'proposal_received',
        resource_type: 'proposal', resource_id: '../private', created_at: '2026-09-07T22:00:00Z',
        read_at: null, revision: 0,
      }] }),
    ];
    const store = createSupabaseWorksWorkflowStore();
    for (const projection of malformed) {
      rpc.mockResolvedValueOnce({ data: projection, error: null });
      await expect(store.readWorkspace(ACTOR)).resolves.toMatchObject({ ok: false, code: 'store_invalid' });
    }
  });

  it('propagates sanitized RPC failures across every workflow operation', async () => {
    const store = createSupabaseWorksWorkflowStore();
    const databaseError = { data: null, error: { code: 'EW403', message: 'private row detail' } };
    rpc.mockResolvedValue(databaseError);
    await expect(store.readAssignment(ACTOR, 'assignment-one'))
      .resolves.toMatchObject({ ok: false, code: 'forbidden' });
    await expect(store.commandRecord(ACTOR, {
      command: 'close_job', record_id: 'job-one', expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'forbidden' });
    await expect(store.selectProposal(ACTOR, {
      proposal_id: 'proposal-one', expected_revision: 0, idempotency_key: IDEM,
      scope: 'Work', acceptance_criteria: ['Pass'], terms: 'External',
    })).resolves.toMatchObject({ ok: false, code: 'forbidden' });
    await expect(store.commandAssignment(ACTOR, 'assignment-one', {
      command: 'builder_confirm', expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'forbidden' });
    await expect(store.markNotificationRead(ACTOR, '33333333-3333-4333-8333-333333333333', {
      expected_revision: 0, idempotency_key: IDEM,
    })).resolves.toMatchObject({ ok: false, code: 'forbidden' });
    await expect(store.readPublicStates('opportunities', ['job-one']))
      .resolves.toMatchObject({ ok: false, code: 'forbidden' });
  });

  it('exposes the public-state convenience function through the guarded adapter', async () => {
    const rows = [{ record_id: 'job-one', workflow: { state: 'open', revision: 0, updated_at: null } }];
    rpc.mockResolvedValueOnce({ data: rows, error: null });
    await expect(getWorksPublicWorkflowStates('opportunities', ['job-one']))
      .resolves.toEqual({ ok: true, states: rows });
  });
});
