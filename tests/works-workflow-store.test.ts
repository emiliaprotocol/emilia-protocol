// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const database = vi.hoisted(() => ({ getServiceClient: vi.fn() }));
vi.mock('../lib/supabase.js', () => ({ getServiceClient: database.getServiceClient }));

import { createSupabaseWorksWorkflowStore } from '../lib/works/workflow-store.ts';

const ACTOR = '11111111-1111-4111-8111-111111111111';
const IDEM = 'works-command-0001';

function workspace(overrides: Record<string, unknown> = {}) {
  return {
    viewer: { display_name: 'Acme', role: 'buyer' }, profiles: [], listings: [], jobs: [],
    submitted_proposals: [], received_proposals: [], assignments: [], notifications: [],
    ...overrides,
  };
}

describe('Works workflow production adapter', () => {
  const rpc = vi.fn();

  beforeEach(() => {
    rpc.mockReset();
    database.getServiceClient.mockReturnValue({ rpc });
  });

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
});
