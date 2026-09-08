// SPDX-License-Identifier: Apache-2.0

import type { SupabaseClient } from '@supabase/supabase-js';
import { getServiceClient } from '../supabase.js';
import type {
  WorksAssignment,
  WorksAssignmentCommandInput,
  WorksNotificationReadInput,
  WorksSelectProposalInput,
  WorksWorkspaceCommandInput,
  WorksWorkspaceDto,
  WorksWriteResult,
} from './workflow-model.js';

type RpcClient = Pick<SupabaseClient, 'rpc'>;
export type WorksWorkflowError = { ok: false; code: string; detail: string };
type Result<T> = { ok: true } & T | WorksWorkflowError;
type PublicState = {
  record_id: string;
  workflow: { state: string; revision: number; updated_at: string | null };
};
type RecordCommandResource = {
  record_id: string;
  collection: 'listings' | 'opportunities' | 'submissions';
  workflow: { state: string; revision: number; updated_at: string | null };
};

const ENTITY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const WORKS_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PRIVATE_KEYS = new Set([
  'owner_entity_id', 'owner_tenant_id', 'buyer_entity_id', 'builder_entity_id', 'actor_entity_id',
  'idempotency_key', 'request_digest', 'email_claimed_until',
]);

function failure(code: string, detail: string): WorksWorkflowError {
  return { ok: false, code, detail };
}

function databaseFailure(error?: { code?: string } | null): WorksWorkflowError {
  switch (error?.code) {
    case 'EWREV': return failure('revision_conflict', 'The record changed. Refresh and retry.');
    case 'EWIDM': return failure('idempotency_conflict', 'The idempotency key is already bound to another command.');
    case 'EWTRN': return failure('invalid_transition', 'This command is not valid for the current state.');
    case 'EW403': return failure('forbidden', 'The authenticated account cannot perform this command.');
    case 'EW404': return failure('not_found', 'The workflow resource was not found.');
    case '22023': return failure('invalid_command', 'The workflow command is invalid.');
    default: return failure('store_unavailable', 'Works workflow storage is unavailable.');
  }
}

function object(value: unknown): value is Record<string, any> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function containsPrivateKey(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value as object)) return false;
  seen.add(value as object);
  if (Array.isArray(value)) return value.some((item) => containsPrivateKey(item, seen));
  return Object.entries(value as Record<string, unknown>)
    .some(([key, nested]) => PRIVATE_KEYS.has(key) || containsPrivateKey(nested, seen));
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value));
}

function secureHttps(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 600 || /[\s\\]/.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname.length > 0
      && !url.username && !url.password;
  } catch {
    return false;
  }
}

function workflow(value: unknown): boolean {
  return object(value)
    && typeof value.state === 'string'
    && Number.isSafeInteger(value.revision) && value.revision >= 0
    && (value.updated_at === null || timestamp(value.updated_at));
}

function assignment(value: unknown): value is WorksAssignment {
  if (!object(value) || !WORKS_ID.test(value.assignment_id || '')
    || !WORKS_ID.test(value.job_id || '') || !WORKS_ID.test(value.proposal_id || '')
    || !WORKS_ID.test(value.builder_id || '')
    || (value.listing_id !== null && !WORKS_ID.test(value.listing_id || ''))
    || !['proposed', 'confirmed', 'declined', 'delivery_submitted',
      'changes_requested', 'completed', 'cancelled'].includes(value.state)
    || !Number.isSafeInteger(value.revision) || value.revision < 0
    || typeof value.scope !== 'string' || typeof value.terms !== 'string'
    || !Array.isArray(value.acceptance_criteria)
    || !value.acceptance_criteria.every((item: unknown) => typeof item === 'string')
    || !object(value.frozen) || !object(value.frozen.job) || !object(value.frozen.proposal)
    || (value.delivery !== null && (!object(value.delivery) || !secureHttps(value.delivery.url)
      || typeof value.delivery.summary !== 'string' || !timestamp(value.delivery.submitted_at)))
    || (value.outcome !== null && (!object(value.outcome) || !timestamp(value.outcome.accepted_at)
      || (value.outcome.summary !== null && typeof value.outcome.summary !== 'string')))
    || !Array.isArray(value.history) || value.history.length === 0
    || !timestamp(value.created_at) || !timestamp(value.updated_at)) return false;
  let previousRevision = -1;
  const validHistory = value.history.every((event: unknown) => {
    if (!object(event) || !['buyer', 'builder'].includes(event.actor_role)
      || typeof event.command !== 'string'
      || !Number.isSafeInteger(event.revision) || event.revision <= previousRevision
      || event.revision > value.revision
      || !timestamp(event.at)
      || (event.summary !== null && typeof event.summary !== 'string')
      || (event.reason !== null && typeof event.reason !== 'string')
      || (event.delivery !== null && (!object(event.delivery) || !secureHttps(event.delivery.url)
        || typeof event.delivery.summary !== 'string' || !timestamp(event.delivery.submitted_at)))) return false;
    previousRevision = event.revision;
    return true;
  });
  return validHistory && previousRevision === value.revision;
}

function writeResult<T>(value: unknown, resource: (candidate: unknown) => candidate is T): value is WorksWriteResult<T> {
  return object(value) && value.ok === true && typeof value.replayed === 'boolean' && resource(value.resource);
}

function recordCommandResource(value: unknown): value is RecordCommandResource {
  return object(value) && WORKS_ID.test(value.record_id || '')
    && ['listings', 'opportunities', 'submissions'].includes(value.collection)
    && workflow(value.workflow);
}

function notificationReadResource(value: unknown): value is {
  notification_id: string; read_at: string; revision: number;
} {
  return object(value) && UUID.test(value.notification_id || '') && timestamp(value.read_at)
    && Number.isSafeInteger(value.revision) && value.revision > 0;
}

function workspace(value: unknown): value is WorksWorkspaceDto {
  if (!object(value) || containsPrivateKey(value) || !object(value.viewer)
    || (value.viewer.display_name !== null && typeof value.viewer.display_name !== 'string')
    || !['buyer', 'builder', 'both'].includes(value.viewer.role)
    || !Array.isArray(value.profiles) || !Array.isArray(value.listings) || !Array.isArray(value.jobs)
    || !Array.isArray(value.submitted_proposals) || !Array.isArray(value.received_proposals)
    || !Array.isArray(value.assignments) || !Array.isArray(value.notifications)) return false;
  if (!value.profiles.every(object)) return false;
  if (![...value.listings, ...value.jobs, ...value.submitted_proposals]
    .every((item: unknown) => object(item) && object(item.record) && workflow(item.workflow))) return false;
  if (!value.received_proposals.every((item: unknown) => object(item)
    && object(item.job) && object(item.record) && workflow(item.workflow))) return false;
  if (!value.assignments.every((item: unknown) => object(item)
    && ['buyer', 'builder'].includes(item.viewer_role) && assignment(item.assignment))) return false;
  return value.notifications.every((item: unknown) => object(item)
    && typeof item.notification_id === 'string' && typeof item.kind === 'string'
    && typeof item.resource_type === 'string' && WORKS_ID.test(item.resource_id || '')
    && timestamp(item.created_at) && (item.read_at === null || timestamp(item.read_at))
    && Number.isSafeInteger(item.revision) && item.revision >= 0);
}

async function call(client: RpcClient, name: string, args: Record<string, unknown>) {
  try {
    const response = await client.rpc(name, args);
    if (response?.error) return databaseFailure(response.error);
    return { ok: true as const, data: response?.data };
  } catch {
    return databaseFailure();
  }
}

export function createSupabaseWorksWorkflowStore(client?: RpcClient) {
  const resolvedClient = client ?? (process.env.WORKS_DATA_DIR ? null : getServiceClient());
  const run = (name: string, args: Record<string, unknown>) => resolvedClient
    ? call(resolvedClient, name, args)
    : Promise.resolve(failure(
      'store_unavailable',
      'Works workflow commands require the PostgreSQL workflow store.',
    ));
  return {
    async readWorkspace(actorEntityId: string): Promise<Result<{ workspace: WorksWorkspaceDto }>> {
      if (!ENTITY_ID.test(actorEntityId)) return failure('invalid_actor', 'A stable entity DB id is required.');
      const result = await run('read_works_workspace', { p_actor_entity_id: actorEntityId });
      if (!result.ok) return result;
      return workspace(result.data)
        ? { ok: true, workspace: result.data }
        : failure('store_invalid', 'Works workflow storage returned invalid data.');
    },

    async readAssignment(actorEntityId: string, assignmentId: string): Promise<Result<{
      assignment: WorksAssignment; viewer_role: 'buyer' | 'builder';
    }>> {
      if (!ENTITY_ID.test(actorEntityId) || !WORKS_ID.test(assignmentId)) {
        return failure('not_found', 'The workflow resource was not found.');
      }
      const result = await run('read_works_assignment', {
        p_actor_entity_id: actorEntityId, p_assignment_id: assignmentId,
      });
      if (!result.ok) return result;
      if (result.data === null) return failure('not_found', 'The workflow resource was not found.');
      if (!object(result.data) || containsPrivateKey(result.data)
        || !['buyer', 'builder'].includes(result.data.viewer_role) || !assignment(result.data.assignment)) {
        return failure('store_invalid', 'Works workflow storage returned invalid data.');
      }
      return { ok: true, assignment: result.data.assignment, viewer_role: result.data.viewer_role };
    },

    async commandRecord(actorEntityId: string, input: WorksWorkspaceCommandInput): Promise<Result<{
      result: WorksWriteResult<RecordCommandResource>;
    }>> {
      const rpc = await run('command_works_record', {
        p_actor_entity_id: actorEntityId, p_command: input.command, p_record_id: input.record_id,
        p_expected_revision: input.expected_revision, p_idempotency_key: input.idempotency_key,
      });
      if (!rpc.ok) return rpc;
      if (containsPrivateKey(rpc.data) || !writeResult(rpc.data, recordCommandResource)) {
        return failure('store_invalid', 'Works workflow storage returned invalid data.');
      }
      return { ok: true, result: rpc.data };
    },

    async selectProposal(actorEntityId: string, input: WorksSelectProposalInput): Promise<Result<{
      result: WorksWriteResult<WorksAssignment>;
    }>> {
      const rpc = await run('select_works_proposal', {
        p_actor_entity_id: actorEntityId, p_proposal_id: input.proposal_id,
        p_expected_revision: input.expected_revision, p_idempotency_key: input.idempotency_key,
        p_scope: input.scope, p_acceptance_criteria: input.acceptance_criteria, p_terms: input.terms,
      });
      if (!rpc.ok) return rpc;
      if (containsPrivateKey(rpc.data) || !writeResult(rpc.data, assignment)) {
        return failure('store_invalid', 'Works workflow storage returned invalid data.');
      }
      return { ok: true, result: rpc.data };
    },

    async commandAssignment(
      actorEntityId: string, assignmentId: string, input: WorksAssignmentCommandInput,
    ): Promise<Result<{ result: WorksWriteResult<WorksAssignment> }>> {
      const payload = {
        ...(input.delivery_url ? { delivery_url: input.delivery_url } : {}),
        ...(input.summary !== undefined ? { summary: input.summary } : {}),
        ...(input.reason ? { reason: input.reason } : {}),
      };
      const rpc = await run('command_works_assignment', {
        p_actor_entity_id: actorEntityId, p_assignment_id: assignmentId,
        p_command: input.command, p_expected_revision: input.expected_revision,
        p_idempotency_key: input.idempotency_key, p_payload: payload,
      });
      if (!rpc.ok) return rpc;
      if (containsPrivateKey(rpc.data) || !writeResult(rpc.data, assignment)) {
        return failure('store_invalid', 'Works workflow storage returned invalid data.');
      }
      return { ok: true, result: rpc.data };
    },

    async markNotificationRead(
      actorEntityId: string, notificationId: string, input: WorksNotificationReadInput,
    ): Promise<Result<{ result: WorksWriteResult<{
      notification_id: string; read_at: string; revision: number;
    }> }>> {
      if (!UUID.test(notificationId)) return failure('not_found', 'The notification was not found.');
      const rpc = await run('mark_works_notification_read', {
        p_actor_entity_id: actorEntityId, p_notification_id: notificationId,
        p_expected_revision: input.expected_revision, p_idempotency_key: input.idempotency_key,
      });
      if (!rpc.ok) return rpc;
      if (containsPrivateKey(rpc.data) || !writeResult(rpc.data, notificationReadResource)) {
        return failure('store_invalid', 'Works workflow storage returned invalid data.');
      }
      return { ok: true, result: rpc.data };
    },

    async readPublicStates(
      collection: 'listings' | 'opportunities', recordIds: string[],
    ): Promise<Result<{ states: PublicState[] }>> {
      if (recordIds.some((id) => !WORKS_ID.test(id))) return failure('invalid_id', 'Invalid Works id.');
      const rpc = await run('read_works_public_workflow_states', {
        p_collection: collection, p_record_ids: recordIds,
      });
      if (!rpc.ok) return rpc;
      if (!Array.isArray(rpc.data) || containsPrivateKey(rpc.data)
        || !rpc.data.every((item) => object(item) && WORKS_ID.test(item.record_id || '')
          && workflow(item.workflow))) {
        return failure('store_invalid', 'Works workflow storage returned invalid data.');
      }
      return { ok: true, states: rpc.data };
    },
  };
}

export async function getWorksPublicWorkflowStates(
  collection: 'listings' | 'opportunities', recordIds: string[],
) {
  return createSupabaseWorksWorkflowStore().readPublicStates(collection, recordIds);
}
