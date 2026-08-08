// SPDX-License-Identifier: Apache-2.0
/** Durable inbox and leased worker for GitHub deployment-protection deliveries. */
import crypto from 'node:crypto';

import {
  authenticateGitHubDeploymentWebhook,
  validateGitHubDeploymentWebhookAuthenticationConfig,
} from './github-deployment-webhook.js';

type JsonObject = Record<string, any>;
type TerminalState = 'APPROVED' | 'REFUSED' | 'INDETERMINATE';
type QueueState = 'QUEUED' | 'PROCESSING' | TerminalState;

interface QueueRecord {
  tenant_id: string;
  delivery_id: string;
  request_digest: string;
  body: Buffer;
  headers: Record<string, string>;
  state: QueueState;
  attempt_count: number;
  available_at?: number;
  lease_owner?: string | null;
  lease_token?: string | null;
  lease_expires_at?: number | null;
  reason?: string | null;
  result?: JsonObject | null;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TERMINAL = new Set<TerminalState>(['APPROVED', 'REFUSED', 'INDETERMINATE']);

const ENQUEUE_SQL = `
  SELECT outcome, delivery
  FROM consequence_actuator_private.enqueue_github_deployment_delivery(
    $1::text, $2::text, $3::text, $4::bytea, $5::jsonb
  )
`;
const CLAIM_SQL = `
  SELECT delivery
  FROM consequence_actuator_private.claim_github_deployment_delivery(
    $1::text, $2::text, $3::text, $4::bigint
  )
`;
const COMPLETE_SQL = `
  SELECT delivery
  FROM consequence_actuator_private.complete_github_deployment_delivery(
    $1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::jsonb
  )
`;
const RETRY_SQL = `
  SELECT delivery
  FROM consequence_actuator_private.retry_github_deployment_delivery(
    $1::text, $2::text, $3::text, $4::text, $5::text, $6::bigint
  )
`;
const READ_SQL = `
  SELECT delivery
  FROM consequence_actuator_private.read_github_deployment_delivery(
    $1::text, $2::text
  )
`;

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function identifier(value: unknown, name: string): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new TypeError(`${name}_invalid`);
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== 'string' || !DIGEST.test(value)) throw new TypeError('request_digest_invalid');
  return value;
}

function copy(record: QueueRecord): QueueRecord {
  return {
    ...structuredClone(record),
    body: Buffer.from(record.body),
  };
}

function normalizeDatabaseRecord(value: unknown): QueueRecord {
  if (!plainObject(value)
      || typeof value.tenant_id !== 'string'
      || typeof value.delivery_id !== 'string'
      || typeof value.request_digest !== 'string'
      || typeof value.state !== 'string') {
    throw new Error('github_delivery_record_ambiguous');
  }
  const body = Buffer.isBuffer(value.body)
    ? Buffer.from(value.body)
    : typeof value.body === 'string' ? Buffer.from(value.body, 'base64') : null;
  if (!body || !plainObject(value.headers)) throw new Error('github_delivery_record_ambiguous');
  return { ...structuredClone(value), body } as QueueRecord;
}

export function createMemoryGitHubDeploymentDeliveryQueue({
  now = () => Date.now(),
}: { now?: () => number } = {}) {
  const records = new Map<string, QueueRecord>();
  const key = (tenant: string, delivery: string) => `${tenant}\0${delivery}`;
  return Object.freeze({
    durable: false,
    async enqueue(input: any) {
      const tenantId = identifier(input?.tenant_id, 'tenant_id');
      const deliveryId = identifier(input?.delivery_id, 'delivery_id');
      const requestDigest = digest(input?.request_digest);
      if (!Buffer.isBuffer(input?.body) || !plainObject(input?.headers)) {
        throw new TypeError('github_delivery_input_invalid');
      }
      const recordKey = key(tenantId, deliveryId);
      const existing = records.get(recordKey);
      if (existing) {
        if (existing.request_digest !== requestDigest) return { ok: false, reason: 'delivery_id_conflict' };
        return { ok: true, duplicate: true, record: copy(existing) };
      }
      const record: QueueRecord = {
        tenant_id: tenantId,
        delivery_id: deliveryId,
        request_digest: requestDigest,
        body: Buffer.from(input.body),
        headers: structuredClone(input.headers),
        state: 'QUEUED',
        attempt_count: 0,
        available_at: now(),
        lease_owner: null,
        lease_token: null,
        lease_expires_at: null,
        reason: null,
        result: null,
      };
      records.set(recordKey, record);
      return { ok: true, duplicate: false, record: copy(record) };
    },
    async claimNext(input: any) {
      const tenantId = identifier(input?.tenant_id, 'tenant_id');
      const leaseOwner = identifier(input?.lease_owner, 'lease_owner');
      const leaseToken = identifier(input?.lease_token, 'lease_token');
      const leaseMs = input?.lease_ms;
      if (!Number.isSafeInteger(leaseMs) || leaseMs < 100 || leaseMs > 300_000) {
        throw new TypeError('lease_ms_invalid');
      }
      const timestamp = now();
      const candidate = [...records.values()]
        .filter((record) => record.tenant_id === tenantId
          && (record.state === 'QUEUED'
            ? Number(record.available_at ?? 0) <= timestamp
            : record.state === 'PROCESSING' && Number(record.lease_expires_at ?? 0) <= timestamp))
        .sort((left, right) => Number(left.available_at ?? 0) - Number(right.available_at ?? 0))[0];
      if (!candidate) return { ok: true, empty: true, record: null };
      candidate.state = 'PROCESSING';
      candidate.attempt_count += 1;
      candidate.lease_owner = leaseOwner;
      candidate.lease_token = leaseToken;
      candidate.lease_expires_at = timestamp + leaseMs;
      return { ok: true, empty: false, record: copy(candidate) };
    },
    async complete(input: any) {
      const record = records.get(key(identifier(input?.tenant_id, 'tenant_id'), identifier(input?.delivery_id, 'delivery_id')));
      const state = input?.state as TerminalState;
      if (!record || record.request_digest !== digest(input?.request_digest)
          || record.state !== 'PROCESSING' || record.lease_token !== input?.lease_token
          || !TERMINAL.has(state)) {
        return { ok: false, reason: 'delivery_lease_conflict' };
      }
      record.state = state;
      record.reason = typeof input.reason === 'string' ? input.reason : null;
      record.result = plainObject(input.result) ? structuredClone(input.result) : null;
      record.lease_owner = null;
      record.lease_token = null;
      record.lease_expires_at = null;
      return { ok: true, record: copy(record) };
    },
    async retry(input: any) {
      const record = records.get(key(identifier(input?.tenant_id, 'tenant_id'), identifier(input?.delivery_id, 'delivery_id')));
      const delayMs = input?.delay_ms;
      if (!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 3_600_000) throw new TypeError('retry_delay_invalid');
      if (!record || record.request_digest !== digest(input?.request_digest)
          || record.state !== 'PROCESSING' || record.lease_token !== input?.lease_token) {
        return { ok: false, reason: 'delivery_lease_conflict' };
      }
      record.state = 'QUEUED';
      record.available_at = now() + delayMs;
      record.reason = typeof input.reason === 'string' ? input.reason : 'retryable_unavailable';
      record.lease_owner = null;
      record.lease_token = null;
      record.lease_expires_at = null;
      return { ok: true, record: copy(record) };
    },
    async read(input: any) {
      const record = records.get(key(identifier(input?.tenant_id, 'tenant_id'), identifier(input?.delivery_id, 'delivery_id')));
      return record ? copy(record) : null;
    },
  });
}

export function createPostgresGitHubDeploymentDeliveryQueue(query: (
  text: string,
  values: readonly unknown[],
) => Promise<any>) {
  if (typeof query !== 'function') throw new TypeError('github_delivery_query_required');
  const one = (result: any, name: string) => {
    if (result?.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
      throw new Error(`${name}_acknowledgement_ambiguous`);
    }
    return result.rows[0];
  };
  return Object.freeze({
    durable: true,
    async enqueue(input: any) {
      const row = one(await query(ENQUEUE_SQL, [
        input.tenant_id, input.delivery_id, input.request_digest, input.body, JSON.stringify(input.headers),
      ]), 'github_delivery_enqueue');
      if (row.outcome === 'CONFLICT') return { ok: false, reason: 'delivery_id_conflict' };
      if (!['ENQUEUED', 'DUPLICATE'].includes(row.outcome)) throw new Error('github_delivery_enqueue_acknowledgement_ambiguous');
      return { ok: true, duplicate: row.outcome === 'DUPLICATE', record: normalizeDatabaseRecord(row.delivery) };
    },
    async claimNext(input: any) {
      const result = await query(CLAIM_SQL, [input.tenant_id, input.lease_owner, input.lease_token, input.lease_ms]);
      if (result?.rowCount === 0 && Array.isArray(result.rows) && result.rows.length === 0) return { ok: true, empty: true, record: null };
      return { ok: true, empty: false, record: normalizeDatabaseRecord(one(result, 'github_delivery_claim').delivery) };
    },
    async complete(input: any) {
      const result = await query(COMPLETE_SQL, [
        input.tenant_id, input.delivery_id, input.request_digest, input.lease_token,
        input.state, input.reason, input.result === null ? null : JSON.stringify(input.result),
      ]);
      if (result?.rowCount === 0 && Array.isArray(result.rows) && result.rows.length === 0) return { ok: false, reason: 'delivery_lease_conflict' };
      return { ok: true, record: normalizeDatabaseRecord(one(result, 'github_delivery_complete').delivery) };
    },
    async retry(input: any) {
      const result = await query(RETRY_SQL, [
        input.tenant_id, input.delivery_id, input.request_digest, input.lease_token, input.reason, input.delay_ms,
      ]);
      if (result?.rowCount === 0 && Array.isArray(result.rows) && result.rows.length === 0) return { ok: false, reason: 'delivery_lease_conflict' };
      return { ok: true, record: normalizeDatabaseRecord(one(result, 'github_delivery_retry').delivery) };
    },
    async read(input: any) {
      const result = await query(READ_SQL, [input.tenant_id, input.delivery_id]);
      if (result?.rowCount === 0 && Array.isArray(result.rows) && result.rows.length === 0) return null;
      return normalizeDatabaseRecord(one(result, 'github_delivery_read').delivery);
    },
  });
}

export function createGitHubDeploymentWebhookInbox({
  tenantId,
  queue,
  allowEphemeralQueue = false,
  ...authentication
}: any = {}) {
  identifier(tenantId, 'tenant_id');
  if (!queue || typeof queue.enqueue !== 'function'
      || (queue.durable !== true && allowEphemeralQueue !== true)) {
    throw new TypeError('github_deployment_durable_queue_required');
  }
  const authenticationConfig = validateGitHubDeploymentWebhookAuthenticationConfig(authentication);
  return Object.freeze({
    async handle(input: { headers?: unknown; body?: unknown } = {}) {
      try {
        const authenticated = authenticateGitHubDeploymentWebhook(input, authenticationConfig);
        const enqueued = await queue.enqueue({
          tenant_id: tenantId,
          delivery_id: authenticated.delivery_id,
          request_digest: authenticated.request_digest,
          body: authenticated.body,
          headers: authenticated.headers,
        });
        if (!enqueued?.ok) {
          return { ok: false, status: 409, state: 'REFUSED', reason: enqueued?.reason ?? 'delivery_enqueue_refused' };
        }
        return {
          ok: true,
          status: 202,
          state: enqueued.record.state,
          delivery_id: authenticated.delivery_id,
          ...(enqueued.duplicate ? { duplicate: true } : {}),
        };
      } catch (error: any) {
        const status = Number.isSafeInteger(error?.status) ? error.status : 500;
        return {
          ok: false,
          status,
          state: status >= 500 ? 'INDETERMINATE' : 'REFUSED',
          reason: status >= 500 ? 'delivery_enqueue_indeterminate' : String(error?.message ?? 'webhook_refused'),
        };
      }
    },
  });
}

export function createGitHubDeploymentDeliveryWorker({
  tenantId,
  queue,
  process,
  leaseOwner,
  leaseMs = 30_000,
  retryDelayMs = 1_000,
  maxAttempts = 8,
  allowEphemeralQueue = false,
}: any = {}) {
  identifier(tenantId, 'tenant_id');
  identifier(leaseOwner, 'lease_owner');
  if (!queue || typeof queue.claimNext !== 'function' || typeof queue.complete !== 'function'
      || typeof queue.retry !== 'function'
      || (queue.durable !== true && allowEphemeralQueue !== true)
      || typeof process !== 'function'
      || !Number.isSafeInteger(leaseMs) || leaseMs < 100 || leaseMs > 300_000
      || !Number.isSafeInteger(retryDelayMs) || retryDelayMs < 0 || retryDelayMs > 3_600_000
      || !Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 100) {
    throw new TypeError('github_deployment_worker_config_invalid');
  }
  return Object.freeze({
    async runOnce() {
      const leaseToken = crypto.randomUUID();
      const claimed = await queue.claimNext({
        tenant_id: tenantId,
        lease_owner: leaseOwner,
        lease_token: leaseToken,
        lease_ms: leaseMs,
      });
      if (!claimed?.ok) return { processed: false, state: 'INDETERMINATE', reason: 'delivery_claim_indeterminate' };
      if (claimed.empty) return { processed: false, empty: true };
      const record = claimed.record;
      let outcome: any;
      try {
        outcome = await process(copy(record));
      } catch {
        outcome = { ok: false, status: 500, state: 'INDETERMINATE', reason: 'delivery_processing_indeterminate' };
      }
      if (outcome?.state === 'UNAVAILABLE' && record.attempt_count < maxAttempts) {
        const retried = await queue.retry({
          tenant_id: tenantId,
          delivery_id: record.delivery_id,
          request_digest: record.request_digest,
          lease_token: leaseToken,
          reason: typeof outcome.reason === 'string' ? outcome.reason : 'retryable_unavailable',
          delay_ms: retryDelayMs,
        });
        return retried?.ok
          ? { processed: true, requeued: true, state: 'QUEUED' }
          : { processed: true, state: 'INDETERMINATE', reason: 'delivery_retry_indeterminate' };
      }
      const state: TerminalState = TERMINAL.has(outcome?.state)
        ? outcome.state
        : 'INDETERMINATE';
      const completed = await queue.complete({
        tenant_id: tenantId,
        delivery_id: record.delivery_id,
        request_digest: record.request_digest,
        lease_token: leaseToken,
        state,
        reason: typeof outcome?.reason === 'string' ? outcome.reason : null,
        result: plainObject(outcome?.result) ? outcome.result : null,
      });
      return completed?.ok
        ? { processed: true, state }
        : { processed: true, state: 'INDETERMINATE', reason: 'delivery_completion_indeterminate' };
    },
  });
}

export default Object.freeze({
  createMemoryGitHubDeploymentDeliveryQueue,
  createPostgresGitHubDeploymentDeliveryQueue,
  createGitHubDeploymentWebhookInbox,
  createGitHubDeploymentDeliveryWorker,
});
