// SPDX-License-Identifier: Apache-2.0
/**
 * Authenticated GitHub deployment-protection webhook front end.
 *
 * This module authenticates GitHub's raw delivery, pins the installation and
 * repository, validates the callback target, re-reads the workflow run, and
 * hands one immutable action to the EMILIA allowance adapter.  It does not
 * treat repository-controlled workflow files as authority.
 */
import crypto from 'node:crypto';

import {
  createGithubDeploymentProtectionConnector,
  guardGithubDeploymentProtectionRule,
} from '@emilia-protocol/gate/adapters/github';
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';

const JSON_CONTENT_TYPE = /^application\/json(?:\s*;|$)/i;
const DELIVERY_ID = /^[A-Za-z0-9][A-Za-z0-9-]{15,127}$/;
const SHA256_SIGNATURE = /^sha256=([a-f0-9]{64})$/;
const SHA = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
const SAFE_REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const SAFE_ENVIRONMENT = /^[A-Za-z0-9_.:/-]{1,255}$/;
const SAFE_EVENT = /^[A-Za-z0-9_.:-]{1,100}$/;
const SAFE_REF = /^refs\/(?:heads|tags)\/[A-Za-z0-9._/-]{1,240}$/;
const WORKFLOW_PATH = /^\.github\/workflows\/([A-Za-z0-9_.-]{1,200})$/;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

type JsonObject = Record<string, any>;
type DeliveryState =
  | 'PROCESSING'
  | 'APPROVED'
  | 'REFUSED'
  | 'INDETERMINATE'
  | 'UNAVAILABLE';

interface DeliveryRecord {
  delivery_id: string;
  request_digest: string;
  state: DeliveryState;
  reason: string | null;
  result: JsonObject | null;
}

class WebhookInputError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function header(headers: unknown, name: string): string | null {
  if (!headers || typeof headers !== 'object') return null;
  const source = headers as Record<string, unknown>;
  const value = source[name] ?? source[name.toLowerCase()] ?? source[name.toUpperCase()];
  return typeof value === 'string' && !/[\r\n]/.test(value) ? value : null;
}

function requestDigest(bytes: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function verifySignature(bytes: Buffer, supplied: string | null, secret: string): boolean {
  const match = typeof supplied === 'string' ? SHA256_SIGNATURE.exec(supplied) : null;
  if (!match) return false;
  const expected = crypto.createHmac('sha256', secret).update(bytes).digest();
  const actual = Buffer.from(match[1], 'hex');
  return actual.byteLength === expected.byteLength && crypto.timingSafeEqual(actual, expected);
}

function strictJson(bytes: Buffer): JsonObject {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new WebhookInputError(400, 'webhook_utf8_invalid');
  }
  if (!strictJsonGate(text).ok) throw new WebhookInputError(400, 'webhook_json_invalid');
  const parsed = JSON.parse(text);
  if (!plainObject(parsed)) throw new WebhookInputError(400, 'webhook_object_required');
  return parsed;
}

function callbackRunId(value: unknown, owner: string, repo: string): number {
  let url: URL;
  try {
    url = new URL(String(value));
  } catch {
    throw new WebhookInputError(400, 'deployment_callback_url_invalid');
  }
  if (url.protocol !== 'https:'
      || url.hostname !== 'api.github.com'
      || url.port
      || url.username
      || url.password
      || url.search
      || url.hash
      || url.pathname.includes('%')) {
    throw new WebhookInputError(400, 'deployment_callback_url_invalid');
  }
  const escapedOwner = owner.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const escapedRepo = repo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(
    `^/repos/${escapedOwner}/${escapedRepo}/actions/runs/([1-9][0-9]*)/deployment_protection_rule$`,
  ).exec(url.pathname);
  const runId = match ? Number(match[1]) : NaN;
  if (!Number.isSafeInteger(runId)) {
    throw new WebhookInputError(400, 'deployment_callback_url_invalid');
  }
  return runId;
}

function normalizePayload(payload: JsonObject) {
  const repository = payload.repository;
  const owner = repository?.owner?.login;
  const repo = repository?.name;
  const fullName = repository?.full_name;
  if (payload.action !== 'requested'
      || typeof owner !== 'string'
      || typeof repo !== 'string'
      || fullName !== `${owner}/${repo}`
      || !SAFE_REPOSITORY.test(fullName)
      || !positiveInteger(repository?.id)
      || !positiveInteger(payload.installation?.id)
      || typeof payload.environment !== 'string'
      || !SAFE_ENVIRONMENT.test(payload.environment)
      || typeof payload.event !== 'string'
      || !SAFE_EVENT.test(payload.event)
      || typeof payload.sha !== 'string'
      || !SHA.test(payload.sha)
      || typeof payload.ref !== 'string'
      || !SAFE_REF.test(payload.ref)) {
    throw new WebhookInputError(400, 'deployment_payload_invalid');
  }
  const runId = callbackRunId(payload.deployment_callback_url, owner, repo);
  return Object.freeze({
    installation_id: payload.installation.id as number,
    repository_id: repository.id as number,
    repository: fullName as string,
    owner,
    repo,
    environment: payload.environment as string,
    event: payload.event as string,
    sha: payload.sha as string,
    ref: payload.ref as string,
    run_id: runId,
  });
}

function normalizeRun(value: unknown, expected: ReturnType<typeof normalizePayload>) {
  if (!plainObject(value)) throw new Error('workflow_run_invalid');
  const rawPath = typeof value.path === 'string' ? value.path.split('@', 1)[0] : '';
  const workflowMatch = WORKFLOW_PATH.exec(rawPath);
  const refName = expected.ref.replace(/^refs\/(?:heads|tags)\//, '');
  if (value.id !== expected.run_id
      || value.head_sha !== expected.sha
      || value.event !== expected.event
      || value.head_branch !== refName
      || value.repository?.id !== expected.repository_id
      || value.repository?.full_name !== expected.repository
      || !workflowMatch) {
    return null;
  }
  return Object.freeze({
    workflow: workflowMatch[1],
  });
}

function publicResult(record: DeliveryRecord, duplicate = false) {
  const ok = record.state === 'APPROVED';
  const status = record.state === 'UNAVAILABLE' ? 503 : record.state === 'PROCESSING' ? 202 : 200;
  return {
    ok,
    status,
    state: record.state,
    ...(record.reason ? { reason: record.reason } : {}),
    ...(duplicate ? { duplicate: true } : {}),
  };
}

export function createMemoryGitHubWebhookDeliveryStore() {
  const records = new Map<string, DeliveryRecord>();
  return Object.freeze({
    durable: false,
    async claim({ delivery_id, request_digest }: { delivery_id: string; request_digest: string }) {
      const existing = records.get(delivery_id);
      if (existing && existing.request_digest !== request_digest) {
        return { ok: false, reason: 'delivery_id_conflict' };
      }
      if (existing && existing.state !== 'UNAVAILABLE') {
        return { ok: true, duplicate: true, record: structuredClone(existing) };
      }
      const record: DeliveryRecord = {
        delivery_id,
        request_digest,
        state: 'PROCESSING',
        reason: null,
        result: null,
      };
      records.set(delivery_id, record);
      return { ok: true, duplicate: false, record: structuredClone(record) };
    },
    async complete({ delivery_id, request_digest, state, reason = null, result = null }: any) {
      const current = records.get(delivery_id);
      if (!current || current.request_digest !== request_digest) {
        return { ok: false, reason: 'delivery_not_claimed' };
      }
      if (current.state !== 'PROCESSING') {
        return current.state === state
          ? { ok: true, idempotent: true, record: structuredClone(current) }
          : { ok: false, reason: 'delivery_state_conflict' };
      }
      const record: DeliveryRecord = {
        ...current,
        state,
        reason,
        result: result === null ? null : structuredClone(result),
      };
      records.set(delivery_id, record);
      return { ok: true, idempotent: false, record: structuredClone(record) };
    },
    async read(delivery_id: string) {
      const record = records.get(delivery_id);
      return record ? structuredClone(record) : null;
    },
  });
}

function uncertainAdmission(reason: unknown): boolean {
  return typeof reason === 'string' && (
    reason.includes('indeterminate')
    || reason.includes('already_committed')
    || reason.includes('already_in_progress')
    || reason.includes('action_in_progress')
  );
}

export function createGitHubDeploymentWebhookGate({
  webhookSecret,
  expectedInstallationId,
  expectedRepositoryId,
  expectedRepository,
  deliveryStore,
  inspectRun,
  admitDeployment,
  allowEphemeralStore = false,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
}: any = {}) {
  if (typeof webhookSecret !== 'string' || webhookSecret.length < 16
      || !positiveInteger(expectedInstallationId)
      || !positiveInteger(expectedRepositoryId)
      || typeof expectedRepository !== 'string'
      || !SAFE_REPOSITORY.test(expectedRepository)
      || !deliveryStore || typeof deliveryStore.claim !== 'function'
      || typeof deliveryStore.complete !== 'function'
      || (deliveryStore.durable !== true && allowEphemeralStore !== true)
      || typeof inspectRun !== 'function'
      || typeof admitDeployment !== 'function'
      || !Number.isSafeInteger(maxBodyBytes)
      || maxBodyBytes < 1024
      || maxBodyBytes > 25 * 1024 * 1024) {
    throw new TypeError('github_deployment_webhook_config_invalid');
  }

  async function finish(
    deliveryId: string,
    digest: string,
    state: DeliveryState,
    reason: string | null,
    result: JsonObject | null = null,
  ) {
    const completed = await deliveryStore.complete({
      delivery_id: deliveryId,
      request_digest: digest,
      state,
      reason,
      result,
    });
    if (!completed?.ok) {
      return { ok: false, status: 503, state: 'INDETERMINATE', reason: 'delivery_state_indeterminate' };
    }
    return publicResult(completed.record);
  }

  return Object.freeze({
    async handle(input: { headers?: unknown; body?: unknown } = {}) {
      try {
        const bytes = Buffer.isBuffer(input.body)
          ? input.body
          : input.body instanceof Uint8Array ? Buffer.from(input.body) : null;
        if (!bytes || bytes.byteLength === 0 || bytes.byteLength > maxBodyBytes) {
          throw new WebhookInputError(bytes && bytes.byteLength > maxBodyBytes ? 413 : 400, 'webhook_body_invalid');
        }
        if (!JSON_CONTENT_TYPE.test(header(input.headers, 'content-type') ?? '')) {
          throw new WebhookInputError(415, 'application_json_required');
        }
        if (header(input.headers, 'x-github-event') !== 'deployment_protection_rule') {
          throw new WebhookInputError(400, 'github_event_invalid');
        }
        const deliveryId = header(input.headers, 'x-github-delivery');
        if (!deliveryId || !DELIVERY_ID.test(deliveryId)) {
          throw new WebhookInputError(400, 'github_delivery_id_invalid');
        }
        if (!String(header(input.headers, 'user-agent') ?? '').startsWith('GitHub-Hookshot/')) {
          throw new WebhookInputError(400, 'github_user_agent_invalid');
        }
        if (!verifySignature(bytes, header(input.headers, 'x-hub-signature-256'), webhookSecret)) {
          throw new WebhookInputError(401, 'webhook_signature_invalid');
        }
        const payload = normalizePayload(strictJson(bytes));
        if (payload.installation_id !== expectedInstallationId
            || payload.repository_id !== expectedRepositoryId
            || payload.repository !== expectedRepository) {
          throw new WebhookInputError(403, 'github_target_not_allowed');
        }
        const digest = requestDigest(bytes);
        const claim = await deliveryStore.claim({ delivery_id: deliveryId, request_digest: digest });
        if (!claim?.ok) {
          return { ok: false, status: 409, state: 'REFUSED', reason: claim?.reason || 'delivery_claim_refused' };
        }
        if (claim.duplicate) return publicResult(claim.record, true);

        let observedRun;
        try {
          observedRun = await inspectRun({
            installation_id: payload.installation_id,
            owner: payload.owner,
            repo: payload.repo,
            repository_id: payload.repository_id,
            run_id: payload.run_id,
          });
        } catch {
          return finish(deliveryId, digest, 'UNAVAILABLE', 'workflow_run_unavailable');
        }
        const run = normalizeRun(observedRun, payload);
        if (!run) {
          return finish(deliveryId, digest, 'REFUSED', 'workflow_run_binding_mismatch');
        }

        const operationId = `github:environment:${payload.repository_id}:${payload.run_id}:${payload.environment}`;
        const params = Object.freeze({
          owner: payload.owner,
          repo: payload.repo,
          repositoryId: payload.repository_id,
          environment: payload.environment,
          workflow: run.workflow,
          ref: payload.ref,
          sha: payload.sha,
          event: payload.event,
          runId: payload.run_id,
        });
        let admission;
        try {
          admission = await admitDeployment({ params, operation_id: operationId });
        } catch {
          return finish(deliveryId, digest, 'INDETERMINATE', 'admission_outcome_indeterminate');
        }
        if (admission?.ok === true) {
          return finish(deliveryId, digest, 'APPROVED', null, admission);
        }
        const reason = typeof admission?.reason === 'string' ? admission.reason : 'deployment_not_authorized';
        if (uncertainAdmission(reason)) {
          return finish(deliveryId, digest, 'INDETERMINATE', reason, admission ?? null);
        }
        return finish(deliveryId, digest, 'REFUSED', reason, admission ?? null);
      } catch (error) {
        if (error instanceof WebhookInputError) {
          return { ok: false, status: error.status, state: 'REFUSED', reason: error.message };
        }
        return { ok: false, status: 500, state: 'INDETERMINATE', reason: 'webhook_internal_error' };
      }
    },
  });
}

/**
 * Build the provider functions consumed by the webhook gate from one
 * installation-authenticated Octokit client and one server-owned allowance
 * context.  The allowance context contains the signed allowance, capability,
 * currentness verifier, trusted keys, and durable capability store; none is
 * read from the protected repository.
 */
export async function createGitHubDeploymentProtectionProvider({
  octokit,
  allowanceOptions,
}: any = {}): Promise<{
  inspectRun(input: JsonObject): Promise<JsonObject>;
  admitDeployment(input: JsonObject): Promise<JsonObject>;
}> {
  if (typeof octokit?.request !== 'function'
      || !allowanceOptions
      || typeof allowanceOptions !== 'object'
      || Array.isArray(allowanceOptions)) {
    throw new TypeError('github_deployment_provider_config_invalid');
  }
  const connector = await createGithubDeploymentProtectionConnector({ octokit });
  return Object.freeze({
    async inspectRun({ owner, repo, run_id }: any) {
      const response = await octokit.request(
        'GET /repos/{owner}/{repo}/actions/runs/{run_id}',
        { owner, repo, run_id },
      );
      if (!plainObject(response?.data)) throw new Error('workflow_run_response_invalid');
      return structuredClone(response.data);
    },
    async admitDeployment({ params, operation_id }: any) {
      return guardGithubDeploymentProtectionRule({
        connector,
        params,
        operationId: operation_id,
        ...allowanceOptions,
      });
    },
  });
}

export default Object.freeze({
  createGitHubDeploymentWebhookGate,
  createMemoryGitHubWebhookDeliveryStore,
  createGitHubDeploymentProtectionProvider,
});
