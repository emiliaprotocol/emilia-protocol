// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createGitHubDeploymentDeliveryWorker,
  createGitHubDeploymentWebhookInbox,
  createMemoryGitHubDeploymentDeliveryQueue,
  createPostgresGitHubDeploymentDeliveryQueue,
} from '../src/github-deployment-queue.js';
import { createGitHubDeploymentWebhookProcessor } from '../src/github-deployment-webhook.js';

const SECRET = 'queue-webhook-secret-with-enough-entropy';
const DELIVERY = '72d3162e-cc78-11e3-81ab-4c9367dc0958';
const PAYLOAD = Object.freeze({
  action: 'requested',
  environment: 'production',
  event: 'push',
  sha: '0123456789abcdef0123456789abcdef01234567',
  ref: 'refs/heads/main',
  deployment_callback_url: 'https://api.github.com/repos/acme/payments/actions/runs/9001/deployment_protection_rule',
  repository: { id: 1001, full_name: 'acme/payments', name: 'payments', owner: { login: 'acme' } },
  installation: { id: 101 },
});

function request(payload: any = PAYLOAD, delivery = DELIVERY) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const signature = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  return {
    body,
    headers: {
      'content-type': 'application/json',
      'user-agent': 'GitHub-Hookshot/abc123',
      'x-github-event': 'deployment_protection_rule',
      'x-github-delivery': delivery,
      'x-hub-signature-256': `sha256=${signature}`,
    },
  };
}

function inbox(queue: any) {
  return createGitHubDeploymentWebhookInbox({
    tenantId: 'tenant:acme',
    webhookSecret: SECRET,
    expectedInstallationId: 101,
    expectedRepositoryId: 1001,
    expectedRepository: 'acme/payments',
    queue,
    allowEphemeralQueue: true,
  });
}

test('inbox refuses invalid authentication configuration at startup', () => {
  assert.throws(
    () => createGitHubDeploymentWebhookInbox({
      tenantId: 'tenant:acme',
      webhookSecret: 'short',
      expectedInstallationId: 101,
      expectedRepositoryId: 1001,
      expectedRepository: 'acme/payments',
      queue: createMemoryGitHubDeploymentDeliveryQueue(),
      allowEphemeralQueue: true,
    }),
    /github_deployment_webhook_auth_config_invalid/,
  );
});

test('inbox authenticates and durably records exact bytes before returning 202', async () => {
  const queue = createMemoryGitHubDeploymentDeliveryQueue();
  const candidate = request();
  const result = await inbox(queue).handle(candidate);

  assert.deepEqual(result, {
    ok: true,
    status: 202,
    state: 'QUEUED',
    delivery_id: DELIVERY,
  });
  const stored = await queue.read({ tenant_id: 'tenant:acme', delivery_id: DELIVERY });
  assert.equal(stored.body.equals(candidate.body), true);
  assert.equal(stored.headers['x-hub-signature-256'], candidate.headers['x-hub-signature-256']);
  assert.equal(stored.state, 'QUEUED');
});

test('duplicate bytes are idempotent and a reused delivery ID with different bytes conflicts', async () => {
  const queue = createMemoryGitHubDeploymentDeliveryQueue();
  const receiver = inbox(queue);
  assert.equal((await receiver.handle(request())).status, 202);
  const duplicate = await receiver.handle(request());
  assert.equal(duplicate.status, 202);
  assert.equal(duplicate.duplicate, true);
  const conflict = await receiver.handle(request({ ...PAYLOAD, environment: 'staging' }));
  assert.equal(conflict.status, 409);
  assert.equal(conflict.reason, 'delivery_id_conflict');
});

test('concurrent workers lease one delivery to exactly one processor', async () => {
  const queue = createMemoryGitHubDeploymentDeliveryQueue();
  await inbox(queue).handle(request());
  let calls = 0;
  const process = async () => {
    calls += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return { ok: true, status: 200, state: 'APPROVED' };
  };
  const first = createGitHubDeploymentDeliveryWorker({
    tenantId: 'tenant:acme', queue, process, leaseOwner: 'worker-a', allowEphemeralQueue: true,
  });
  const second = createGitHubDeploymentDeliveryWorker({
    tenantId: 'tenant:acme', queue, process, leaseOwner: 'worker-b', allowEphemeralQueue: true,
  });
  const results = await Promise.all([first.runOnce(), second.runOnce()]);

  assert.equal(calls, 1);
  assert.equal(results.filter((result) => result.processed === true).length, 1);
  assert.equal(results.filter((result) => result.empty === true).length, 1);
});

test('leased processing re-verifies the queued HMAC and exact workflow-run binding', async () => {
  const queue = createMemoryGitHubDeploymentDeliveryQueue();
  await inbox(queue).handle(request());
  let admissions = 0;
  const processor = createGitHubDeploymentWebhookProcessor({
    webhookSecret: SECRET,
    expectedInstallationId: 101,
    expectedRepositoryId: 1001,
    expectedRepository: 'acme/payments',
    inspectRun: async () => ({
      id: 9001,
      head_sha: PAYLOAD.sha,
      head_branch: 'main',
      event: 'push',
      path: '.github/workflows/deploy.yml@refs/heads/main',
      repository: { id: 1001, full_name: 'acme/payments' },
    }),
    admitDeployment: async () => {
      admissions += 1;
      return { ok: true, action_digest: `sha256:${'b'.repeat(64)}` };
    },
  });
  const worker = createGitHubDeploymentDeliveryWorker({
    tenantId: 'tenant:acme',
    queue,
    process: processor.process,
    leaseOwner: 'worker-a',
    allowEphemeralQueue: true,
  });

  assert.equal((await worker.runOnce()).state, 'APPROVED');
  assert.equal((await worker.runOnce()).empty, true);
  assert.equal(admissions, 1);
});

test('pre-admission unavailability is retried, but indeterminate admission is terminal', async () => {
  const queue = createMemoryGitHubDeploymentDeliveryQueue();
  await inbox(queue).handle(request());
  let calls = 0;
  const worker = createGitHubDeploymentDeliveryWorker({
    tenantId: 'tenant:acme',
    queue,
    leaseOwner: 'worker-a',
    allowEphemeralQueue: true,
    retryDelayMs: 0,
    process: async () => {
      calls += 1;
      return calls === 1
        ? { ok: false, status: 503, state: 'UNAVAILABLE', reason: 'workflow_run_unavailable' }
        : { ok: false, status: 200, state: 'INDETERMINATE', reason: 'effect_indeterminate' };
    },
  });

  assert.equal((await worker.runOnce()).requeued, true);
  assert.equal((await worker.runOnce()).state, 'INDETERMINATE');
  assert.equal((await worker.runOnce()).empty, true);
  assert.equal(calls, 2);
});

test('an expired lease is reclaimable and the stale worker cannot complete it', async () => {
  let now = 1_000;
  const queue = createMemoryGitHubDeploymentDeliveryQueue({ now: () => now });
  await inbox(queue).handle(request());
  const first = await queue.claimNext({
    tenant_id: 'tenant:acme', lease_owner: 'worker-a', lease_token: 'lease-a', lease_ms: 100,
  });
  assert.equal(first.ok, true);
  now = 1_101;
  const second = await queue.claimNext({
    tenant_id: 'tenant:acme', lease_owner: 'worker-b', lease_token: 'lease-b', lease_ms: 100,
  });
  assert.equal(second.ok, true);
  assert.equal(second.record.delivery_id, DELIVERY);
  assert.equal((await queue.complete({
    tenant_id: 'tenant:acme', delivery_id: DELIVERY, request_digest: first.record.request_digest,
    lease_token: 'lease-a', state: 'APPROVED', reason: null, result: null,
  })).ok, false);
});

test('PostgreSQL adapter binds enqueue, lease, completion, retry, and read to exact RPC acknowledgements', async () => {
  const calls: Array<{ text: string; values: readonly unknown[] }> = [];
  const record = {
    tenant_id: 'tenant:acme', delivery_id: DELIVERY, request_digest: `sha256:${'a'.repeat(64)}`,
    body: Buffer.from('{}'), headers: {}, state: 'QUEUED', attempt_count: 0,
  };
  const queue = createPostgresGitHubDeploymentDeliveryQueue(async (text, values) => {
    calls.push({ text, values });
    if (text.includes('enqueue_github_deployment_delivery')) return { rowCount: 1, rows: [{ outcome: 'ENQUEUED', delivery: record }] };
    if (text.includes('claim_github_deployment_delivery')) return { rowCount: 1, rows: [{ delivery: { ...record, state: 'PROCESSING' } }] };
    if (text.includes('complete_github_deployment_delivery')) return { rowCount: 1, rows: [{ delivery: { ...record, state: 'APPROVED' } }] };
    if (text.includes('retry_github_deployment_delivery')) return { rowCount: 1, rows: [{ delivery: record }] };
    if (text.includes('read_github_deployment_delivery')) return { rowCount: 1, rows: [{ delivery: record }] };
    throw new Error('unexpected query');
  });

  assert.equal((await queue.enqueue({ ...record })).ok, true);
  assert.equal((await queue.claimNext({ tenant_id: 'tenant:acme', lease_owner: 'worker', lease_token: 'lease', lease_ms: 1000 })).ok, true);
  assert.equal((await queue.complete({ ...record, lease_token: 'lease', state: 'APPROVED', reason: null, result: null })).ok, true);
  assert.equal((await queue.retry({ ...record, lease_token: 'lease', reason: 'upstream_unavailable', delay_ms: 1000 })).ok, true);
  assert.equal((await queue.read({ tenant_id: 'tenant:acme', delivery_id: DELIVERY })).state, 'QUEUED');
  assert.equal(calls.length, 5);
  assert.ok(calls.every((call) => call.text.includes('consequence_actuator_private.')));
});
