// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createGitHubDeploymentWebhookGate,
  createMemoryGitHubWebhookDeliveryStore,
} from '../src/github-deployment-webhook.js';

const SECRET = 'test-webhook-secret-with-enough-entropy';
const DELIVERY = '72d3162e-cc78-11e3-81ab-4c9367dc0958';
const PAYLOAD = Object.freeze({
  action: 'requested',
  environment: 'production',
  event: 'push',
  sha: '0123456789abcdef0123456789abcdef01234567',
  ref: 'refs/heads/main',
  deployment_callback_url: 'https://api.github.com/repos/acme/payments/actions/runs/9001/deployment_protection_rule',
  deployment: { id: 7001 },
  repository: { id: 1001, full_name: 'acme/payments', name: 'payments', owner: { login: 'acme' } },
  installation: { id: 101 },
  sender: { id: 501, login: 'release-bot' },
});
const RUN = Object.freeze({
  id: 9001,
  run_attempt: 1,
  head_sha: PAYLOAD.sha,
  head_branch: 'main',
  event: 'push',
  path: '.github/workflows/deploy.yml@refs/heads/main',
  repository: { id: 1001, full_name: 'acme/payments' },
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

function fixture(overrides: Record<string, any> = {}) {
  const calls: Array<[string, any]> = [];
  const gate = createGitHubDeploymentWebhookGate({
    webhookSecret: SECRET,
    expectedInstallationId: 101,
    expectedRepositoryId: 1001,
    expectedRepository: 'acme/payments',
    deliveryStore: createMemoryGitHubWebhookDeliveryStore(),
    allowEphemeralStore: true,
    inspectRun: async (input: any) => {
      calls.push(['inspect', input]);
      return structuredClone(RUN);
    },
    admitDeployment: async (input: any) => {
      calls.push(['admit', input]);
      return { ok: true, action_digest: `sha256:${'b'.repeat(64)}` };
    },
    ...overrides,
  });
  return { gate, calls };
}

test('invalid webhook authentication is refused before parsing or provider work', async () => {
  const { gate, calls } = fixture();
  const candidate = request();
  candidate.headers['x-hub-signature-256'] = `sha256:${'0'.repeat(64)}`;
  const result = await gate.handle(candidate);
  assert.deepEqual(result, { ok: false, status: 401, state: 'REFUSED', reason: 'webhook_signature_invalid' });
  assert.equal(calls.length, 0);
});

test('a callback URL outside the pinned GitHub endpoint is refused as hostile input', async () => {
  const { gate, calls } = fixture();
  const result = await gate.handle(request({
    ...PAYLOAD,
    deployment_callback_url: 'https://attacker.example/internal/metadata',
  }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'deployment_callback_url_invalid');
  assert.equal(calls.length, 0);
});

test('signed webhook facts are re-read and the exact deployment reaches admission', async () => {
  const { gate, calls } = fixture();
  const result = await gate.handle(request());
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.state, 'APPROVED');
  assert.deepEqual(calls[0], ['inspect', {
    installation_id: 101,
    owner: 'acme',
    repo: 'payments',
    repository_id: 1001,
    run_id: 9001,
  }]);
  assert.deepEqual(calls[1][0], 'admit');
  assert.deepEqual(calls[1][1].params, {
    owner: 'acme',
    repo: 'payments',
    repositoryId: 1001,
    environment: 'production',
    workflow: 'deploy.yml',
    ref: 'refs/heads/main',
    sha: PAYLOAD.sha,
    event: 'push',
    runId: 9001,
  });
  assert.equal(calls[1][1].operation_id, 'github:environment:1001:9001:production');
});

test('a webhook/API fact mismatch is refused and never reaches admission', async () => {
  const { gate, calls } = fixture({
    inspectRun: async () => ({ ...RUN, head_sha: 'f'.repeat(40) }),
  });
  const result = await gate.handle(request());
  assert.equal(result.ok, false);
  assert.equal(result.state, 'REFUSED');
  assert.equal(result.reason, 'workflow_run_binding_mismatch');
  assert.equal(calls.some(([name]) => name === 'admit'), false);
  assert.equal(calls.length, 0);
});

test('the same webhook delivery is idempotent and never invokes admission twice', async () => {
  const { gate, calls } = fixture();
  const first = await gate.handle(request());
  const duplicate = await gate.handle(request());
  assert.equal(first.state, 'APPROVED');
  assert.equal(duplicate.state, 'APPROVED');
  assert.equal(duplicate.duplicate, true);
  assert.equal(calls.filter(([name]) => name === 'admit').length, 1);
});

test('an uncertain approval callback remains indeterminate and duplicate delivery does not retry', async () => {
  const { gate, calls } = fixture({
    admitDeployment: async (input: any) => {
      calls.push(['admit', input]);
      return { ok: false, reason: 'effect_indeterminate' };
    },
  });
  const first = await gate.handle(request());
  const duplicate = await gate.handle(request());
  assert.equal(first.ok, false);
  assert.equal(first.state, 'INDETERMINATE');
  assert.equal(duplicate.state, 'INDETERMINATE');
  assert.equal(duplicate.duplicate, true);
  assert.equal(calls.filter(([name]) => name === 'admit').length, 1);
});
