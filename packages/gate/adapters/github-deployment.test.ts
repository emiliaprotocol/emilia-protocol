// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import { allowanceDigest, issueGateAllowance } from '../allowance.js';
import { createMemoryCapabilityStore } from '../capability-receipt.js';
import {
  createGithubDeploymentProtectionConnector,
  guardGithubDeploymentProtectionRule,
} from './github.js';

const NOW = Date.parse('2026-08-08T20:00:00.000Z');
const STATUS = Object.freeze({
  ok: true,
  status_epoch: 1,
  status_head_digest: `sha256:${'a'.repeat(64)}`,
});

const BASE_PARAMS = Object.freeze({
  owner: 'acme',
  repo: 'payments',
  repositoryId: 1001,
  environment: 'production',
  workflow: 'deploy.yml',
  ref: 'refs/heads/main',
  sha: '0123456789abcdef0123456789abcdef01234567',
  event: 'push',
  runId: 9001,
});

function fakeOctokit({ installationId = 101, callbackError = null, callbackStatus = 204 } = {}) {
  const calls: Array<[string, any?]> = [];
  return {
    calls,
    async request(route: string, parameters?: any) {
      calls.push([route, parameters]);
      if (route === 'GET /installation') return { data: { id: installationId } };
      if (callbackError) throw callbackError;
      return { status: callbackStatus };
    },
  };
}

function issueDeploymentAllowance() {
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const issued = issueGateAllowance({
    authorizationReceipt: {
      '@version': 'EP-RECEIPT-v1',
      payload: {
        receipt_id: 'receipt:github-deployment-allowance:01',
        claim: { action_type: 'gate.allowance.issue', capability_only: true },
      },
    },
    allowance: {
      allowance_id: 'allowance:github-deployment:production',
      tenant_id: 'tenant:acme',
      subject_id: 'agent:release',
      audience: 'gate:github:production',
      connector_id: 'github:installation:101',
      action_type: 'github.environment.enter.production',
      revision: 1,
      supersedes_allowance_digest: null,
      presentation_digest: `sha256:${'1'.repeat(64)}`,
      issued_at: '2026-08-08T19:59:00.000Z',
      valid_from: '2026-08-08T20:00:00.000Z',
      expires_at: '2026-08-09T20:00:00.000Z',
      constraints: {
        currency: 'ADMISSION',
        aggregate_amount: 3,
        max_amount_per_action: 1,
        material_fields: [
          'action_type',
          'repository',
          'repository_id',
          'environment',
          'workflow',
          'ref',
          'sha',
          'event',
          'run_id',
          'decision',
          'amount',
          'currency',
          'operation_id',
        ],
        operation_id_field: 'operation_id',
        amount_field: 'amount',
        currency_field: 'currency',
        target_field: 'repository',
        allowed_targets: ['acme/payments'],
        allowed_values: {
          environment: ['production'],
          workflow: ['deploy.yml'],
          ref: ['refs/heads/main'],
          sha: ['0123456789abcdef0123456789abcdef01234567'],
          event: ['push'],
          decision: ['approved'],
        },
      },
    },
    signer: {
      issuer_id: 'customer:acme:security',
      key_id: 'key:allowance',
      private_key: keys.privateKey,
    },
    capabilityIssuerPrivateKey: keys.privateKey,
    capabilityRevocationMode: 'direct',
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  assert.equal(store.advanceAllowanceStatus({
    allowance_profile_id: `${issued.allowance.tenant_id}/${issued.allowance.allowance_id}`,
    allowance_digest: allowanceDigest(issued.allowance),
    revision: issued.allowance.revision,
    status_epoch: STATUS.status_epoch,
    status_head_digest: STATUS.status_head_digest,
    expected_status_epoch: null,
    expected_status_head_digest: null,
    status: 'active',
  }).ok, true);
  return {
    issued,
    store,
    trustedAllowanceKeys: {
      'key:allowance': {
        issuer_id: 'customer:acme:security',
        public_key: publicKey,
      },
    },
    trustedCapabilityIssuerKeys: [publicKey],
  };
}

function allowanceArgs(fixture: ReturnType<typeof issueDeploymentAllowance>) {
  return {
    allowance: fixture.issued.allowance,
    capabilityReceipt: fixture.issued.capabilityReceipt,
    secret: fixture.issued.secret,
    store: fixture.store,
    verifyAuthorizationReceipt: () => true,
    verifyAllowanceStatus: () => STATUS,
    trustedAllowanceKeys: fixture.trustedAllowanceKeys,
    trustedCapabilityIssuerKeys: fixture.trustedCapabilityIssuerKeys,
    expected: {
      allowance_id: 'allowance:github-deployment:production',
      tenant_id: 'tenant:acme',
      subject_id: 'agent:release',
      audience: 'gate:github:production',
      authorizer_id: 'customer:acme:security',
    },
    now: NOW,
  };
}

test('deployment connector binds itself to the authenticated GitHub installation', async () => {
  const octokit = fakeOctokit();
  await createGithubDeploymentProtectionConnector({ octokit });
  assert.deepEqual(octokit.calls, [['GET /installation', undefined]]);
});

test('an exact run/environment admission consumes authority before GitHub approval', async () => {
  const fixture = issueDeploymentAllowance();
  const octokit = fakeOctokit();
  const connector = await createGithubDeploymentProtectionConnector({ octokit });
  const result = await guardGithubDeploymentProtectionRule({
    connector,
    params: BASE_PARAMS,
    operationId: 'github:deployment:1001:9001:1:production',
    ...allowanceArgs(fixture),
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(octokit.calls.at(-1), [
    'POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule',
    {
      owner: 'acme',
      repo: 'payments',
      run_id: 9001,
      environment_name: 'production',
      state: 'approved',
      comment: "EMILIA authorized this workflow run's admission to this environment.",
    },
  ]);
});

test('workflow, ref, SHA, environment, and installation substitution never reaches approval', async () => {
  for (const [change, installationId] of [
    [{ workflow: 'attacker.yml' }, 101],
    [{ ref: 'refs/heads/attacker' }, 101],
    [{ sha: 'f'.repeat(40) }, 101],
    [{ environment: 'production-shadow' }, 101],
    [{}, 202],
  ] as const) {
    const fixture = issueDeploymentAllowance();
    const octokit = fakeOctokit({ installationId });
    const connector = await createGithubDeploymentProtectionConnector({ octokit });
    const result = await guardGithubDeploymentProtectionRule({
      connector,
      params: { ...BASE_PARAMS, ...change },
      operationId: `github:deployment:substitution:${installationId}:${Object.keys(change)[0] ?? 'installation'}`,
      ...allowanceArgs(fixture),
    });
    assert.equal(result.ok, false);
    assert.equal(octokit.calls.length, 1, JSON.stringify(octokit.calls));
  }
});

test('the same material deployment cannot be approved under a second operation id', async () => {
  const fixture = issueDeploymentAllowance();
  const octokit = fakeOctokit();
  const connector = await createGithubDeploymentProtectionConnector({ octokit });
  const first = await guardGithubDeploymentProtectionRule({
    connector,
    params: BASE_PARAMS,
    operationId: 'github:deployment:first',
    ...allowanceArgs(fixture),
  });
  const replay = await guardGithubDeploymentProtectionRule({
    connector,
    params: BASE_PARAMS,
    operationId: 'github:deployment:second',
    ...allowanceArgs(fixture),
  });
  assert.equal(first.ok, true);
  assert.equal(replay.ok, false);
  assert.match(String(replay.reason), /action_(?:already_)?(?:committed|executed|in_progress)|replay/);
  assert.equal(octokit.calls.filter(([route]) => route.startsWith('POST ')).length, 1);
});

test('an uncertain GitHub callback is indeterminate and cannot be blindly retried', async () => {
  const fixture = issueDeploymentAllowance();
  const octokit = fakeOctokit({ callbackError: new Error('response lost') });
  const connector = await createGithubDeploymentProtectionConnector({ octokit });
  const first = await guardGithubDeploymentProtectionRule({
    connector,
    params: BASE_PARAMS,
    operationId: 'github:deployment:uncertain',
    ...allowanceArgs(fixture),
  });
  const retry = await guardGithubDeploymentProtectionRule({
    connector,
    params: BASE_PARAMS,
    operationId: 'github:deployment:retry',
    ...allowanceArgs(fixture),
  });
  assert.deepEqual(first.ok, false);
  assert.equal(first.reason, 'effect_indeterminate');
  assert.equal(retry.ok, false);
  assert.equal(octokit.calls.filter(([route]) => route.startsWith('POST ')).length, 1);
});

test('a non-204 GitHub review acknowledgement is indeterminate', async () => {
  const fixture = issueDeploymentAllowance();
  const octokit = fakeOctokit({ callbackStatus: 202 });
  const connector = await createGithubDeploymentProtectionConnector({ octokit });
  const result = await guardGithubDeploymentProtectionRule({
    connector,
    params: BASE_PARAMS,
    operationId: 'github:deployment:non-204',
    ...allowanceArgs(fixture),
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'effect_indeterminate');
});

test('concurrent wrappers have one approval winner for one material deployment', async () => {
  const fixture = issueDeploymentAllowance();
  const octokit = fakeOctokit();
  const connector = await createGithubDeploymentProtectionConnector({ octokit });
  const [first, second] = await Promise.all([
    guardGithubDeploymentProtectionRule({
      connector,
      params: BASE_PARAMS,
      operationId: 'github:deployment:race:a',
      ...allowanceArgs(fixture),
    }),
    guardGithubDeploymentProtectionRule({
      connector,
      params: BASE_PARAMS,
      operationId: 'github:deployment:race:b',
      ...allowanceArgs(fixture),
    }),
  ]);
  assert.equal([first, second].filter((result) => result.ok).length, 1);
  assert.equal(octokit.calls.filter(([route]) => route.startsWith('POST ')).length, 1);
});
