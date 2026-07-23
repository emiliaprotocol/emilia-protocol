// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createGitHubAppInstallationTokenProvider,
  createGitHubIssueEffectProvider,
} from '../src/github-app.js';

const NOW = Date.parse('2026-07-23T12:00:00Z');
const ACTION = Object.freeze({
  action_type: 'github.issue.update.1',
  owner: 'emiliaprotocol',
  repo: 'gate-smoke-target',
  issue_number: 1,
  title: 'EMILIA consequence-control smoke',
  body: 'exact effect body',
});
const ATTEMPT = Object.freeze({
  tenant_id: 'tenant:emilia',
  provider_id: 'github',
  provider_account_id: 'emiliaprotocol',
  environment: 'production-smoke',
  attempt_id: 'attempt:0000000000000001',
  request_digest: `sha256:${'1'.repeat(64)}`,
});

test('GitHub App token provider mints a short-lived JWT and caches the installation token', async () => {
  const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const calls = [];
  const provider = createGitHubAppInstallationTokenProvider({
    appId: '12345',
    installationId: '67890',
    privateKeyPem,
    now: () => NOW,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({
        token: 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
        expires_at: '2026-07-23T12:30:00Z',
      }), { status: 201, headers: { 'content-type': 'application/json' } });
    },
  });

  const first = await provider.getToken();
  const second = await provider.getToken();
  assert.equal(first, second);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.github.com/app/installations/67890/access_tokens');
  assert.equal(calls[0].options.method, 'POST');
  const jwt = calls[0].options.headers.Authorization.slice('Bearer '.length);
  const [encodedHeader, encodedPayload, signature] = jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(encodedHeader, 'base64url')), { alg: 'RS256', typ: 'JWT' });
  assert.equal(JSON.parse(Buffer.from(encodedPayload, 'base64url')).iss, '12345');
  assert.equal(crypto.verify(
    'RSA-SHA256',
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    keys.publicKey,
    Buffer.from(signature, 'base64url'),
  ), true);
});

test('GitHub issue effect is fixed to the configured repository and binds the attempt', async () => {
  const calls = [];
  const provider = createGitHubIssueEffectProvider({
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    tokenProvider: { getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz' },
    now: () => NOW,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ number: 1, title: ACTION.title, body: ACTION.body }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  const result = await provider.effect({ action: ACTION, attempt: ATTEMPT });
  assert.equal(result.provider_status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.github.com/repos/emiliaprotocol/gate-smoke-target/issues/1');
  assert.equal(calls[0].options.method, 'PATCH');
  assert.equal(calls[0].options.headers['X-EMILIA-Attempt-ID'], ATTEMPT.attempt_id);
  assert.deepEqual(JSON.parse(calls[0].options.body), { title: ACTION.title, body: ACTION.body });

  await assert.rejects(
    () => provider.effect({ action: { ...ACTION, repo: 'emilia-protocol' }, attempt: ATTEMPT }),
    /github_issue_action_refused/,
  );
  assert.equal(calls.length, 1);
});

test('forced post-commit uncertainty stays indeterminate and equal current state escalates without attempt attribution', async () => {
  let method = null;
  const provider = createGitHubIssueEffectProvider({
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    forceIndeterminateAfterCommit: true,
    tokenProvider: { getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz' },
    now: () => NOW,
    fetchImpl: async (_url, options) => {
      method = options.method;
      return new Response(JSON.stringify({ number: 1, title: ACTION.title, body: ACTION.body }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  await assert.rejects(
    () => provider.effect({ action: ACTION, attempt: ATTEMPT }),
    (error) => error.code === 'github_issue_outcome_indeterminate',
  );
  assert.equal(method, 'PATCH');

  const expected = {
    operation_id: 'operation:0000000000000001',
    caid: `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`,
    action_digest: `sha256:${'2'.repeat(64)}`,
    ...ATTEMPT,
  };
  const verified = await provider.verifyProviderEvidence({
    evidence: { kind: 'github-issue-observation-v1' },
    expected,
    action: ACTION,
  });
  assert.equal(method, 'GET');
  assert.equal(verified.valid, true);
  assert.equal(verified.outcome, 'ESCALATED');
  assert.equal(verified.reason, 'github_attempt_attribution_unavailable');
  assert.equal(verified.attempt_id, ATTEMPT.attempt_id);
  assert.match(verified.evidence_digest, /^sha256:[a-f0-9]{64}$/);
});

test('authenticated observation cannot attribute an equal state written by an unrelated actor', async () => {
  const provider = createGitHubIssueEffectProvider({
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    tokenProvider: { getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz' },
    now: () => NOW,
    fetchImpl: async () => new Response(JSON.stringify({
      number: 1,
      title: ACTION.title,
      body: ACTION.body,
      updated_by: { login: 'unrelated-writer' },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  });

  const verified = await provider.verifyProviderEvidence({
    evidence: { kind: 'github-issue-observation-v1' },
    expected: {
      operation_id: 'operation:0000000000000001',
      caid: `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`,
      action_digest: `sha256:${'2'.repeat(64)}`,
      ...ATTEMPT,
    },
    action: ACTION,
  });

  assert.equal(verified.valid, true);
  assert.equal(verified.outcome, 'ESCALATED');
  assert.equal(verified.reason, 'github_attempt_attribution_unavailable');
});

test('current-state evidence cannot be substituted across attempts', async () => {
  const provider = createGitHubIssueEffectProvider({
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    tokenProvider: { getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz' },
    now: () => NOW,
    fetchImpl: async () => new Response(JSON.stringify({
      number: 1,
      title: ACTION.title,
      body: ACTION.body,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  });
  const evidence = { kind: 'github-issue-observation-v1' };
  const expected = {
    operation_id: 'operation:0000000000000001',
    caid: `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`,
    action_digest: `sha256:${'2'.repeat(64)}`,
    ...ATTEMPT,
  };

  const first = await provider.verifyProviderEvidence({ evidence, expected, action: ACTION });
  const substituted = await provider.verifyProviderEvidence({
    evidence,
    expected: {
      ...expected,
      attempt_id: 'attempt:0000000000000002',
      request_digest: `sha256:${'3'.repeat(64)}`,
    },
    action: ACTION,
  });

  assert.equal(first.outcome, 'ESCALATED');
  assert.equal(substituted.outcome, 'ESCALATED');
  assert.equal(substituted.reason, 'github_attempt_attribution_unavailable');
  assert.notEqual(first.evidence_digest, substituted.evidence_digest);
});
