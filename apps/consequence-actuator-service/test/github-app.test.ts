// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import {
  createGitHubAppInstallationTokenProvider,
  createGitHubIssueEffectProvider,
} from '../src/github-app.ts';

const NOW = Date.parse('2026-07-25T12:00:00.000Z');
const ACTION = Object.freeze({
  action_type: 'github.issue.update.1',
  owner: 'emiliaprotocol',
  repo: 'gate-smoke-target',
  issue_number: 1,
  title: 'EMILIA consequence-control smoke',
  body: 'exact effect body',
});
const ATTEMPT = Object.freeze({
  attempt_id: 'attempt:0000000000000001',
});
const EXPECTED = Object.freeze({
  operation_id: 'operation:0000000000000001',
  caid: `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`,
  action_digest: `sha256:${'2'.repeat(64)}`,
  tenant_id: 'tenant:emilia',
  provider_id: 'github',
  provider_account_id: 'emiliaprotocol',
  environment: 'production-smoke',
  attempt_id: ATTEMPT.attempt_id,
  request_digest: `sha256:${'1'.repeat(64)}`,
});

describe('actuator-owned GitHub App provider', () => {
  it('mints a signed app JWT and caches the installation token', async () => {
    const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const calls: Array<{ url: string; options: any }> = [];
    const provider = createGitHubAppInstallationTokenProvider({
      appId: '12345',
      installationId: '67890',
      privateKeyPem,
      now: () => NOW,
      fetchImpl: async (url: string, options: any) => {
        calls.push({ url, options });
        return new Response(JSON.stringify({
          token: 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
          expires_at: '2026-07-25T12:30:00.000Z',
        }), {
          status: 201,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    const first = await provider.getToken();
    const second = await provider.getToken();

    assert.equal(first, second);
    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].url,
      'https://api.github.com/app/installations/67890/access_tokens',
    );
    const jwt = calls[0].options.headers.Authorization.slice('Bearer '.length);
    const [encodedHeader, encodedPayload, signature] = jwt.split('.');
    assert.deepEqual(
      JSON.parse(Buffer.from(encodedHeader, 'base64url').toString()),
      { alg: 'RS256', typ: 'JWT' },
    );
    assert.equal(
      JSON.parse(Buffer.from(encodedPayload, 'base64url').toString()).iss,
      '12345',
    );
    assert.equal(crypto.verify(
      'RSA-SHA256',
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      keys.publicKey,
      Buffer.from(signature, 'base64url'),
    ), true);
  });

  it('pins the repository target and binds the attempt header', async () => {
    const calls: Array<{ url: string; options: any }> = [];
    const provider = createGitHubIssueEffectProvider({
      owner: ACTION.owner,
      repo: ACTION.repo,
      issueNumber: ACTION.issue_number,
      tokenProvider: {
        getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
      },
      now: () => NOW,
      fetchImpl: async (url: string, options: any) => {
        calls.push({ url, options });
        return new Response(JSON.stringify({
          number: ACTION.issue_number,
          title: ACTION.title,
          body: ACTION.body,
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    const result = await provider.effect({ action: ACTION, attempt: ATTEMPT });

    assert.equal(result.provider_status, 200);
    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].url,
      'https://api.github.com/repos/emiliaprotocol/gate-smoke-target/issues/1',
    );
    assert.equal(calls[0].options.method, 'PATCH');
    assert.equal(
      calls[0].options.headers['X-EMILIA-Attempt-ID'],
      ATTEMPT.attempt_id,
    );
    assert.deepEqual(JSON.parse(calls[0].options.body), {
      title: ACTION.title,
      body: ACTION.body,
    });

    await assert.rejects(
      provider.effect({
        action: { ...ACTION, repo: 'substituted-target' },
        attempt: ATTEMPT,
      }),
      /github_issue_action_refused/,
    );
    assert.equal(calls.length, 1);
  });

  it('returns action/attempt-bound observation material without overstating attribution', async () => {
    const provider = createGitHubIssueEffectProvider({
      owner: ACTION.owner,
      repo: ACTION.repo,
      issueNumber: ACTION.issue_number,
      tokenProvider: {
        getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
      },
      now: () => NOW,
      fetchImpl: async () => new Response(JSON.stringify({
        number: ACTION.issue_number,
        title: ACTION.title,
        body: ACTION.body,
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    });

    const observation = await provider.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
    });

    assert.equal(observation.valid, true);
    assert.equal(observation.outcome, 'ESCALATED');
    assert.equal(
      observation.reason,
      'github_attempt_attribution_unavailable',
    );
    assert.match(
      observation.evidence_digest,
      /^sha256:[a-f0-9]{64}$/,
    );
  });

  it('refuses redirects even if a mock presents a successful JSON response', async () => {
    const body = new Response('{}', {
      headers: { 'content-type': 'application/json' },
    }).body;
    const provider = createGitHubIssueEffectProvider({
      owner: ACTION.owner,
      repo: ACTION.repo,
      issueNumber: ACTION.issue_number,
      tokenProvider: {
        getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
      },
      fetchImpl: async () => ({
        status: 200,
        redirected: true,
        url: 'https://attacker.example/redirected',
        headers: new Headers({ 'content-type': 'application/json' }),
        body,
      }),
    });

    await assert.rejects(
      provider.effect({ action: ACTION, attempt: ATTEMPT }),
      /github_redirect_refused/,
    );
  });

  it('refuses announced and streamed oversized provider bodies', async () => {
    const provider = createGitHubIssueEffectProvider({
      owner: ACTION.owner,
      repo: ACTION.repo,
      issueNumber: ACTION.issue_number,
      tokenProvider: {
        getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
      },
      fetchImpl: async () => new Response('{}', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(600 * 1024),
        },
      }),
    });

    await assert.rejects(
      provider.effect({ action: ACTION, attempt: ATTEMPT }),
      /github_response_too_large/,
    );
  });
});
