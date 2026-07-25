// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import {
  createGitHubAppInstallationTokenProvider,
  createGitHubIssueEffectProvider,
} from '../src/github-app.ts';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';

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
  action_digest: digestAeb(ACTION),
  tenant_id: 'tenant:emilia',
  provider_id: 'github',
  provider_account_id: 'emiliaprotocol',
  environment: 'production-smoke',
  attempt_id: ATTEMPT.attempt_id,
  request_digest: `sha256:${'1'.repeat(64)}`,
});
const TARGET_DIGEST = digestAeb({
  domain: 'EP-CONSEQUENCE-ACTUATOR-TARGET-v1',
  provider_id: EXPECTED.provider_id,
  provider_account_id: EXPECTED.provider_account_id,
  target: {
    kind: 'github.issue',
    owner: ACTION.owner,
    repo: ACTION.repo,
    issue_number: ACTION.issue_number,
  },
});
const EFFECT_DIGEST = digestAeb({
  domain: 'EP-GITHUB-ISSUE-EFFECT-v1',
  tenant_id: EXPECTED.tenant_id,
  provider_id: EXPECTED.provider_id,
  provider_account_id: EXPECTED.provider_account_id,
  environment: EXPECTED.environment,
  target_digest: TARGET_DIGEST,
  target: {
    owner: ACTION.owner,
    repo: ACTION.repo,
    issue_number: ACTION.issue_number,
  },
  effect: {
    title: ACTION.title,
    body: ACTION.body,
  },
});
const BOUND_ATTEMPT = Object.freeze({
  '@version': 'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1',
  issuer_id: 'consequence-control',
  tenant_id: EXPECTED.tenant_id,
  provider_id: EXPECTED.provider_id,
  provider_account_id: EXPECTED.provider_account_id,
  environment: EXPECTED.environment,
  request_digest: EXPECTED.request_digest,
  attempt_id: EXPECTED.attempt_id,
  operation_id: EXPECTED.operation_id,
  caid: EXPECTED.caid,
  action_digest: EXPECTED.action_digest,
  target_digest: TARGET_DIGEST,
  operation: ACTION.action_type,
  envelope_digest: `sha256:${'3'.repeat(64)}`,
  effect_digest: EFFECT_DIGEST,
  issued_at: new Date(NOW - 1_000).toISOString(),
});
const ATTRIBUTION_KEYS = crypto.generateKeyPairSync('ed25519');

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function attributionProviderOptions(
  fetchImpl: (url: string, options: any) => Promise<any>,
  privateKey: crypto.KeyObject,
) {
  return {
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    tokenProvider: {
      getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
    },
    attributionKeyId: 'actuator-evidence-key',
    attributionPrivateKey: privateKey,
    attributionIssuerId: BOUND_ATTEMPT.issuer_id,
    targetDigest: TARGET_DIGEST,
    fetchImpl,
    now: () => NOW,
  };
}

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
      attributionIssuerId: BOUND_ATTEMPT.issuer_id,
      attributionKeyId: 'actuator-evidence-key',
      attributionPrivateKey: ATTRIBUTION_KEYS.privateKey,
      targetDigest: TARGET_DIGEST,
      now: () => NOW,
      fetchImpl: async (url: string, options: any) => {
        calls.push({ url, options });
        const requestBody = options.body ? JSON.parse(options.body) : {};
        if (url.endsWith('/issues/1/comments') && options.method === 'POST') {
          return json({ id: 7000, body: requestBody.body }, 201);
        }
        if (url.endsWith('/issues/comments/7000') && options.method === 'PATCH') {
          return json({ id: 7000, body: requestBody.body });
        }
        return json({
          number: ACTION.issue_number,
          title: requestBody.title,
          body: requestBody.body,
        });
      },
    });

    const result = await provider.effect({
      action: ACTION,
      attempt: BOUND_ATTEMPT,
    });

    assert.equal(result.provider_status, 200);
    assert.equal(calls.length, 3);
    const mutation = calls.find(({ url, options }) => (
      url.endsWith('/issues/1') && options.method === 'PATCH'
    ))!;
    assert.equal(
      mutation.url,
      'https://api.github.com/repos/emiliaprotocol/gate-smoke-target/issues/1',
    );
    assert.equal(mutation.options.method, 'PATCH');
    assert.equal(
      mutation.options.headers['X-EMILIA-Attempt-ID'],
      ATTEMPT.attempt_id,
    );
    const mutationBody = JSON.parse(mutation.options.body);
    assert.equal(mutationBody.title, ACTION.title);
    assert.equal(mutationBody.body, ACTION.body);

    await assert.rejects(
      provider.effect({
        action: { ...ACTION, repo: 'substituted-target' },
        attempt: BOUND_ATTEMPT,
      }),
      /github_issue_action_refused/,
    );
    assert.equal(calls.length, 3);
  });

  it('returns action/attempt-bound observation material without overstating attribution', async () => {
    const provider = createGitHubIssueEffectProvider({
      owner: ACTION.owner,
      repo: ACTION.repo,
      issueNumber: ACTION.issue_number,
      tokenProvider: {
        getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
      },
      attributionIssuerId: BOUND_ATTEMPT.issuer_id,
      attributionKeyId: 'actuator-evidence-key',
      attributionPrivateKey: ATTRIBUTION_KEYS.privateKey,
      targetDigest: TARGET_DIGEST,
      now: () => NOW,
      fetchImpl: async (url: string) => (
        url.includes('/comments?')
          ? json([])
          : json({
            number: ACTION.issue_number,
            title: ACTION.title,
            body: ACTION.body,
          })
      ),
    });

    const observation = await provider.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
      operation: ACTION.action_type,
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

  it('reconciles the exact committed attempt after the signed actuator response is lost and the service restarts', async () => {
    const attributionKeys = crypto.generateKeyPairSync('ed25519');
    let issue = {
      number: ACTION.issue_number,
      title: 'before',
      body: 'before',
      updated_at: '2026-07-25T11:00:00.000Z',
    };
    const comments: Array<{ id: number; body: string }> = [];
    const fetchImpl = async (url: string, options: any) => {
      if (url.endsWith('/issues/1/comments') && options.method === 'POST') {
        const comment = {
          id: 7001,
          body: JSON.parse(options.body).body,
        };
        comments.push(comment);
        return json(comment, 201);
      }
      if (url.endsWith('/issues/1') && options.method === 'PATCH') {
        const mutation = JSON.parse(options.body);
        issue = {
          number: ACTION.issue_number,
          title: mutation.title,
          body: mutation.body,
          updated_at: new Date(NOW).toISOString(),
        };
        return json(issue);
      }
      if (url.endsWith('/issues/comments/7001') && options.method === 'PATCH') {
        comments[0] = { id: 7001, body: JSON.parse(options.body).body };
        return json(comments[0]);
      }
      if (url.endsWith('/issues/1') && options.method === 'GET') {
        return json(issue);
      }
      if (url.includes('/issues/1/comments?') && options.method === 'GET') {
        return json(comments);
      }
      throw new Error(`unexpected GitHub request: ${options.method} ${url}`);
    };
    const firstProcess = createGitHubIssueEffectProvider({
      ...attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
      forceIndeterminateAfterCommit: true,
    });

    await assert.rejects(
      firstProcess.effect({ action: ACTION, attempt: BOUND_ATTEMPT }),
      /github_issue_outcome_indeterminate/,
    );

    const restartedProcess = createGitHubIssueEffectProvider(
      attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
    );
    const observation = await restartedProcess.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
      operation: ACTION.action_type,
    });

    assert.equal(observation.valid, true);
    assert.equal(observation.outcome, 'COMMITTED');
    assert.equal(observation.reason, 'github_exact_attempt_committed');
    assert.equal(issue.body, ACTION.body);
    assert.equal(comments.length, 1);

    comments[0] = { id: 7999, body: comments[0].body };
    const replayedRecord = await restartedProcess.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
      operation: ACTION.action_type,
    });
    assert.equal(replayedRecord.outcome, 'ESCALATED');
    assert.equal(
      replayedRecord.reason,
      'github_attempt_attribution_unavailable',
    );
  });

  it('keeps the attempt ESCALATED when the GitHub mutation response is lost before terminal attribution', async () => {
    const attributionKeys = crypto.generateKeyPairSync('ed25519');
    let issue = {
      number: ACTION.issue_number,
      title: 'before',
      body: 'before',
      updated_at: '2026-07-25T11:00:00.000Z',
    };
    const comments: Array<{ id: number; body: string }> = [];
    const fetchImpl = async (url: string, options: any) => {
      if (url.endsWith('/issues/1/comments') && options.method === 'POST') {
        const comment = {
          id: 7001,
          body: JSON.parse(options.body).body,
        };
        comments.push(comment);
        return json(comment, 201);
      }
      if (url.endsWith('/issues/1') && options.method === 'PATCH') {
        const mutation = JSON.parse(options.body);
        issue = {
          number: ACTION.issue_number,
          title: mutation.title,
          body: mutation.body,
          updated_at: new Date(NOW).toISOString(),
        };
        throw Object.assign(new Error('socket closed after commit'), {
          name: 'TimeoutError',
        });
      }
      if (url.endsWith('/issues/1') && options.method === 'GET') {
        return json(issue);
      }
      if (url.includes('/issues/1/comments?') && options.method === 'GET') {
        return json(comments);
      }
      throw new Error(`unexpected GitHub request: ${options.method} ${url}`);
    };
    const firstProcess = createGitHubIssueEffectProvider(
      attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
    );

    await assert.rejects(
      firstProcess.effect({ action: ACTION, attempt: BOUND_ATTEMPT }),
      /github_issue_outcome_indeterminate/,
    );

    const restartedProcess = createGitHubIssueEffectProvider(
      attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
    );
    const observation = await restartedProcess.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
      operation: ACTION.action_type,
    });

    assert.equal(observation.valid, true);
    assert.equal(observation.outcome, 'ESCALATED');
    assert.equal(observation.reason, 'github_attempt_outcome_indeterminate');
    assert.equal(issue.body, ACTION.body);
    assert.equal(comments.length, 1);
  });

  it('persists and reconciles a definitive provider refusal as NOT_COMMITTED', async () => {
    const attributionKeys = crypto.generateKeyPairSync('ed25519');
    const issue = {
      number: ACTION.issue_number,
      title: 'before',
      body: 'before',
      updated_at: '2026-07-25T11:00:00.000Z',
    };
    const comments: Array<{ id: number; body: string }> = [];
    const fetchImpl = async (url: string, options: any) => {
      if (url.endsWith('/issues/1/comments') && options.method === 'POST') {
        const comment = { id: 7002, body: JSON.parse(options.body).body };
        comments.push(comment);
        return json(comment, 201);
      }
      if (url.endsWith('/issues/1') && options.method === 'PATCH') {
        return json({ message: 'validation failed' }, 422);
      }
      if (url.endsWith('/issues/comments/7002') && options.method === 'PATCH') {
        comments[0] = { id: 7002, body: JSON.parse(options.body).body };
        return json(comments[0]);
      }
      if (url.endsWith('/issues/1') && options.method === 'GET') {
        return json(issue);
      }
      if (url.includes('/issues/1/comments?') && options.method === 'GET') {
        return json(comments);
      }
      throw new Error(`unexpected GitHub request: ${options.method} ${url}`);
    };
    const provider = createGitHubIssueEffectProvider(
      attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
    );

    await assert.rejects(
      provider.effect({ action: ACTION, attempt: BOUND_ATTEMPT }),
      /github_issue_not_committed/,
    );

    const restartedProcess = createGitHubIssueEffectProvider(
      attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
    );
    const observation = await restartedProcess.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
      operation: ACTION.action_type,
    });

    assert.equal(observation.valid, true);
    assert.equal(observation.outcome, 'NOT_COMMITTED');
    assert.equal(observation.reason, 'github_provider_refused_before_effect');
  });

  it('keeps a prepared attempt ESCALATED after a genuine timeout and rejects marker substitution', async () => {
    const attributionKeys = crypto.generateKeyPairSync('ed25519');
    const issue = {
      number: ACTION.issue_number,
      title: 'before',
      body: 'before',
      updated_at: '2026-07-25T11:00:00.000Z',
    };
    const comments: Array<{ id: number; body: string }> = [];
    const fetchImpl = async (url: string, options: any) => {
      if (url.endsWith('/issues/1/comments') && options.method === 'POST') {
        const comment = { id: 7003, body: JSON.parse(options.body).body };
        comments.push(comment);
        return json(comment, 201);
      }
      if (url.endsWith('/issues/1') && options.method === 'PATCH') {
        throw Object.assign(new Error('provider timed out before acknowledgement'), {
          name: 'TimeoutError',
        });
      }
      if (url.endsWith('/issues/1') && options.method === 'GET') {
        return json(issue);
      }
      if (url.includes('/issues/1/comments?') && options.method === 'GET') {
        return json(comments);
      }
      throw new Error(`unexpected GitHub request: ${options.method} ${url}`);
    };
    const provider = createGitHubIssueEffectProvider(
      attributionProviderOptions(fetchImpl, attributionKeys.privateKey),
    );
    await assert.rejects(
      provider.effect({ action: ACTION, attempt: BOUND_ATTEMPT }),
      /github_issue_outcome_indeterminate/,
    );

    const exact = await provider.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: EXPECTED,
      operation: ACTION.action_type,
    });
    assert.equal(exact.outcome, 'ESCALATED');
    assert.equal(exact.reason, 'github_attempt_outcome_indeterminate');

    const substituted = await provider.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      action: ACTION,
      expected: {
        ...EXPECTED,
        request_digest: `sha256:${'9'.repeat(64)}`,
      },
      operation: ACTION.action_type,
    });
    assert.notEqual(substituted.outcome, 'COMMITTED');
    assert.notEqual(substituted.outcome, 'NOT_COMMITTED');
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
      attributionIssuerId: BOUND_ATTEMPT.issuer_id,
      attributionKeyId: 'actuator-evidence-key',
      attributionPrivateKey: ATTRIBUTION_KEYS.privateKey,
      targetDigest: TARGET_DIGEST,
      fetchImpl: async () => ({
        status: 200,
        redirected: true,
        url: 'https://attacker.example/redirected',
        headers: new Headers({ 'content-type': 'application/json' }),
        body,
      }),
    });

    await assert.rejects(
      provider.effect({ action: ACTION, attempt: BOUND_ATTEMPT }),
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
      attributionIssuerId: BOUND_ATTEMPT.issuer_id,
      attributionKeyId: 'actuator-evidence-key',
      attributionPrivateKey: ATTRIBUTION_KEYS.privateKey,
      targetDigest: TARGET_DIGEST,
      fetchImpl: async () => new Response('{}', {
        status: 201,
        headers: {
          'content-type': 'application/json',
          'content-length': String(600 * 1024),
        },
      }),
    });

    await assert.rejects(
      provider.effect({ action: ACTION, attempt: BOUND_ATTEMPT }),
      /github_response_too_large/,
    );
  });
});
