// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import { canonicalize } from '@emilia-protocol/gate';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';

import { createGitHubIssueEffectProvider } from '../src/github-app.ts';

const NOW = Date.parse('2026-07-25T12:00:00.000Z');
const ACTION = Object.freeze({
  action_type: 'github.issue.update.1',
  owner: 'emiliaprotocol',
  repo: 'gate-smoke-target',
  issue_number: 1,
  title: 'EMILIA consequence-control smoke',
  body: 'exact effect body',
});
const EXPECTED = Object.freeze({
  operation_id: 'operation:0000000000000001',
  caid: `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`,
  action_digest: digestAeb(ACTION),
  tenant_id: 'tenant:emilia',
  provider_id: 'github',
  provider_account_id: ACTION.owner,
  environment: 'production-smoke',
  attempt_id: 'attempt:0000000000000001',
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
const ENVELOPE_DIGEST = `sha256:${'3'.repeat(64)}`;
const NONCE = Buffer.alloc(24, 7).toString('base64url');
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
const ATTRIBUTION_KEYS = crypto.generateKeyPairSync('ed25519');

function signedAttribution(overrides: Record<string, unknown> = {}) {
  const payload = JSON.parse(canonicalize({
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
    nonce: NONCE,
    envelope_digest: ENVELOPE_DIGEST,
    effect_digest: EFFECT_DIGEST,
    issued_at: new Date(NOW - 1_000).toISOString(),
    ...overrides,
  }));
  return JSON.parse(canonicalize({
    payload,
    signature: {
      algorithm: 'Ed25519',
      key_id: 'control-envelope-key',
      value: crypto.sign(
        null,
        Buffer.concat([
          Buffer.from('EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1'),
          Buffer.from([0]),
          Buffer.from(canonicalize(payload)),
        ]),
        ATTRIBUTION_KEYS.privateKey,
      ).toString('base64url'),
    },
  }));
}

function memoryProviderRecordStore({
  failWrite = false,
  failRead = false,
  returnAnyRecord = false,
}: {
  failWrite?: boolean;
  failRead?: boolean;
  returnAnyRecord?: boolean;
} = {}) {
  const records = new Map<string, { record: any; record_digest: string }>();
  const key = (value: any) => canonicalize([
    value.tenant_id,
    value.provider_id,
    value.provider_account_id,
    value.environment,
    value.attempt_id,
    value.request_digest,
  ]);
  return {
    records,
    async write(value: { record: any; record_digest: string }) {
      if (failWrite) throw new Error('provider_record_store_unavailable');
      const binding = value.record.payload.provider_attribution.payload;
      const recordKey = key(binding);
      const current = records.get(recordKey);
      if (current && canonicalize(current) !== canonicalize(value)) {
        throw new Error('provider_record_conflict');
      }
      records.set(recordKey, structuredClone(value));
      return structuredClone(value);
    },
    async read(expected: any) {
      if (failRead) throw new Error('provider_record_store_unavailable');
      if (returnAnyRecord) {
        const first = records.values().next().value;
        return first ? structuredClone(first) : null;
      }
      const value = records.get(key(expected));
      return value ? structuredClone(value) : null;
    },
  };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function provider(
  fetchImpl: (url: string, options: any) => Promise<any>,
  providerRecordStore: any,
  options: Record<string, unknown> = {},
) {
  return createGitHubIssueEffectProvider({
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    tokenProvider: {
      getToken: async () => 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
    },
    attributionIssuerId: 'consequence-control',
    attributionKeyId: 'actuator-evidence-key',
    attributionPrivateKey: ATTRIBUTION_KEYS.privateKey,
    providerAttributionKeyId: 'control-envelope-key',
    providerAttributionPublicKey: ATTRIBUTION_KEYS.publicKey,
    targetDigest: TARGET_DIGEST,
    providerRecordStore,
    fetchImpl,
    now: () => NOW,
    ...options,
  });
}

function exactGitHubResponse() {
  return {
    number: ACTION.issue_number,
    title: ACTION.title,
    body: ACTION.body,
  };
}

describe('hostile private GitHub provider-record boundary', () => {
  it('performs only the approved issue PATCH and creates no public comments', async () => {
    const store = memoryProviderRecordStore();
    const calls: Array<{ url: string; method: string }> = [];
    const value = provider(async (url, options) => {
      calls.push({ url, method: options.method });
      assert.equal(url.endsWith('/issues/1'), true);
      assert.equal(options.method, 'PATCH');
      return json(exactGitHubResponse());
    }, store);

    const result = await value.effect({
      action: ACTION,
      attempt: signedAttribution(),
    });

    assert.equal(result.provider_status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls.some(({ url }) => url.includes('/comments')), false);
    assert.equal(store.records.size, 1);
  });

  it('never returns success when the terminal provider-record write fails', async () => {
    const store = memoryProviderRecordStore({ failWrite: true });
    const value = provider(
      async () => json(exactGitHubResponse()),
      store,
    );

    await assert.rejects(
      value.effect({ action: ACTION, attempt: signedAttribution() }),
      /github_provider_record_store_unavailable/,
    );
    assert.equal(store.records.size, 0);
  });

  it('requires the provider response title and body to match exactly', async () => {
    for (const response of [
      { ...exactGitHubResponse(), title: `${ACTION.title} ` },
      { ...exactGitHubResponse(), body: `${ACTION.body}\n` },
    ]) {
      const store = memoryProviderRecordStore();
      const value = provider(async () => json(response), store);

      await assert.rejects(
        value.effect({ action: ACTION, attempt: signedAttribution() }),
        /github_issue_outcome_indeterminate/,
      );
      assert.equal(store.records.size, 0);
    }
  });

  it('reconciles COMMITTED after exact GitHub 200 was durably recorded but the actuator response was lost', async () => {
    const store = memoryProviderRecordStore();
    const first = provider(
      async () => json(exactGitHubResponse()),
      store,
      { forceIndeterminateAfterCommit: true },
    );

    await assert.rejects(
      first.effect({ action: ACTION, attempt: signedAttribution() }),
      /github_issue_outcome_indeterminate/,
    );

    const restarted = provider(async () => {
      throw new Error('reconciliation_must_not_call_github');
    }, store);
    const observation = await restarted.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      expected: EXPECTED,
      action: ACTION,
      operation: ACTION.action_type,
    });

    assert.equal(observation.valid, true);
    assert.equal(observation.outcome, 'COMMITTED');
    assert.equal(observation.reason, 'github_exact_attempt_committed');
    assert.equal(observation.envelope_digest, ENVELOPE_DIGEST);
    assert.equal(observation.nonce, NONCE);
    assert.equal(
      observation.provider_attribution_digest,
      digestAeb(signedAttribution()),
    );
  });

  it('keeps a genuinely lost GitHub PATCH response retryably unavailable with no terminal attribution', async () => {
    const store = memoryProviderRecordStore();
    let providerState = 'before';
    const first = provider(async () => {
      providerState = 'after';
      throw Object.assign(new Error('socket closed after GitHub mutation'), {
        name: 'TimeoutError',
      });
    }, store);

    await assert.rejects(
      first.effect({ action: ACTION, attempt: signedAttribution() }),
      /github_issue_outcome_indeterminate/,
    );
    assert.equal(providerState, 'after');
    assert.equal(store.records.size, 0);

    const restarted = provider(async () => {
      throw new Error('reconciliation_must_not_call_github');
    }, store);
    const observation = await restarted.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      expected: EXPECTED,
      action: ACTION,
      operation: ACTION.action_type,
    });

    assert.equal(observation.valid, false);
    assert.equal(observation.reason, 'provider_evidence_unavailable');
  });

  it('refuses old-envelope and cross-attempt provider-record replay', async () => {
    const store = memoryProviderRecordStore({ returnAnyRecord: true });
    const value = provider(
      async () => json(exactGitHubResponse()),
      store,
    );
    await value.effect({ action: ACTION, attempt: signedAttribution() });

    const replayed = await value.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      expected: {
        ...EXPECTED,
        attempt_id: 'attempt:0000000000000002',
      },
      action: ACTION,
      operation: ACTION.action_type,
    });

    assert.equal(replayed.valid, false);
    assert.equal(replayed.reason, 'provider_evidence_binding_mismatch');
  });

  it('refuses tenant/account/request/environment substitution instead of copying expectations', async () => {
    const store = memoryProviderRecordStore({ returnAnyRecord: true });
    const value = provider(
      async () => json(exactGitHubResponse()),
      store,
    );
    await value.effect({ action: ACTION, attempt: signedAttribution() });

    for (const expected of [
      { ...EXPECTED, request_digest: `sha256:${'9'.repeat(64)}` },
      { ...EXPECTED, environment: 'substituted-environment' },
      { ...EXPECTED, tenant_id: 'tenant:attacker' },
      { ...EXPECTED, provider_account_id: 'attacker' },
    ]) {
      const substituted = await value.verifyProviderEvidence({
        evidence: { kind: 'github-issue-observation-v1' },
        expected,
        action: ACTION,
        operation: ACTION.action_type,
      });
      assert.equal(substituted.valid, false);
      assert.equal(
        substituted.reason,
        'provider_evidence_binding_mismatch',
      );
    }
  });

  it('keeps transient provider-record observation failure retryable', async () => {
    const value = provider(
      async () => {
        throw new Error('github_must_not_be_called');
      },
      memoryProviderRecordStore({ failRead: true }),
    );

    const observation = await value.verifyProviderEvidence({
      evidence: { kind: 'github-issue-observation-v1' },
      expected: EXPECTED,
      action: ACTION,
      operation: ACTION.action_type,
    });

    assert.equal(observation.valid, false);
    assert.equal(observation.reason, 'provider_evidence_unavailable');
  });
});
