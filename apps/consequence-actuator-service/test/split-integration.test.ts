// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { afterEach, it } from 'node:test';

import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import { computeCaid } from '../../../caid/impl/js/caid.mjs';
import { createMemoryConsequenceActuatorStore } from '@emilia-protocol/gate/consequence-actuator';
import { createConsequenceActuatorClient } from '../../consequence-control-service/src/actuator-client.ts';
import { createConsequenceActuatorObservationSigner } from '../src/observation.ts';
import { createConsequenceActuatorRuntime } from '../src/runtime.ts';
import { createHttpServer } from '../src/server.ts';

const ACTION = {
  action_type: 'github.issue.update.1',
  owner: 'emiliaprotocol',
  repo: 'gate-smoke-target',
  issue_number: 1,
  title: 'split deployment integration',
  body: 'exact bytes',
};
const ACTION_DIGEST = digestAeb(ACTION);
const CAID = computeCaid(ACTION, {
  suite: 'jcs-sha256',
  definitions: [{
    action_type: ACTION.action_type,
    required_fields: [
      { name: 'owner', type: 'string' },
      { name: 'repo', type: 'string' },
      { name: 'issue_number', type: 'integer' },
      { name: 'title', type: 'string' },
      { name: 'body', type: 'string' },
    ],
    optional_fields: [],
  }],
}).caid!;
const TARGET_DIGEST = digestAeb({
  domain: 'EP-CONSEQUENCE-ACTUATOR-TARGET-v1',
  provider_id: 'github',
  provider_account_id: ACTION.owner,
  target: {
    kind: 'github.issue',
    owner: ACTION.owner,
    repo: ACTION.repo,
    issue_number: ACTION.issue_number,
  },
});

const servers = new Set<ReturnType<typeof createHttpServer>>();

afterEach(async () => {
  await Promise.all([...servers].map((server) => new Promise<void>((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  })));
  servers.clear();
});

it('executes and reconciles across the authenticated split deployment boundary', async () => {
  const envelopeKeys = crypto.generateKeyPairSync('ed25519');
  const evidenceKeys = crypto.generateKeyPairSync('ed25519');
  const now = Date.parse('2026-07-25T12:00:00.000Z');
  const runtime = createConsequenceActuatorRuntime({
    testOnly: true,
    tenantId: 'tenant:emilia',
    providerId: 'github',
    providerAccountId: ACTION.owner,
    environment: 'production-smoke',
    targetDigest: TARGET_DIGEST,
    envelopeIssuerId: 'consequence-control',
    envelopeKeyId: 'control-envelope-key',
    envelopePublicKey: envelopeKeys.publicKey,
    store: createMemoryConsequenceActuatorStore(),
    normalizeAction(candidate) {
      if (digestAeb(candidate) !== ACTION_DIGEST) throw new Error('action_refused');
      return {
        action: structuredClone(ACTION),
        actionDigest: ACTION_DIGEST,
        caid: CAID,
        targetDigest: TARGET_DIGEST,
      };
    },
    operations: {
      [ACTION.action_type]: async () => ({
        provider_status: 200,
        provider_reference: 'github:issue:emiliaprotocol/gate-smoke-target#1',
      }),
    },
    observationSigner: createConsequenceActuatorObservationSigner({
      issuerId: 'consequence-actuator',
      keyId: 'actuator-evidence-key',
      privateKey: evidenceKeys.privateKey,
    }),
    reconciliationEvidence: {
      privateKey: evidenceKeys.privateKey,
      keyId: 'actuator-evidence-key',
    },
    observeProvider: async () => ({
      outcome: 'ESCALATED',
      reason: 'github_attempt_attribution_unavailable',
      observed_at: new Date(now).toISOString(),
      provider_observation_digest: `sha256:${'b'.repeat(64)}`,
    }),
    authenticateRequest: async (authorization) => (
      authorization === 'Bearer split-test-token-000000000000000000000000000'
    ),
    readiness: async () => ({ ok: true }),
    now: () => now,
  });
  const server = createHttpServer(runtime);
  servers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert(address && typeof address === 'object');
  const client = createConsequenceActuatorClient({
    endpoint: `http://127.0.0.1:${address.port}`,
    authorization: 'split-test-token-000000000000000000000000000',
    identityTokenAudience: 'https://actuator.test.run.app',
    identityTokenProvider: {
      async fetchIdToken(audience: string) {
        assert.equal(audience, 'https://actuator.test.run.app');
        return 'test-header.test-payload.test-signature';
      },
    },
    tenantId: 'tenant:emilia',
    providerId: 'github',
    providerAccountId: ACTION.owner,
    environment: 'production-smoke',
    owner: ACTION.owner,
    repo: ACTION.repo,
    issueNumber: ACTION.issue_number,
    operation: ACTION.action_type,
    envelopeIssuerId: 'consequence-control',
    envelopeKeyId: 'control-envelope-key',
    envelopePrivateKey: envelopeKeys.privateKey,
    observationIssuerId: 'consequence-actuator',
    observationKeyId: 'actuator-evidence-key',
    observationPublicKey: evidenceKeys.publicKey,
    allowInsecureLoopback: true,
    now: () => now,
  });
  const attempt = {
    tenant_id: 'tenant:emilia',
    provider_id: 'github',
    provider_account_id: ACTION.owner,
    environment: 'production-smoke',
    attempt_id: 'attempt:split-1',
    request_digest: `sha256:${'c'.repeat(64)}`,
  };
  const proposal = {
    operation_id: 'operation:split-1',
    caid: CAID,
    aeb_action_digest: ACTION_DIGEST,
    consequence: {
      tenant_id: attempt.tenant_id,
      provider_id: attempt.provider_id,
      provider_account_id: attempt.provider_account_id,
      environment: attempt.environment,
      request_digest: attempt.request_digest,
    },
  };

  const executed = await client.effect({ action: ACTION, proposal, attempt });
  assert.equal(executed.provider_status, 200);
  assert.match(executed.provider_reference, /^github:issue:/);

  const reconciled = await client.verifyProviderEvidence({
    evidence: { kind: 'consequence-actuator-observation-v1' },
    expected: {
      operation_id: proposal.operation_id,
      caid: proposal.caid,
      action_digest: ACTION_DIGEST,
      tenant_id: attempt.tenant_id,
      request_digest: attempt.request_digest,
      provider_id: attempt.provider_id,
      provider_account_id: attempt.provider_account_id,
      environment: attempt.environment,
      attempt_id: attempt.attempt_id,
    },
    action: ACTION,
  });
  assert.equal(reconciled.valid, true);
  assert.equal(reconciled.outcome, 'ESCALATED');
  assert.equal(reconciled.attempt_id, attempt.attempt_id);
});
