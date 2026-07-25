// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';

import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import { computeCaid } from '../../../caid/impl/js/caid.mjs';
import {
  CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
  createMemoryConsequenceActuatorStore,
  signConsequenceExecutionEnvelope,
  type ConsequenceExecutionEnvelopePayload,
} from '../../../packages/gate/src/consequence-actuator.ts';
import { createConsequenceActuatorObservationSigner } from '../src/observation.ts';
import { createConsequenceActuatorRuntime } from '../src/runtime.ts';

const NOW = Date.parse('2026-07-25T12:00:00.000Z');
const ACTION = Object.freeze({
  action_type: 'github.issue.update.1',
  owner: 'emiliaprotocol',
  repo: 'gate-smoke-target',
  issue_number: 1,
  title: 'EMILIA consequence-control smoke',
  body: 'exact effect body',
});
const ACTION_DEFINITION = {
  action_type: ACTION.action_type,
  required_fields: [
    { name: 'owner', type: 'string' },
    { name: 'repo', type: 'string' },
    { name: 'issue_number', type: 'integer' },
    { name: 'title', type: 'string' },
    { name: 'body', type: 'string' },
  ],
  optional_fields: [],
};
const CAID = computeCaid(ACTION, {
  suite: 'jcs-sha256',
  definitions: [ACTION_DEFINITION],
}).caid!;
const ACTION_DIGEST = digestAeb(ACTION);
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

function envelopePayload(
  overrides: Partial<ConsequenceExecutionEnvelopePayload> = {},
): ConsequenceExecutionEnvelopePayload {
  return {
    '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
    issuer_id: 'consequence-control',
    tenant_id: 'tenant:emilia',
    attempt_id: 'attempt:0000000000000001',
    action_digest: ACTION_DIGEST,
    caid: CAID,
    provider_account_id: ACTION.owner,
    target_digest: TARGET_DIGEST,
    operation: ACTION.action_type,
    idempotency_key: 'operation:0000000000000001',
    nonce: crypto.randomBytes(24).toString('base64url'),
    issued_at: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 30_000).toISOString(),
    ...overrides,
  };
}

function signEnvelope(
  signer: { privateKey: KeyObject; publicKey: KeyObject },
  payload: ConsequenceExecutionEnvelopePayload,
) {
  return signConsequenceExecutionEnvelope(payload, {
    privateKey: signer.privateKey,
    keyId: 'control-envelope-key',
  });
}

function executeBody(
  envelope: unknown,
  overrides: Record<string, unknown> = {},
) {
  return {
    action: ACTION,
    attempt_id: 'attempt:0000000000000001',
    action_digest: ACTION_DIGEST,
    idempotency_key: 'operation:0000000000000001',
    envelope,
    ...overrides,
  };
}

async function harness({
  perform = async () => ({ provider_status: 200 }),
}: {
  perform?: (binding: Readonly<ConsequenceExecutionEnvelopePayload>) => Promise<unknown>;
} = {}) {
  const envelopeSigner = crypto.generateKeyPairSync('ed25519');
  const evidenceSigner = crypto.generateKeyPairSync('ed25519');
  const store = createMemoryConsequenceActuatorStore();
  const observationSigner = createConsequenceActuatorObservationSigner({
    issuerId: 'consequence-actuator',
    keyId: 'actuator-evidence-key',
    privateKey: evidenceSigner.privateKey,
  });
  const runtime = createConsequenceActuatorRuntime({
    tenantId: 'tenant:emilia',
    providerId: 'github',
    providerAccountId: ACTION.owner,
    targetDigest: TARGET_DIGEST,
    envelopeIssuerId: 'consequence-control',
    envelopeKeyId: 'control-envelope-key',
    envelopePublicKey: envelopeSigner.publicKey,
    store,
    normalizeAction(candidate) {
      if (digestAeb(candidate) !== ACTION_DIGEST) {
        throw new Error('action_refused');
      }
      return {
        action: structuredClone(candidate as typeof ACTION),
        actionDigest: ACTION_DIGEST,
        caid: CAID,
        targetDigest: TARGET_DIGEST,
      };
    },
    operations: {
      [ACTION.action_type]: ({ binding }) => perform(binding),
    },
    observationSigner,
    reconciliationEvidence: {
      privateKey: evidenceSigner.privateKey,
      keyId: 'actuator-evidence-key',
    },
    observeProvider: async () => ({
      outcome: 'ESCALATED',
      reason: 'github_attempt_attribution_unavailable',
      observed_at: new Date(NOW).toISOString(),
      provider_observation_digest: `sha256:${'b'.repeat(64)}`,
    }),
    authenticateRequest: async () => true,
    readiness: async () => ({ ok: true }),
    now: () => NOW,
  });
  return {
    runtime,
    store,
    envelopeSigner,
    evidenceSigner,
  };
}

describe('hostile actuator execution boundary', () => {
  it('refuses forged envelopes before provider invocation', async () => {
    let invocations = 0;
    const fixture = await harness({
      perform: async () => {
        invocations += 1;
        return {};
      },
    });
    const payload = envelopePayload();
    const signed = structuredClone(signEnvelope(fixture.envelopeSigner, payload));
    signed.signature.value =
      `${signed.signature.value.startsWith('A') ? 'B' : 'A'}`
      + signed.signature.value.slice(1);

    const result = await fixture.runtime.execute(executeBody(signed));

    assert.equal(result.status, 422);
    assert.equal(result.body.reason, 'signature_invalid');
    assert.equal(invocations, 0);
  });

  it('refuses a correctly signed cross-target envelope', async () => {
    let invocations = 0;
    const fixture = await harness({
      perform: async () => {
        invocations += 1;
        return {};
      },
    });
    const payload = envelopePayload({
      target_digest: `sha256:${'c'.repeat(64)}`,
    });

    const result = await fixture.runtime.execute(
      executeBody(signEnvelope(fixture.envelopeSigner, payload)),
    );

    assert.equal(result.status, 422);
    assert.equal(result.body.reason, 'target_mismatch');
    assert.equal(invocations, 0);
  });

  it('refuses wrong live attempts and action substitution', async () => {
    let invocations = 0;
    const fixture = await harness({
      perform: async () => {
        invocations += 1;
        return {};
      },
    });
    const payload = envelopePayload();
    const signed = signEnvelope(fixture.envelopeSigner, payload);

    const wrongAttempt = await fixture.runtime.execute(executeBody(signed, {
      attempt_id: 'attempt:0000000000000002',
    }));
    assert.equal(wrongAttempt.status, 422);
    assert.equal(wrongAttempt.body.reason, 'attempt_mismatch');

    const wrongAction = await fixture.runtime.execute(executeBody(signed, {
      action: { ...ACTION, title: 'substituted action' },
    }));
    assert.equal(wrongAction.status, 422);
    assert.equal(wrongAction.body.reason, 'action_refused');
    assert.equal(invocations, 0);
  });

  it('allows one winner under a replay race and permanently refuses replay', async () => {
    let invocations = 0;
    const fixture = await harness({
      perform: async () => {
        invocations += 1;
        await Promise.resolve();
        return { provider_status: 200 };
      },
    });
    const payload = envelopePayload();
    const body = executeBody(signEnvelope(fixture.envelopeSigner, payload));

    const raced = await Promise.all([
      fixture.runtime.execute(body),
      fixture.runtime.execute(body),
      fixture.runtime.execute(body),
    ]);

    assert.equal(raced.filter((result) => result.status === 200).length, 1);
    assert.equal(raced.filter((result) => result.status === 409).length, 2);
    assert.equal(invocations, 1);
    const replay = await fixture.runtime.execute(body);
    assert.equal(replay.status, 409);
    assert.equal(replay.body.reason, 'envelope_replayed');
  });

  it('fences a network timeout after effect as INDETERMINATE with no blind replay', async () => {
    let providerState = 'before';
    let invocations = 0;
    const fixture = await harness({
      perform: async () => {
        invocations += 1;
        providerState = 'after';
        throw Object.assign(new Error('response acknowledgement timed out'), {
          name: 'TimeoutError',
        });
      },
    });
    const payload = envelopePayload();
    const body = executeBody(signEnvelope(fixture.envelopeSigner, payload));

    const first = await fixture.runtime.execute(body);

    assert.equal(providerState, 'after');
    assert.equal(first.status, 202);
    assert.equal(first.body.outcome, 'INDETERMINATE');
    assert.equal(first.body.ok, false);
    assert.equal(fixture.store.snapshot(payload.tenant_id, payload.nonce)?.outcome, 'INDETERMINATE');

    const replay = await fixture.runtime.execute(body);
    assert.equal(replay.status, 409);
    assert.equal(replay.body.reason, 'envelope_replayed');
    assert.equal(invocations, 1);
  });
});
