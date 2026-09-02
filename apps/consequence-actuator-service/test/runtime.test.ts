// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { type KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';

import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import { canonicalize } from '@emilia-protocol/gate';
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
  envelope: any,
  signer: { privateKey: KeyObject },
  overrides: Record<string, unknown> = {},
) {
  const attributionPayload = JSON.parse(canonicalize({
    '@version': 'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1',
    issuer_id: envelope.payload.issuer_id,
    tenant_id: envelope.payload.tenant_id,
    provider_id: 'github',
    provider_account_id: envelope.payload.provider_account_id,
    environment: 'production-smoke',
    request_digest: `sha256:${'1'.repeat(64)}`,
    attempt_id: envelope.payload.attempt_id,
    operation_id: envelope.payload.idempotency_key,
    caid: envelope.payload.caid,
    action_digest: envelope.payload.action_digest,
    target_digest: envelope.payload.target_digest,
    operation: envelope.payload.operation,
    nonce: envelope.payload.nonce,
    envelope_digest: digestAeb(envelope),
    effect_digest: digestAeb({
      domain: 'EP-GITHUB-ISSUE-EFFECT-v1',
      tenant_id: envelope.payload.tenant_id,
      provider_id: 'github',
      provider_account_id: envelope.payload.provider_account_id,
      environment: 'production-smoke',
      target_digest: envelope.payload.target_digest,
      target: {
        owner: ACTION.owner,
        repo: ACTION.repo,
        issue_number: ACTION.issue_number,
      },
      effect: {
        title: ACTION.title,
        body: ACTION.body,
      },
    }),
    issued_at: envelope.payload.issued_at,
  }));
  const attribution = {
    payload: attributionPayload,
    signature: {
      algorithm: 'Ed25519',
      key_id: 'control-envelope-key',
      value: crypto.sign(
        null,
        Buffer.concat([
          Buffer.from('EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1'),
          Buffer.from([0]),
          Buffer.from(canonicalize(attributionPayload)),
        ]),
        signer.privateKey,
      ).toString('base64url'),
    },
  };
  return {
    action: ACTION,
    attempt_id: 'attempt:0000000000000001',
    action_digest: ACTION_DIGEST,
    attribution,
    idempotency_key: 'operation:0000000000000001',
    envelope,
    ...overrides,
  };
}

async function harness({
  perform = async () => ({ provider_status: 200 }),
  observeProvider = async () => ({
    outcome: 'COMMITTED',
    reason: 'github_exact_attempt_committed',
    observed_at: new Date(NOW).toISOString(),
    ...{
      tenant_id: 'tenant:emilia',
      request_digest: `sha256:${'1'.repeat(64)}`,
      provider_id: 'github',
      provider_account_id: ACTION.owner,
      environment: 'production-smoke',
      attempt_id: 'attempt:0000000000000001',
      operation_id: 'operation:0000000000000001',
      caid: CAID,
      action_digest: ACTION_DIGEST,
      target_digest: TARGET_DIGEST,
      operation: ACTION.action_type,
      nonce: Buffer.alloc(24, 7).toString('base64url'),
      envelope_digest: `sha256:${'c'.repeat(64)}`,
      provider_attribution_digest: `sha256:${'d'.repeat(64)}`,
    },
    provider_observation_digest: `sha256:${'b'.repeat(64)}`,
  }),
  // `null` means "config supplies no probe at all" -- an `undefined` default
  // would be filled in by this destructure and could never express that case.
  readiness = async () => ({ ok: true }),
}: {
  perform?: (binding: Readonly<ConsequenceExecutionEnvelopePayload>) => Promise<unknown>;
  observeProvider?: () => Promise<Record<string, unknown>>;
  readiness?: (() => Promise<{ ok: boolean }>) | null;
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
    testOnly: true,
    tenantId: 'tenant:emilia',
    providerId: 'github',
    providerAccountId: ACTION.owner,
    environment: 'production-smoke',
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
    observeProvider,
    authenticateRequest: async () => true,
    ...(readiness === null ? {} : { readiness }),
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

    const result = await fixture.runtime.execute(executeBody(
      signed,
      fixture.envelopeSigner,
    ));

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
      executeBody(
        signEnvelope(fixture.envelopeSigner, payload),
        fixture.envelopeSigner,
      ),
    );

    assert.equal(result.status, 422);
    assert.equal(result.body.reason, 'attribution_binding_mismatch');
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

    const wrongAttempt = await fixture.runtime.execute(executeBody(
      signed,
      fixture.envelopeSigner,
      {
        attempt_id: 'attempt:0000000000000002',
      },
    ));
    assert.equal(wrongAttempt.status, 422);
    assert.equal(wrongAttempt.body.reason, 'attempt_mismatch');

    const wrongAction = await fixture.runtime.execute(executeBody(
      signed,
      fixture.envelopeSigner,
      {
        action: { ...ACTION, title: 'substituted action' },
      },
    ));
    assert.equal(wrongAction.status, 422);
    assert.equal(wrongAction.body.reason, 'action_refused');
    assert.equal(invocations, 0);
  });

  it('refuses request/provider attribution substitution before reservation or invocation', async () => {
    let invocations = 0;
    const fixture = await harness({
      perform: async () => {
        invocations += 1;
        return {};
      },
    });
    const payload = envelopePayload();
    const envelope = signEnvelope(fixture.envelopeSigner, payload);
    const body = executeBody(envelope, fixture.envelopeSigner);
    body.attribution.payload.request_digest = `sha256:${'9'.repeat(64)}`;

    const result = await fixture.runtime.execute(body);

    assert.equal(result.status, 422);
    assert.equal(result.body.reason, 'attribution_binding_mismatch');
    assert.equal(invocations, 0);
    assert.equal(fixture.store.size, 0);
  });

  it('refuses reconciliation environment substitution before provider observation', async () => {
    const fixture = await harness();

    const result = await fixture.runtime.observe({
      action: ACTION,
      operation: ACTION.action_type,
      expected: {
        operation_id: 'operation:0000000000000001',
        caid: CAID,
        action_digest: ACTION_DIGEST,
        tenant_id: 'tenant:emilia',
        provider_id: 'github',
        provider_account_id: ACTION.owner,
        environment: 'substituted-environment',
        attempt_id: 'attempt:0000000000000001',
        request_digest: `sha256:${'1'.repeat(64)}`,
      },
    });

    assert.equal(result.status, 422);
    assert.equal(result.body.reason, 'observation_binding_mismatch');
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
    const body = executeBody(
      signEnvelope(fixture.envelopeSigner, payload),
      fixture.envelopeSigner,
    );

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
    const body = executeBody(
      signEnvelope(fixture.envelopeSigner, payload),
      fixture.envelopeSigner,
    );

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

  it('signs the sent envelope nonce and digest plus request, environment, and provider-attribution digest', async () => {
    const fixture = await harness();
    const payload = envelopePayload();
    const body = executeBody(
      signEnvelope(fixture.envelopeSigner, payload),
      fixture.envelopeSigner,
    );

    const result = await fixture.runtime.execute(body);

    assert.equal(result.status, 200);
    assert.equal(result.body.observation.payload.nonce, payload.nonce);
    assert.equal(
      result.body.observation.payload.envelope_digest,
      digestAeb(body.envelope),
    );
    assert.equal(
      result.body.observation.payload.request_digest,
      body.attribution.payload.request_digest,
    );
    assert.equal(
      result.body.observation.payload.environment,
      body.attribution.payload.environment,
    );
    assert.equal(
      result.body.observation.payload.provider_attribution_digest,
      digestAeb(body.attribution),
    );
  });

  it('returns retryable unavailable evidence without manufacturing ESCALATED', async () => {
    const fixture = await harness({
      observeProvider: async () => {
        throw new Error('transient_provider_store_unavailable');
      },
    });

    const result = await fixture.runtime.observe({
      action: ACTION,
      operation: ACTION.action_type,
      expected: {
        operation_id: 'operation:0000000000000001',
        caid: CAID,
        action_digest: ACTION_DIGEST,
        tenant_id: 'tenant:emilia',
        provider_id: 'github',
        provider_account_id: ACTION.owner,
        environment: 'production-smoke',
        attempt_id: 'attempt:0000000000000001',
        request_digest: `sha256:${'1'.repeat(64)}`,
      },
    });

    assert.equal(result.status, 503);
    assert.equal(result.body.reason, 'provider_observation_unavailable');
    assert.equal(Object.hasOwn(result.body, 'outcome'), false);
  });
});

describe('actuator readiness and bind defaults', () => {
  it('refuses readiness with a named reason when no probe is configured', async () => {
    // A config that omits the readiness probe proves nothing about the durable
    // dependencies, so /v1/ready must refuse rather than answer 200 and let the
    // startup gate in server.ts (which only checks `status !== 200`) pass
    // vacuously.
    const fixture = await harness({ readiness: null });
    const result = await fixture.runtime.ready();
    assert.equal(result.status, 503);
    assert.equal(result.body.status, 'unavailable');
    assert.equal(result.body.reason, 'readiness_probe_not_configured');
  });

  it('answers ready only when the configured probe says ok', async () => {
    const ok = await harness({ readiness: async () => ({ ok: true }) });
    assert.equal((await ok.runtime.ready()).status, 200);
    const notOk = await harness({ readiness: async () => ({ ok: false }) });
    const refusedResult = await notOk.runtime.ready();
    assert.equal(refusedResult.status, 503);
    assert.equal(refusedResult.body.reason, 'readiness_probe_refused');
  });

  it('binds the loopback interface by default and never 0.0.0.0 for HOST=""', async () => {
    const { listenSettings } = await import('../src/server.ts');
    assert.equal(listenSettings({}).host, '127.0.0.1');
    assert.equal(listenSettings({}).port, 8080);
    // `||` turned an explicitly empty HOST into a bind on every interface.
    // An empty HOST is a configuration error, not a widening.
    assert.throws(() => listenSettings({ HOST: '' }), /listen_host_invalid/);
    assert.equal(listenSettings({ HOST: '0.0.0.0' }).host, '0.0.0.0');
    assert.throws(() => listenSettings({ HOST: 'bad\nhost' }), /listen_host_invalid/);
    assert.throws(() => listenSettings({ PORT: '0' }), /listen_port_invalid/);
  });
});
