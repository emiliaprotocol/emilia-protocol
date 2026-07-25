// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import { canonicalize } from '@emilia-protocol/gate';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  consequenceActuatorTargetDigest,
  createConsequenceActuatorClient,
  createGoogleCloudIdentityTokenProvider,
} from '../src/actuator-client.js';

const NOW = Date.parse('2026-07-25T12:00:00.000Z');
const IDENTITY_AUDIENCE = 'https://emilia-consequence-actuator-abc-uc.a.run.app';
const IDENTITY_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJlbWlsaWEifQ.signature';
const OBSERVATION_DOMAIN = 'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';
const ACTION = Object.freeze({
  action_type: 'github.issue.update.1',
  owner: 'emiliaprotocol',
  repo: 'gate-smoke-target',
  issue_number: 1,
  title: 'EMILIA consequence-control smoke',
  body: 'exact effect body',
});
const ACTION_DIGEST = digestAeb(ACTION);
const CAID = `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`;
const TARGET_DIGEST = consequenceActuatorTargetDigest({
  providerId: 'github',
  providerAccountId: ACTION.owner,
  owner: ACTION.owner,
  repo: ACTION.repo,
  issueNumber: ACTION.issue_number,
});
const ATTEMPT = Object.freeze({
  tenant_id: 'tenant:emilia',
  provider_id: 'github',
  provider_account_id: ACTION.owner,
  environment: 'production-smoke',
  attempt_id: 'attempt:0000000000000001',
  request_digest: `sha256:${'1'.repeat(64)}`,
});
const PROPOSAL = Object.freeze({
  operation_id: 'operation:0000000000000001',
  caid: CAID,
  action: ACTION,
  aeb_action_digest: ACTION_DIGEST,
  consequence: {
    tenant_id: ATTEMPT.tenant_id,
    provider_account_id: ATTEMPT.provider_account_id,
  },
});
const EXPECTED = Object.freeze({
  operation_id: PROPOSAL.operation_id,
  caid: CAID,
  action_digest: ACTION_DIGEST,
  tenant_id: ATTEMPT.tenant_id,
  request_digest: ATTEMPT.request_digest,
  provider_id: ATTEMPT.provider_id,
  provider_account_id: ATTEMPT.provider_account_id,
  environment: ATTEMPT.environment,
  attempt_id: ATTEMPT.attempt_id,
});

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function signObservationEvidence({ observation, privateKey, keyId }) {
  const evidence = JSON.parse(canonicalize({
    ...observation,
    evidence_digest: digestAeb({
      domain: OBSERVATION_DOMAIN,
      evidence: observation,
    }),
  }));
  const signatureInput = Buffer.concat([
    Buffer.from(OBSERVATION_DOMAIN, 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalize(evidence), 'utf8'),
  ]);
  return {
    evidence,
    signature: {
      algorithm: 'Ed25519',
      key_id: keyId,
      value: crypto.sign(null, signatureInput, privateKey).toString('base64url'),
    },
  };
}

function observation(evidenceSigner, overrides = {}) {
  return signObservationEvidence({
    observation: {
      '@version': 'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1',
      evidence_id: `observation:${'a'.repeat(64)}`,
      observed_at: new Date(NOW).toISOString(),
      outcome: 'ESCALATED',
      reason: 'github_attempt_attribution_unavailable',
      ...EXPECTED,
      target_digest: TARGET_DIGEST,
      operation: ACTION.action_type,
      provider_observation_digest: `sha256:${'b'.repeat(64)}`,
      ...overrides,
    },
    privateKey: evidenceSigner.privateKey,
    keyId: 'actuator-evidence-key',
  });
}

function client(fetchImpl, {
  envelopeSigner = crypto.generateKeyPairSync('ed25519'),
  evidenceSigner = crypto.generateKeyPairSync('ed25519'),
  endpoint = 'http://127.0.0.1:8789',
  identityTokenAudience = IDENTITY_AUDIENCE,
  allowInsecureLoopback = true,
  identityTokenProvider = {
    async fetchIdToken(audience) {
      assert.equal(audience, IDENTITY_AUDIENCE);
      return IDENTITY_TOKEN;
    },
  },
} = {}) {
  return {
    envelopeSigner,
    evidenceSigner,
    value: createConsequenceActuatorClient({
      endpoint,
      authorization: 'actuator-api-token-000000000000000000000000000000',
      tenantId: ATTEMPT.tenant_id,
      providerId: ATTEMPT.provider_id,
      providerAccountId: ATTEMPT.provider_account_id,
      environment: ATTEMPT.environment,
      owner: ACTION.owner,
      repo: ACTION.repo,
      issueNumber: ACTION.issue_number,
      operation: ACTION.action_type,
      envelopeIssuerId: 'consequence-control',
      envelopeKeyId: 'control-envelope-key',
      envelopePrivateKey: envelopeSigner.privateKey,
      observationIssuerId: 'consequence-actuator',
      observationKeyId: 'actuator-evidence-key',
      observationPublicKey: evidenceSigner.publicKey,
      identityTokenAudience,
      identityTokenProvider,
      requestTimeoutMs: 1000,
      fetchImpl,
      now: () => NOW,
      randomBytes: () => Buffer.alloc(24, 7),
      allowInsecureLoopback,
    }),
  };
}

describe('decision-plane actuator client', () => {
  it('pins the origin and signs a short-lived exact execution envelope', async () => {
    let captured;
    const envelopeSigner = crypto.generateKeyPairSync('ed25519');
    const fixture = client(async (url, options) => {
      captured = { url, options, body: JSON.parse(options.body) };
      return response({
        status: 'committed',
        result: { provider_status: 200 },
        envelope_digest: `sha256:${'c'.repeat(64)}`,
      });
    }, { envelopeSigner });

    await assert.rejects(fixture.value.effect({
      action: ACTION,
      proposal: {
        ...PROPOSAL,
        consequence: {
          ...PROPOSAL.consequence,
          provider_id: ATTEMPT.provider_id,
          environment: ATTEMPT.environment,
          request_digest: ATTEMPT.request_digest,
        },
      },
      authorization: { allow: true },
      attempt: ATTEMPT,
    }));
    assert.equal(captured.url, 'http://127.0.0.1:8789/v1/execute');
    assert.equal(captured.options.redirect, 'error');
    const requestHeaders = new Headers(captured.options.headers);
    assert.equal(
      requestHeaders.get('authorization'),
      'Bearer actuator-api-token-000000000000000000000000000000',
    );
    assert.equal(
      requestHeaders.get('x-serverless-authorization'),
      `Bearer ${IDENTITY_TOKEN}`,
    );
    assert.equal(captured.body.envelope.payload.target_digest, TARGET_DIGEST);
    assert.equal(captured.body.envelope.payload.operation, ACTION.action_type);
    assert.equal(captured.body.envelope.payload.attempt_id, ATTEMPT.attempt_id);
    assert.equal(captured.body.envelope.payload.action_digest, ACTION_DIGEST);
    assert.equal(
      captured.body.attribution.payload.request_digest,
      ATTEMPT.request_digest,
    );
    assert.equal(
      captured.body.attribution.payload.envelope_digest,
      digestAeb(captured.body.envelope),
    );
    assert.equal(
      captured.body.attribution.payload.attempt_id,
      ATTEMPT.attempt_id,
    );
    assert.equal(
      captured.body.attribution.payload.operation_id,
      PROPOSAL.operation_id,
    );
    assert.equal(
      Date.parse(captured.body.envelope.payload.expires_at)
        - Date.parse(captured.body.envelope.payload.issued_at),
      30_000,
    );
    const signedBytes = Buffer.concat([
      Buffer.from('EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1'),
      Buffer.from([0]),
      Buffer.from(canonicalize(captured.body.envelope.payload)),
    ]);
    assert.equal(crypto.verify(
      null,
      signedBytes,
      envelopeSigner.publicKey,
      Buffer.from(captured.body.envelope.signature.value, 'base64url'),
    ), true);
    const attributionBytes = Buffer.concat([
      Buffer.from('EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1'),
      Buffer.from([0]),
      Buffer.from(canonicalize(captured.body.attribution.payload)),
    ]);
    assert.equal(crypto.verify(
      null,
      attributionBytes,
      envelopeSigner.publicKey,
      Buffer.from(captured.body.attribution.signature.value, 'base64url'),
    ), true);
    assert.equal(Object.hasOwn(captured.body, 'url'), false);
    assert.equal(Object.hasOwn(captured.body, 'key'), false);
  });

  it('refuses forged observation evidence under the pinned verification key', async () => {
    const evidenceSigner = crypto.generateKeyPairSync('ed25519');
    const attacker = crypto.generateKeyPairSync('ed25519');
    const fixture = client(async () => response(
      observation(attacker),
    ), { evidenceSigner });

    const verified = await fixture.value.verifyProviderEvidence({
      evidence: { kind: 'consequence-actuator-observation-v1' },
      expected: EXPECTED,
      action: ACTION,
    });

    assert.equal(verified.valid, false);
    assert.equal(verified.reason, 'provider_evidence_signature_invalid');
  });

  it('refuses signed evidence substituted across attempt or action bindings', async () => {
    const evidenceSigner = crypto.generateKeyPairSync('ed25519');
    for (const overrides of [
      { attempt_id: 'attempt:0000000000000002' },
      { action_digest: `sha256:${'d'.repeat(64)}` },
    ]) {
      const fixture = client(async () => response(
        observation(evidenceSigner, overrides),
      ), { evidenceSigner });
      const verified = await fixture.value.verifyProviderEvidence({
        evidence: { kind: 'consequence-actuator-observation-v1' },
        expected: EXPECTED,
        action: ACTION,
      });
      assert.equal(verified.valid, false);
      assert.equal(verified.reason, 'provider_evidence_binding_mismatch');
    }
  });

  it('refuses redirected actuator responses and never follows them', async () => {
    const body = new Response(JSON.stringify({
      status: 'committed',
      result: {},
      envelope_digest: `sha256:${'c'.repeat(64)}`,
    }), {
      headers: { 'content-type': 'application/json' },
    }).body;
    const fixture = client(async () => ({
      status: 200,
      redirected: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      body,
    }));

    await assert.rejects(
      fixture.value.effect({
        action: ACTION,
        proposal: {
          ...PROPOSAL,
          consequence: {
            ...PROPOSAL.consequence,
            provider_id: ATTEMPT.provider_id,
            environment: ATTEMPT.environment,
            request_digest: ATTEMPT.request_digest,
          },
        },
        authorization: { allow: true },
        attempt: ATTEMPT,
      }),
      /actuator_redirect_refused/,
    );
  });

  it('fails closed when the workload identity token cannot be acquired', async () => {
    let actuatorCalls = 0;
    const fixture = client(async () => {
      actuatorCalls += 1;
      throw new Error('must_not_call_actuator');
    }, {
      identityTokenProvider: {
        async fetchIdToken() {
          throw new Error('adc_unavailable');
        },
      },
    });

    await assert.rejects(
      fixture.value.effect({
        action: ACTION,
        proposal: {
          ...PROPOSAL,
          consequence: {
            ...PROPOSAL.consequence,
            provider_id: ATTEMPT.provider_id,
            environment: ATTEMPT.environment,
            request_digest: ATTEMPT.request_digest,
          },
        },
        authorization: { allow: true },
        attempt: ATTEMPT,
      }),
      /actuator_identity_token_unavailable/,
    );
    assert.equal(actuatorCalls, 0);
  });

  it('requires a pinned HTTPS origin and never treats metadata as an audience', () => {
    const baseOptions = {
      endpoint: 'http://127.0.0.1:8789',
      authorization: 'actuator-api-token-000000000000000000000000000000',
      identityTokenProvider: { fetchIdToken: async () => IDENTITY_TOKEN },
    };
    for (const identityTokenAudience of [
      undefined,
      'http://metadata.google.internal',
      'https://metadata.google.internal/computeMetadata/v1',
      'https://user:password@example.run.app',
    ]) {
      assert.throws(
        () => createConsequenceActuatorClient({
          ...baseOptions,
          identityTokenAudience,
        }),
        /actuator_identity_audience_invalid/,
      );
    }
  });

  it('binds the identity audience to the canonical or exact Cloud Run tag origin', () => {
    const audienceHost = new URL(IDENTITY_AUDIENCE).hostname;
    assert.doesNotThrow(() => client(async () => response({}), {
      endpoint: IDENTITY_AUDIENCE,
      allowInsecureLoopback: false,
    }));
    assert.doesNotThrow(() => client(async () => response({}), {
      endpoint: `https://canary-r20260725---${audienceHost}`,
      allowInsecureLoopback: false,
    }));

    for (const endpoint of [
      'https://unrelated-service.run.app',
      `https://canary-r20260725---evil-${audienceHost}`,
      `${IDENTITY_AUDIENCE}:444`,
      `http://canary-r20260725---${audienceHost}`,
    ]) {
      assert.throws(
        () => client(async () => response({}), {
          endpoint,
          allowInsecureLoopback: false,
        }),
        /actuator_identity_endpoint_mismatch/,
      );
    }
  });

  it('uses ADC through the Google auth library with one exact audience pin', async () => {
    const calls = [];
    const provider = createGoogleCloudIdentityTokenProvider({
      audience: `${IDENTITY_AUDIENCE}/`,
      auth: {
        async getIdTokenClient(audience) {
          calls.push(['client', audience]);
          return {
            idTokenProvider: {
              async fetchIdToken(requestedAudience) {
                calls.push(['token', requestedAudience]);
                return IDENTITY_TOKEN;
              },
            },
          };
        },
      },
    });

    assert.equal(await provider.fetchIdToken(IDENTITY_AUDIENCE), IDENTITY_TOKEN);
    assert.equal(await provider.fetchIdToken(`${IDENTITY_AUDIENCE}/`), IDENTITY_TOKEN);
    assert.deepEqual(calls, [
      ['client', IDENTITY_AUDIENCE],
      ['token', IDENTITY_AUDIENCE],
      ['token', IDENTITY_AUDIENCE],
    ]);
    await assert.rejects(
      provider.fetchIdToken('https://different-service.run.app'),
      /actuator_identity_audience_mismatch/,
    );
  });
});
