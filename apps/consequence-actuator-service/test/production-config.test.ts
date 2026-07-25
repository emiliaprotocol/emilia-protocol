// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import { createProductionConsequenceActuatorConfig } from '../src/production-config.ts';

function keyMaterial() {
  const envelope = crypto.generateKeyPairSync('ed25519');
  const evidence = crypto.generateKeyPairSync('ed25519');
  const github = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    envelopePublic: envelope.publicKey.export({ type: 'spki', format: 'pem' }),
    evidencePrivate: evidence.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    githubPrivate: github.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function completeEnvironment() {
  const keys = keyMaterial();
  return {
    NODE_ENV: 'production',
    EMILIA_ACTUATOR_TENANT_ID: 'tenant:emilia',
    EMILIA_ACTUATOR_API_TOKEN:
      'actuator-api-token-000000000000000000000000000000',
    EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID: 'consequence-control',
    EMILIA_ACTUATOR_ENVELOPE_KEY_ID: 'control-envelope-key',
    EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY: keys.envelopePublic,
    EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID: 'consequence-actuator',
    EMILIA_ACTUATOR_OBSERVATION_KEY_ID: 'actuator-evidence-key',
    EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY: keys.evidencePrivate,
    EMILIA_ACTUATOR_GITHUB_OWNER: 'emiliaprotocol',
    EMILIA_ACTUATOR_GITHUB_REPO: 'gate-smoke-target',
    EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER: '1',
    EMILIA_ACTUATOR_GITHUB_APP_ID: '12345',
    EMILIA_ACTUATOR_GITHUB_INSTALLATION_ID: '67890',
    EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY: keys.githubPrivate,
  };
}

describe('actuator production startup requirements', () => {
  it('refuses startup without a durable store unless the explicit test flag is active', async () => {
    await assert.rejects(
      createProductionConsequenceActuatorConfig({
        environment: completeEnvironment(),
      }),
      /consequence_actuator_durable_store_required/,
    );

    await assert.rejects(
      createProductionConsequenceActuatorConfig({
        environment: {
          ...completeEnvironment(),
          EMILIA_ACTUATOR_ALLOW_MEMORY_STORE_FOR_TESTS: 'true',
        },
      }),
      /consequence_actuator_memory_store_test_only/,
    );
  });

  it('refuses startup when provider credentials are absent', async () => {
    const environment = {
      ...completeEnvironment(),
      NODE_ENV: 'test',
      EMILIA_ACTUATOR_ALLOW_MEMORY_STORE_FOR_TESTS: 'true',
    };
    delete (environment as Record<string, string>)
      .EMILIA_ACTUATOR_GITHUB_APP_ID;

    await assert.rejects(
      createProductionConsequenceActuatorConfig({ environment }),
      /EMILIA_ACTUATOR_GITHUB_APP_ID_required/,
    );
  });

  it('permits memory storage only under the explicit test-only flag', async () => {
    const environment = {
      ...completeEnvironment(),
      NODE_ENV: 'test',
      EMILIA_ACTUATOR_ALLOW_MEMORY_STORE_FOR_TESTS: 'true',
    };
    const config = await createProductionConsequenceActuatorConfig({
      environment,
      fetchImpl: async (url: string) => {
        assert.match(url, /\/access_tokens$/);
        return new Response(JSON.stringify({
          token: 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
          expires_at: '2099-01-01T00:00:00.000Z',
        }), {
          status: 201,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    assert.deepEqual(await config.readiness(), { ok: true });
    await config.close();
  });
});
