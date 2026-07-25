// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import {
  createPostgresProviderRecordStore,
  createProductionConsequenceActuatorConfig,
} from '../src/production-config.ts';

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

function productionEnvironment() {
  return {
    ...completeEnvironment(),
    EMILIA_ACTUATOR_DATABASE_URL:
      'postgresql://actuator.example.test/emilia',
    EMILIA_ACTUATOR_DATABASE_PRINCIPAL:
      'consequence_actuator_tenant_emilia',
  };
}

function installationTokenResponse(url: string) {
  assert.match(url, /\/access_tokens$/);
  return new Response(JSON.stringify({
    token: 'ghs_installation_token_abcdefghijklmnopqrstuvwxyz',
    expires_at: '2099-01-01T00:00:00.000Z',
  }), {
    status: 201,
    headers: { 'content-type': 'application/json' },
  });
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
      fetchImpl: async (url: string) => installationTokenResponse(url),
    });

    assert.deepEqual(await config.readiness(), { ok: true });
    await config.close();
  });

  it('proves the exact actuator migration surface before declaring production readiness', async () => {
    const readiness = {
      principal_name: 'consequence_actuator_tenant_emilia',
      role_membership_ok: true,
      provider_attempts_ready: true,
      provider_records_ready: true,
      reserve_envelope_ready: true,
      consume_envelope_ready: true,
      record_provider_attempt_ready: true,
      read_provider_attempt_ready: true,
      record_provider_record_ready: true,
      read_provider_record_ready: true,
    };
    const queries: string[] = [];
    class Pool {
      query = async (text: string) => {
        queries.push(text);
        return { rowCount: 1, rows: [{ ...readiness }] };
      };

      async end() {}
    }
    const config = await createProductionConsequenceActuatorConfig({
      environment: productionEnvironment(),
      PoolClass: Pool,
      fetchImpl: async (url: string) => installationTokenResponse(url),
    });

    assert.deepEqual(await config.readiness(), { ok: true });
    assert.equal(queries.length, 1);
    assert.ok(
      queries[0].includes(
        "'consequence_actuator_private.provider_attempts'",
      ),
    );
    assert.ok(
      queries[0].includes(
        "'consequence_actuator_private.provider_records'",
      ),
    );
    for (const signature of [
      'consequence_actuator_private.reserve_envelope(text,text,text,text,text,text,text,text,text,timestamp with time zone,timestamp with time zone,text)',
      'consequence_actuator_private.consume_envelope(text,text,text,text,text,text,text,text,text,text,text)',
      'consequence_actuator_private.record_provider_attempt(jsonb,text)',
      'consequence_actuator_private.read_provider_attempt(text,text,text,text,text,text,text,text,text)',
      'consequence_actuator_private.record_provider_record(jsonb,text)',
      'consequence_actuator_private.read_provider_record(text,text,text,text,text,text,text,text,text)',
    ]) {
      assert.ok(
        queries[0].includes(`'${signature}'`),
        signature,
      );
    }

    for (const field of [
      'provider_attempts_ready',
      'provider_records_ready',
      'reserve_envelope_ready',
      'consume_envelope_ready',
      'record_provider_attempt_ready',
      'read_provider_attempt_ready',
      'record_provider_record_ready',
      'read_provider_record_ready',
    ] as const) {
      readiness[field] = false;
      assert.deepEqual(await config.readiness(), { ok: false }, field);
      readiness[field] = true;
    }
    await config.close();
  });

  it('uses the production PostgreSQL provider-record adapter through exact RPC-only bindings', async () => {
    const record = {
      '@version': 'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v2',
      payload: { outcome: 'COMMITTED' },
      signature: { algorithm: 'Ed25519' },
    };
    const recordDigest = `sha256:${'a'.repeat(64)}`;
    const attribution = {
      payload: { attempt_id: 'attempt:0000000000000001' },
      signature: { algorithm: 'Ed25519' },
    };
    const attributionDigest = `sha256:${'b'.repeat(64)}`;
    const expected = {
      tenant_id: 'tenant:emilia',
      provider_id: 'github',
      provider_account_id: 'emiliaprotocol',
      environment: 'production-smoke',
      request_digest: `sha256:${'1'.repeat(64)}`,
      attempt_id: 'attempt:0000000000000001',
      operation_id: 'operation:0000000000000001',
      caid: `caid:1:github.issue.update.1:jcs-sha256:${'A'.repeat(43)}`,
      action_digest: `sha256:${'2'.repeat(64)}`,
    };
    const calls: Array<{ text: string; values: readonly unknown[] }> = [];
    const store = createPostgresProviderRecordStore(async (text, values) => {
      calls.push({ text, values });
      if (text.includes('record_provider_attempt')) {
        return {
          rowCount: 1,
          rows: [{ provider_attribution_digest: attributionDigest }],
        };
      }
      if (text.includes('read_provider_attempt')) {
        return {
          rowCount: 1,
          rows: [{
            provider_attribution: attribution,
            provider_attribution_digest: attributionDigest,
          }],
        };
      }
      if (text.includes('record_provider_record')) {
        return {
          rowCount: 1,
          rows: [{ provider_record_digest: recordDigest }],
        };
      }
      if (text.includes('read_provider_record')) {
        return {
          rowCount: 1,
          rows: [{ provider_record: record, provider_record_digest: recordDigest }],
        };
      }
      throw new Error('unexpected_query');
    });

    assert.deepEqual(
      await store.writeAttempt({
        attribution,
        attribution_digest: attributionDigest,
      }),
      { attribution, attribution_digest: attributionDigest },
    );
    assert.deepEqual(await store.readAttempt(expected), {
      attribution,
      attribution_digest: attributionDigest,
    });
    assert.deepEqual(
      await store.write({ record, record_digest: recordDigest }),
      { record, record_digest: recordDigest },
    );
    assert.deepEqual(await store.read(expected), {
      record,
      record_digest: recordDigest,
    });
    assert.equal(calls.length, 4);
    assert.match(
      calls[0].text,
      /FROM consequence_actuator_private\.record_provider_attempt\(/,
    );
    assert.deepEqual(calls[0].values, [
      JSON.stringify(attribution),
      attributionDigest,
    ]);
    assert.match(
      calls[1].text,
      /FROM consequence_actuator_private\.read_provider_attempt\(/,
    );
    assert.deepEqual(calls[1].values, Object.values(expected));
    assert.match(
      calls[2].text,
      /FROM consequence_actuator_private\.record_provider_record\(/,
    );
    assert.deepEqual(calls[2].values, [
      JSON.stringify(record),
      recordDigest,
    ]);
    assert.match(
      calls[3].text,
      /FROM consequence_actuator_private\.read_provider_record\(/,
    );
    assert.deepEqual(calls[3].values, Object.values(expected));
    assert.equal(
      calls.some(({ text }) => /\b(?:INSERT|UPDATE|DELETE)\b/.test(text)),
      false,
    );
  });
});
