// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import { getAgentRecordConfigurationReadiness } from '../lib/agent-record/readiness';
import { getAgentRecordRuntimeReadiness } from '../lib/agent-record/runtime-readiness';

const SECRETS = Object.freeze({
  signingKey: Buffer.alloc(32, 7).toString('base64'),
  upstashToken: 'upstash-secret-token-for-readiness-test',
  serviceRoleKey: 'supabase-service-role-secret-for-readiness-test',
});

function productionEnvironment(overrides: Record<string, string | undefined> = {}) {
  return {
    NODE_ENV: 'production',
    EP_COMMIT_SIGNING_KEY: SECRETS.signingKey,
    EP_AGENT_RECORD_SIGNING_KEY_ID: 'agent-record-signing-2026-08',
    UPSTASH_REDIS_REST_URL: 'https://rate-limit.example',
    UPSTASH_REDIS_REST_TOKEN: SECRETS.upstashToken,
    NEXT_PUBLIC_SUPABASE_URL: 'https://database.example',
    SUPABASE_SERVICE_ROLE_KEY: SECRETS.serviceRoleKey,
    ...overrides,
  };
}

function healthyRpcClient() {
  return {
    rpc: vi.fn(async (name: string) => ({
      data: null,
      error: {
        code: name === 'read_agent_record_public' ? 'P0002' : '22023',
      },
    })),
  };
}

describe('Agent Record runtime readiness', () => {
  it('requires every production configuration component without returning secret values', () => {
    const ready = getAgentRecordConfigurationReadiness(productionEnvironment());
    expect(ready).toMatchObject({
      enforced: true,
      ready: true,
      checks: {
        signing_key: true,
        durable_rate_limiting: true,
        database_configuration: true,
      },
      unavailable: [],
    });

    for (const [missing, dependency] of [
      ['EP_COMMIT_SIGNING_KEY', 'signing_key'],
      ['UPSTASH_REDIS_REST_URL', 'durable_rate_limiting'],
      ['UPSTASH_REDIS_REST_TOKEN', 'durable_rate_limiting'],
      ['NEXT_PUBLIC_SUPABASE_URL', 'database_configuration'],
      ['SUPABASE_SERVICE_ROLE_KEY', 'database_configuration'],
    ] as const) {
      const result = getAgentRecordConfigurationReadiness(
        productionEnvironment({ [missing]: undefined }),
      );
      expect(result.ready, missing).toBe(false);
      expect(result.unavailable, missing).toContain(dependency);
    }

    const serialized = JSON.stringify(ready);
    for (const secret of Object.values(SECRETS)) expect(serialized).not.toContain(secret);
  });

  it('rejects malformed signing material and reserved signing key ids', () => {
    for (const overrides of [
      { EP_COMMIT_SIGNING_KEY: 'not-a-seed' },
      { EP_AGENT_RECORD_SIGNING_KEY_ID: 'constructor' },
      { EP_AGENT_RECORD_SIGNING_KEY_ID: 'unsafe key id' },
    ]) {
      const result = getAgentRecordConfigurationReadiness(productionEnvironment(overrides));
      expect(result.ready).toBe(false);
      expect(result.checks.signing_key).toBe(false);
    }
  });

  it('keeps non-production development usable without operated dependencies', async () => {
    const client = healthyRpcClient();
    const result = await getAgentRecordRuntimeReadiness({
      environment: { NODE_ENV: 'test' },
      client: client as never,
      useCache: false,
    });

    expect(result).toMatchObject({ enforced: false, ready: true });
    expect(client.rpc).not.toHaveBeenCalled();
  });

  it('probes all deployed RPC entry points with inert non-secret inputs', async () => {
    const client = healthyRpcClient();
    const result = await getAgentRecordRuntimeReadiness({
      environment: productionEnvironment(),
      client: client as never,
      useCache: false,
    });

    expect(result).toMatchObject({
      enforced: true,
      ready: true,
      checks: { database_rpcs: true },
      unavailable: [],
    });
    expect(client.rpc.mock.calls.map(([name]) => name).sort()).toEqual([
      'create_agent_record',
      'read_agent_record_public',
      'revoke_agent_record',
    ]);
    const createProbe = client.rpc.mock.calls.find(([name]) => name === 'create_agent_record');
    expect(Object.keys(createProbe?.[1] ?? {}).sort()).toEqual([
      'p_action_digest',
      'p_adoption_id',
      'p_adoption_session_token',
      'p_bond_digest',
      'p_bond_id',
      'p_observed_at',
      'p_owner_token',
      'p_public_projection',
      'p_record_id',
      'p_refusal_digest',
      'p_refused_at',
      'p_retention_expires_at',
      'p_source_artifact_digest',
      'p_source_attempt_id',
      'p_source_commitment',
      'p_source_session_id',
      'p_source_token_hash',
    ].sort());
    const probeBytes = JSON.stringify(client.rpc.mock.calls);
    for (const secret of Object.values(SECRETS)) expect(probeBytes).not.toContain(secret);
  });

  it('fails closed when any one Agent Record RPC is missing or misconfigured', async () => {
    const client = healthyRpcClient();
    client.rpc.mockImplementation(async (name: string) => ({
      data: null,
      error: {
        code: name === 'create_agent_record'
          ? 'PGRST202'
          : name === 'read_agent_record_public' ? 'P0002' : '22023',
      },
    }));

    const result = await getAgentRecordRuntimeReadiness({
      environment: productionEnvironment(),
      client: client as never,
      useCache: false,
    });

    expect(result.ready).toBe(false);
    expect(result.checks.database_rpcs).toBe(false);
    expect(result.unavailable).toContain('database_rpcs');
  });
});
