// SPDX-License-Identifier: Apache-2.0
import type { SupabaseClient } from '@supabase/supabase-js';

import { getServiceClient } from '@/lib/supabase';
import {
  getAgentRecordConfigurationReadiness,
  type AgentRecordReadinessDependency,
} from './readiness';

type RpcClient = Pick<SupabaseClient, 'rpc'>;
type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;

export type AgentRecordRuntimeReadiness = Readonly<{
  enforced: boolean;
  ready: boolean;
  checks: Readonly<{
    signing_key: boolean;
    durable_rate_limiting: boolean;
    database_configuration: boolean;
    database_rpcs: boolean;
  }>;
  unavailable: readonly AgentRecordReadinessDependency[];
}>;

const READINESS_CACHE_MS = 30_000;
let cachedReadiness: Readonly<{
  expiresAt: number;
  result: AgentRecordRuntimeReadiness;
}> | null = null;
let inFlightReadiness: Promise<AgentRecordRuntimeReadiness> | null = null;

const RPC_PROBES = Object.freeze([
  Object.freeze({
    name: 'read_agent_record_public',
    expectedCode: 'P0002',
    args: Object.freeze({ p_record_id: 'agent_record_readiness_probe' }),
  }),
  Object.freeze({
    name: 'create_agent_record',
    expectedCode: '22023',
    // Every argument is deliberately inert. The RPC's first validation block
    // rejects these NULLs before it can publish or insert anything.
    args: Object.freeze({
      p_adoption_id: null,
      p_adoption_session_token: null,
      p_record_id: null,
      p_owner_token: null,
      p_bond_id: null,
      p_bond_digest: null,
      p_source_session_id: null,
      p_source_token_hash: null,
      p_source_attempt_id: null,
      p_source_commitment: null,
      p_source_artifact_digest: null,
      p_action_digest: null,
      p_refusal_digest: null,
      p_refused_at: null,
      p_observed_at: null,
      p_retention_expires_at: null,
      p_public_projection: null,
    }),
  }),
  Object.freeze({
    name: 'revoke_agent_record',
    expectedCode: '22023',
    args: Object.freeze({
      p_record_id: 'agent_record_readiness_probe',
      p_owner_token: 'readiness_probe',
      p_revocation_nonce: 'readiness_probe',
    }),
  }),
]);

async function probeRpc(
  client: RpcClient,
  probe: (typeof RPC_PROBES)[number],
): Promise<boolean> {
  try {
    const result = await client.rpc(probe.name, probe.args);
    return result?.error?.code === probe.expectedCode;
  } catch {
    return false;
  }
}

function withRpcReadiness(
  configuration: ReturnType<typeof getAgentRecordConfigurationReadiness>,
  databaseRpcs: boolean,
): AgentRecordRuntimeReadiness {
  const unavailable: AgentRecordReadinessDependency[] = [...configuration.unavailable];
  if (!databaseRpcs) unavailable.push('database_rpcs');
  return Object.freeze({
    enforced: configuration.enforced,
    ready: !configuration.enforced || (configuration.ready && databaseRpcs),
    checks: Object.freeze({ ...configuration.checks, database_rpcs: databaseRpcs }),
    unavailable: Object.freeze(unavailable),
  });
}

async function probeRuntime(client: RpcClient): Promise<boolean> {
  const results = await Promise.all(RPC_PROBES.map((probe) => probeRpc(client, probe)));
  return results.every(Boolean);
}

/**
 * Production Agent Record gate. It validates secret presence without returning
 * values, then exercises all three deployed RPC entry points with inputs that
 * must be rejected before mutation. Results are briefly cached per process.
 */
export async function getAgentRecordRuntimeReadiness({
  environment = process.env,
  client,
  now = Date.now(),
  useCache = client === undefined,
}: {
  environment?: RuntimeEnvironment;
  client?: RpcClient;
  now?: number;
  useCache?: boolean;
} = {}): Promise<AgentRecordRuntimeReadiness> {
  const configuration = getAgentRecordConfigurationReadiness(environment);
  if (!configuration.enforced) return withRpcReadiness(configuration, true);
  if (!configuration.ready) return withRpcReadiness(configuration, false);

  if (useCache && cachedReadiness && cachedReadiness.expiresAt > now) {
    return cachedReadiness.result;
  }
  if (useCache && inFlightReadiness) return inFlightReadiness;

  const run = async () => {
    let databaseRpcs = false;
    try {
      databaseRpcs = await probeRuntime(client ?? getServiceClient());
    } catch {
      databaseRpcs = false;
    }
    const result = withRpcReadiness(configuration, databaseRpcs);
    if (useCache) cachedReadiness = Object.freeze({
      expiresAt: now + READINESS_CACHE_MS,
      result,
    });
    return result;
  };

  if (!useCache) return run();
  inFlightReadiness = run();
  try {
    return await inFlightReadiness;
  } finally {
    inFlightReadiness = null;
  }
}
