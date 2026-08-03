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
    database_creation_authorization: boolean;
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

async function probeCreationAuthorization(
  client: RpcClient,
  creationCapability: string,
): Promise<boolean> {
  try {
    const result = await client.rpc('check_agent_record_creation_capability', {
      p_creation_capability: creationCapability,
    });
    return result?.error == null && result?.data === true;
  } catch {
    return false;
  }
}

async function probeCreationRpc(
  client: RpcClient,
  creationCapability: string,
): Promise<boolean> {
  try {
    const result = await client.rpc('create_agent_record_with_capability', {
      // The real capability proves the deployed application and database agree.
      // Every business argument is inert, so the base creator must reject the
      // call in its first validation block before any insert can occur.
      p_creation_capability: creationCapability,
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
    });
    return result?.error?.code === '22023';
  } catch {
    return false;
  }
}

function withRpcReadiness(
  configuration: ReturnType<typeof getAgentRecordConfigurationReadiness>,
  databaseCreationAuthorization: boolean,
  databaseRpcs: boolean,
): AgentRecordRuntimeReadiness {
  const unavailable: AgentRecordReadinessDependency[] = [...configuration.unavailable];
  if (!databaseCreationAuthorization
      && !unavailable.includes('database_creation_authorization')) {
    unavailable.push('database_creation_authorization');
  }
  if (!databaseRpcs) unavailable.push('database_rpcs');
  return Object.freeze({
    enforced: configuration.enforced,
    ready: !configuration.enforced
      || (configuration.ready && databaseCreationAuthorization && databaseRpcs),
    checks: Object.freeze({
      ...configuration.checks,
      database_creation_authorization: databaseCreationAuthorization,
      database_rpcs: databaseRpcs,
    }),
    unavailable: Object.freeze(unavailable),
  });
}

async function probeRuntime(client: RpcClient, creationCapability: string) {
  const [databaseCreationAuthorization, creationRpc, ...otherRpcs] = await Promise.all([
    probeCreationAuthorization(client, creationCapability),
    probeCreationRpc(client, creationCapability),
    ...RPC_PROBES.map((probe) => probeRpc(client, probe)),
  ]);
  return Object.freeze({
    databaseCreationAuthorization,
    databaseRpcs: creationRpc && otherRpcs.every(Boolean),
  });
}

/**
 * Production Agent Record gate. It validates secret presence without returning
 * values, verifies the independent database creation capability, then exercises
 * each deployed RPC entry point with inputs that cannot mutate state. Results
 * are briefly cached per process.
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
  if (!configuration.enforced) {
    return withRpcReadiness(
      configuration,
      configuration.checks.database_creation_authorization,
      true,
    );
  }
  if (!configuration.ready) return withRpcReadiness(configuration, false, false);

  if (useCache && cachedReadiness && cachedReadiness.expiresAt > now) {
    return cachedReadiness.result;
  }
  if (useCache && inFlightReadiness) return inFlightReadiness;

  const run = async () => {
    let databaseCreationAuthorization = false;
    let databaseRpcs = false;
    try {
      const probed = await probeRuntime(
        client ?? getServiceClient(),
        environment.EP_AGENT_RECORD_CREATION_CAPABILITY as string,
      );
      databaseCreationAuthorization = probed.databaseCreationAuthorization;
      databaseRpcs = probed.databaseRpcs;
    } catch {
      databaseCreationAuthorization = false;
      databaseRpcs = false;
    }
    const result = withRpcReadiness(
      configuration,
      databaseCreationAuthorization,
      databaseRpcs,
    );
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
