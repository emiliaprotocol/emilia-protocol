// SPDX-License-Identifier: Apache-2.0

export type AgentRecordReadinessDependency =
  | 'signing_key'
  | 'durable_rate_limiting'
  | 'database_configuration'
  | 'database_creation_authorization'
  | 'database_rpcs';

export type AgentRecordConfigurationReadiness = Readonly<{
  enforced: boolean;
  ready: boolean;
  checks: Readonly<{
    signing_key: boolean;
    durable_rate_limiting: boolean;
    database_configuration: boolean;
    database_creation_authorization: boolean;
  }>;
  unavailable: readonly AgentRecordReadinessDependency[];
}>;

type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;

const SIGNING_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const RESERVED_SIGNING_KEY_IDS = new Set(['constructor', 'prototype']);
const BASE64_ED25519_SEED = /^[A-Za-z0-9+/]{43}=$/;
const CREATION_CAPABILITY = /^earc1_[0-9a-f]{64}$/;

function validSigningKeyId(value: string): boolean {
  return SIGNING_KEY_ID.test(value) && !RESERVED_SIGNING_KEY_IDS.has(value);
}

function validSigningSeed(value: string | undefined): boolean {
  if (!value || !BASE64_ED25519_SEED.test(value)) return false;
  try {
    const decoded = atob(value);
    return decoded.length === 32 && btoa(decoded) === value;
  } catch {
    return false;
  }
}

/**
 * Secret-free production configuration gate for Agent Record surfaces.
 *
 * Non-production keeps the local ephemeral signer and in-memory limiter usable.
 * Production must explicitly carry every operated dependency; the server-only
 * runtime helper separately proves that the deployed database RPCs answer.
 */
export function getAgentRecordConfigurationReadiness(
  environment: RuntimeEnvironment = process.env,
): AgentRecordConfigurationReadiness {
  const enforced = environment.NODE_ENV === 'production';
  const signingKeyId = environment.EP_AGENT_RECORD_SIGNING_KEY_ID || 'ep-signing-key-1';
  const checks = Object.freeze({
    signing_key: validSigningSeed(environment.EP_COMMIT_SIGNING_KEY)
      && validSigningKeyId(signingKeyId),
    durable_rate_limiting: Boolean(
      environment.UPSTASH_REDIS_REST_URL && environment.UPSTASH_REDIS_REST_TOKEN,
    ),
    database_configuration: Boolean(
      environment.NEXT_PUBLIC_SUPABASE_URL && environment.SUPABASE_SERVICE_ROLE_KEY,
    ),
    database_creation_authorization: CREATION_CAPABILITY.test(
      environment.EP_AGENT_RECORD_CREATION_CAPABILITY ?? '',
    ),
  });
  const unavailable = Object.freeze((Object.entries(checks) as Array<[
    Exclude<AgentRecordReadinessDependency, 'database_rpcs'>,
    boolean,
  ]>)
    .filter(([, available]) => !available)
    .map(([dependency]) => dependency));

  return Object.freeze({
    enforced,
    ready: !enforced || unavailable.length === 0,
    checks,
    unavailable,
  });
}
