// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import type { SupabaseClient } from '@supabase/supabase-js';

import { getAgentRecordCreationCapability } from '@/lib/env.js';
import { getServiceClient } from '@/lib/supabase';
import {
  AGENT_RECORD_RETENTION_MS,
  AgentRecordCoreError,
  signAgentRecordObservation,
  verifyAgentRecordObservation,
} from './core';
import {
  AgentRecordSourceError,
  prepareAgentRecordRefusalSource,
  type AgentRecordAuthorization,
} from './source';

const RECORD_ID = /^agent_record_[0-9a-f]{40}$/;
const OWNER_TOKEN = /^ear1_[0-9a-f]{64}$/;
const REVOCATION_NONCE = /^earv1_[0-9a-f]{64}$/;
const ADOPTION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SOURCE_SESSION_ID = /^arena_session_[0-9a-f]{32}$/;
const SOURCE_TOKEN = /^ep_arena_[0-9a-f]{64}$/;
const ATTEMPT_ID = /^arena_attempt_[0-9a-f]{32}$/;
const TRIAL_TOKEN = /^epenc:v1:[A-Za-z0-9_-]{40,8192}$/;
const CREATION_CAPABILITY = /^earc1_[0-9a-f]{64}$/;

type RpcClient = Pick<SupabaseClient, 'rpc'>;
type StoreError = Readonly<{ code?: string; message?: string; details?: string }>;

export class AgentRecordServiceError extends Error {
  constructor(public status: number, public code: string, message = code, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentRecordServiceError';
  }
}

function fail(status: number, code: string, message = code, cause?: unknown): never {
  throw new AgentRecordServiceError(
    status,
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function isRecord(value: unknown): value is Record<string, any> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, any> {
  return isRecord(value)
    && Reflect.ownKeys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function canonicalInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

export function agentRecordIdForOwnerToken(ownerToken: string): string {
  const commitment = crypto.createHash('sha256')
    .update(`emilia-agent-record-owner-token-v1\0${ownerToken}`, 'utf8')
    .digest('hex');
  return `agent_record_${commitment.slice(0, 40)}`;
}

export function agentRecordOwnerPairMatches(recordId: unknown, ownerToken: unknown): boolean {
  return typeof recordId === 'string'
    && RECORD_ID.test(recordId)
    && typeof ownerToken === 'string'
    && OWNER_TOKEN.test(ownerToken)
    && recordId === agentRecordIdForOwnerToken(ownerToken);
}

function storeStatus(error: StoreError | null | undefined): number {
  if (error?.code === '42501') return 503;
  if (error?.code === '22023') return 400;
  if (error?.code === 'P0002') return 404;
  if (error?.code === '23505' || error?.code === '55000') return 409;
  return 503;
}

function creationCapability(): string {
  const capability = getAgentRecordCreationCapability() ?? '';
  if (!CREATION_CAPABILITY.test(capability)) {
    fail(
      503,
      'agent_record_creation_capability_unavailable',
      'Agent Record creation is unavailable.',
    );
  }
  return capability;
}

async function callRpc(
  client: RpcClient,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, any>> {
  let result: any;
  try {
    result = await client.rpc(name, args);
  } catch (cause) {
    fail(503, 'agent_record_store_unavailable', 'Agent Record storage is unavailable.', cause);
  }
  if (result?.error) {
    const status = storeStatus(result.error);
    fail(
      status,
      status === 404 ? 'agent_record_not_found'
        : status === 409 ? 'agent_record_conflict'
          : status === 400 ? 'agent_record_invalid'
            : 'agent_record_store_unavailable',
      status === 404 ? 'Agent Record not found.'
        : status === 409 ? 'The Agent Record source or credential was already consumed.'
          : status === 400 ? 'The Agent Record input is invalid.'
            : 'Agent Record storage is unavailable.',
      result.error,
    );
  }
  if (!isRecord(result?.data)) {
    fail(503, 'agent_record_store_invalid', 'Agent Record storage returned an invalid result.');
  }
  return result.data;
}

function creationInput(value: unknown): {
  trial_token: string;
  attempt_id: string;
  record_id: string;
  owner_token: string;
} {
  if (!exactKeys(value, ['trial_token', 'attempt_id', 'record_id', 'owner_token'])
      || typeof value.trial_token !== 'string'
      || !TRIAL_TOKEN.test(value.trial_token)
      || typeof value.attempt_id !== 'string'
      || !ATTEMPT_ID.test(value.attempt_id)
      || typeof value.record_id !== 'string'
      || !RECORD_ID.test(value.record_id)
      || typeof value.owner_token !== 'string'
      || !OWNER_TOKEN.test(value.owner_token)) {
    fail(400, 'agent_record_creation_invalid', 'Agent Record creation input is invalid.');
  }
  return {
    trial_token: value.trial_token,
    attempt_id: value.attempt_id,
    record_id: value.record_id,
    owner_token: value.owner_token,
  };
}

function refusalBindings(
  value: unknown,
  authorization: AgentRecordAuthorization,
  attemptId: string,
) {
  if (!isRecord(value)
      || value.adoption_id !== authorization.sessionId
      || value.adoption_id !== authorization.session?.adoption_id
      || value.bond_id !== authorization.session?.latest_bond_id
      || value.bond_digest !== authorization.session?.bond_digest
      || value.bond_digest !== authorization.session?.latest_bond_digest
      || authorization.session?.status !== 'active'
      || authorization.session?.bond_count !== 1
      || !ADOPTION_ID.test(value.adoption_id ?? '')
      || !ADOPTION_ID.test(value.bond_id ?? '')
      || !DIGEST.test(value.bond_digest ?? '')
      || !SOURCE_SESSION_ID.test(value.source_session_id ?? '')
      || !SOURCE_TOKEN.test(value.source_token ?? '')
      || value.source_attempt_id !== attemptId
      || !ATTEMPT_ID.test(value.source_attempt_id ?? '')
      || !DIGEST.test(value.source_commitment ?? '')
      || !DIGEST.test(value.source_artifact_digest ?? '')
      || !DIGEST.test(value.action_digest ?? '')
      || !DIGEST.test(value.refusal_digest ?? '')
      || value.source_artifact_digest !== value.refusal_digest
      || !canonicalInstant(value.refused_at)
  ) {
    fail(503, 'agent_record_refusal_invalid', 'The bound signed refusal is invalid.');
  }
  return {
    adoptionId: value.adoption_id as string,
    bondId: value.bond_id as string,
    bondDigest: value.bond_digest as string,
    sourceSessionId: value.source_session_id as string,
    sourceToken: value.source_token as string,
    sourceAttemptId: value.source_attempt_id as string,
    sourceCommitment: value.source_commitment as string,
    sourceArtifactDigest: value.source_artifact_digest as string,
    actionDigest: value.action_digest as string,
    refusalDigest: value.refusal_digest as string,
    refusedAt: value.refused_at as string,
  };
}

export async function createAgentRecord({
  authorization,
  input,
  client = getServiceClient(),
  now = Date.now(),
}: {
  authorization: AgentRecordAuthorization;
  input: unknown;
  client?: SupabaseClient;
  now?: number;
}) {
  const parsed = creationInput(input);
  if (!agentRecordOwnerPairMatches(parsed.record_id, parsed.owner_token)) {
    fail(400, 'agent_record_creation_invalid', 'Agent Record creation input is invalid.');
  }
  if (!Number.isFinite(now)) {
    fail(400, 'agent_record_creation_invalid', 'Agent Record observation time is invalid.');
  }
  const capability = creationCapability();
  let prepared: unknown;
  try {
    prepared = await prepareAgentRecordRefusalSource({
      authorization,
      input: {
        trial_token: parsed.trial_token,
        attempt_id: parsed.attempt_id,
      },
      client,
      now,
    });
  } catch (cause) {
    if (cause instanceof AgentRecordSourceError) {
      fail(cause.status, cause.code, cause.message, cause);
    }
    throw cause;
  }
  const source = refusalBindings(prepared, authorization, parsed.attempt_id);
  const recordId = parsed.record_id;
  const observedAt = new Date(now).toISOString();
  const retentionExpiresAt = new Date(now + AGENT_RECORD_RETENTION_MS).toISOString();
  let publicProjection;
  try {
    publicProjection = signAgentRecordObservation({
      recordId,
      bondId: source.bondId,
      bondDigest: source.bondDigest,
      sourceArtifactDigest: source.sourceArtifactDigest,
      actionDigest: source.actionDigest,
      refusalDigest: source.refusalDigest,
      refusedAt: source.refusedAt,
      observedAt,
      retentionExpiresAt,
    });
  } catch (cause) {
    if (cause instanceof AgentRecordCoreError) {
      if (cause.code.startsWith('agent_record_operator_')) {
        fail(503, cause.code, cause.message, cause);
      }
      fail(503, 'agent_record_refusal_invalid', 'The bound signed refusal is invalid.', cause);
    }
    throw cause;
  }
  const preflightVerification = verifyAgentRecordObservation(publicProjection, now);
  if (!preflightVerification.verified || !preflightVerification.within_retention) {
    fail(503, 'agent_record_operator_signature_invalid', 'The operator signature is invalid.');
  }
  const stored = await callRpc(client, 'create_agent_record_with_capability', {
    p_record_id: recordId,
    p_owner_token: parsed.owner_token,
    p_adoption_id: source.adoptionId,
    p_adoption_session_token: authorization.sessionToken,
    p_bond_id: source.bondId,
    p_bond_digest: source.bondDigest,
    p_source_session_id: source.sourceSessionId,
    p_source_token: source.sourceToken,
    p_source_attempt_id: source.sourceAttemptId,
    p_source_commitment: source.sourceCommitment,
    p_source_artifact_digest: source.sourceArtifactDigest,
    p_action_digest: source.actionDigest,
    p_refusal_digest: source.refusalDigest,
    p_refused_at: source.refusedAt,
    p_observed_at: observedAt,
    p_retention_expires_at: retentionExpiresAt,
    p_public_projection: publicProjection,
    p_creation_capability: capability,
  });
  if (!exactKeys(stored, [
    'record_id',
    'created_at',
    'retention_expires_at',
    'public_projection',
  ])
      || stored.record_id !== recordId
      || !canonicalInstant(stored.created_at)
      || !canonicalInstant(stored.retention_expires_at)
      || !isRecord(stored.public_projection)
      || stored.public_projection?.record?.record_id !== recordId
      || stored.public_projection?.record?.bond?.bond_id !== source.bondId
      || stored.public_projection?.record?.bond?.bond_digest !== source.bondDigest
      || stored.public_projection?.record?.source?.artifact_digest !== source.sourceArtifactDigest
      || stored.public_projection?.record?.action?.action_digest !== source.actionDigest
      || stored.public_projection?.record?.refusal?.refusal_digest !== source.refusalDigest
      || stored.public_projection?.record?.refusal?.refused_at !== source.refusedAt
      || stored.created_at !== stored.public_projection?.record?.observed_at
      || stored.retention_expires_at !== stored.public_projection?.record?.retention_expires_at) {
    fail(503, 'agent_record_store_invalid', 'Stored Agent Record is inconsistent.');
  }
  const verification = verifyAgentRecordObservation(stored.public_projection, now);
  if (!verification.verified || !verification.within_retention) {
    fail(503, 'agent_record_store_invalid', 'Stored Agent Record did not verify.');
  }
  return Object.freeze({
    record_id: stored.record_id as string,
    created_at: stored.created_at as string,
    retention_expires_at: stored.retention_expires_at as string,
    public_projection: stored.public_projection,
  });
}

export async function revokeAgentRecord({
  recordId,
  ownerToken,
  client = getServiceClient(),
}: {
  recordId: string;
  ownerToken: string;
  client?: RpcClient;
}) {
  if (!agentRecordOwnerPairMatches(recordId, ownerToken)) {
    fail(400, 'agent_record_owner_credential_invalid', 'Agent Record owner credential is invalid.');
  }
  const revocationNonce = `earv1_${crypto.randomBytes(32).toString('hex')}`;
  if (!REVOCATION_NONCE.test(revocationNonce)) {
    fail(503, 'agent_record_revocation_unavailable', 'Agent Record revocation is unavailable.');
  }
  const stored = await callRpc(client, 'revoke_agent_record', {
    p_record_id: recordId,
    p_owner_token: ownerToken,
    p_revocation_nonce: revocationNonce,
  });
  if (!exactKeys(stored, ['record_id', 'revoked', 'revoked_at'])
      || stored.record_id !== recordId
      || stored.revoked !== true
      || !canonicalInstant(stored.revoked_at)) {
    fail(503, 'agent_record_store_invalid', 'Stored Agent Record revocation is inconsistent.');
  }
  return Object.freeze({
    record_id: stored.record_id as string,
    revoked: true as const,
    revoked_at: stored.revoked_at as string,
  });
}

export async function loadPublicAgentRecord({
  recordId,
  client = getServiceClient(),
  now = Date.now(),
}: {
  recordId: string;
  client?: RpcClient;
  now?: number;
}) {
  if (!RECORD_ID.test(recordId)) return null;
  let stored: Record<string, any>;
  try {
    stored = await callRpc(client, 'read_agent_record_public', { p_record_id: recordId });
  } catch (cause) {
    if (cause instanceof AgentRecordServiceError && cause.status === 404) return null;
    throw cause;
  }
  if (!exactKeys(stored, ['record_id', 'public_projection'])
      || stored.record_id !== recordId) {
    fail(503, 'agent_record_store_invalid', 'Stored public Agent Record is inconsistent.');
  }
  const verification = verifyAgentRecordObservation(stored.public_projection, now);
  if (verification.verified && !verification.within_retention
      && verification.reason === 'agent_record_expired') {
    return null;
  }
  if (!verification.verified || !verification.within_retention
      || verification.record_id !== recordId) {
    fail(503, 'agent_record_store_invalid', 'Stored public Agent Record did not verify.');
  }
  return Object.freeze({
    record_id: recordId,
    public_projection: stored.public_projection,
    verification: Object.freeze({
      integrity_verified: true as const,
      status_checked: true as const,
      currently_public: true as const,
      claim_boundary: stored.public_projection.record.claim_boundary,
    }),
  });
}
