// SPDX-License-Identifier: Apache-2.0
import type { SupabaseClient } from '@supabase/supabase-js';

import { open } from '@/lib/crypto/secret-box';
import {
  actionRefusalStatementDigest,
  verifyActionRefusalStatement,
} from '@/packages/gate/action-refusal-statement.js';

const TRIAL_VERSION = 'EP-AGENT-ADOPTION-TRIAL-v1';
const TRIAL_TOKEN = /^epenc:v1:[A-Za-z0-9_-]{40,8192}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SOURCE_SESSION_ID = /^arena_session_[0-9a-f]{32}$/;
const SOURCE_TOKEN = /^ep_arena_[0-9a-f]{64}$/;
const SOURCE_ATTEMPT_ID = /^arena_attempt_[0-9a-f]{32}$/;

export type AgentRecordAuthorization = Readonly<{
  sessionId: string;
  sessionToken: string;
  session: Record<string, any>;
}>;

type TrialEnvelope = Readonly<{
  '@version': typeof TRIAL_VERSION;
  adoption_id: string;
  bond_id: string;
  bond_digest: string;
  arena_session_id: string;
  arena_token: string;
  expires_at: string;
}>;

export class AgentRecordSourceError extends Error {
  constructor(public status: number, public code: string, message = code) {
    super(message);
    this.name = 'AgentRecordSourceError';
  }
}

function fail(status: number, code: string, message = code): never {
  throw new AgentRecordSourceError(status, code, message);
}

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).every((key) => typeof key === 'string');
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

function activeBond(authorization: AgentRecordAuthorization) {
  const session = authorization?.session;
  if (!isRecord(session)
      || session.status !== 'active'
      || session.adoption_id !== authorization.sessionId
      || session.bond_count !== 1
      || !UUID.test(session.adoption_id ?? '')
      || !UUID.test(session.latest_bond_id ?? '')
      || !DIGEST.test(session.bond_digest ?? '')
      || session.latest_bond_digest !== session.bond_digest) {
    fail(409, 'agent_adoption_bond_not_asserted');
  }
  return Object.freeze({
    adoptionId: session.adoption_id as string,
    bondId: session.latest_bond_id as string,
    bondDigest: session.bond_digest as string,
  });
}

function openTrial(value: unknown, bond: ReturnType<typeof activeBond>, now: number): TrialEnvelope {
  if (typeof value !== 'string' || !TRIAL_TOKEN.test(value) || !Number.isFinite(now)) {
    fail(401, 'agent_adoption_trial_invalid');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(open(value));
  } catch {
    fail(401, 'agent_adoption_trial_invalid');
  }
  if (!exactKeys(parsed, [
    '@version',
    'adoption_id',
    'bond_id',
    'bond_digest',
    'arena_session_id',
    'arena_token',
    'expires_at',
  ])
      || parsed['@version'] !== TRIAL_VERSION
      || parsed.adoption_id !== bond.adoptionId
      || parsed.bond_id !== bond.bondId
      || parsed.bond_digest !== bond.bondDigest
      || typeof parsed.arena_session_id !== 'string'
      || !SOURCE_SESSION_ID.test(parsed.arena_session_id)
      || typeof parsed.arena_token !== 'string'
      || !SOURCE_TOKEN.test(parsed.arena_token)
      || !canonicalInstant(parsed.expires_at)
      || now >= Date.parse(parsed.expires_at)) {
    fail(401, 'agent_adoption_trial_invalid');
  }
  return parsed as TrialEnvelope;
}

export async function prepareAgentRecordRefusalSource({
  authorization,
  input,
  client,
  now = Date.now(),
}: {
  authorization: AgentRecordAuthorization;
  input: Readonly<{ trial_token: string; attempt_id: string }>;
  client: Pick<SupabaseClient, 'rpc'>;
  now?: number;
}) {
  const bond = activeBond(authorization);
  if (!exactKeys(input, ['trial_token', 'attempt_id'])
      || typeof input.attempt_id !== 'string'
      || !SOURCE_ATTEMPT_ID.test(input.attempt_id)) {
    fail(400, 'agent_adoption_refusal_source_invalid');
  }
  const trial = openTrial(input.trial_token, bond, now);
  let prepared: any;
  try {
    prepared = await client.rpc('read_agent_record_refusal_source', {
      p_source_token: trial.arena_token,
      p_source_session_id: trial.arena_session_id,
      p_source_attempt_id: input.attempt_id,
    });
  } catch {
    fail(503, 'agent_adoption_refusal_source_invalid', 'The refusal source is unavailable.');
  }
  if (prepared?.error) {
    fail(
      prepared.error.code === 'P0002' ? 404 : 503,
      'agent_adoption_refusal_source_invalid',
    );
  }

  const source = prepared?.data;
  if (!exactKeys(source, [
    'source_commitment',
    'source_artifact_digest',
    'action_digest',
    'refusal_digest',
    'refused_at',
    'refusal_artifact',
    'issuer',
  ])
      || !DIGEST.test(source.source_commitment ?? '')
      || !DIGEST.test(source.source_artifact_digest ?? '')
      || !DIGEST.test(source.action_digest ?? '')
      || !DIGEST.test(source.refusal_digest ?? '')
      || source.source_artifact_digest !== source.refusal_digest
      || !canonicalInstant(source.refused_at)
      || !isRecord(source.refusal_artifact)
      || !exactKeys(source.issuer, ['issuer_id', 'key_id', 'public_key'])
      || typeof source.issuer.issuer_id !== 'string'
      || typeof source.issuer.key_id !== 'string'
      || typeof source.issuer.public_key !== 'string') {
    fail(503, 'agent_adoption_refusal_source_invalid');
  }

  const artifact = source.refusal_artifact;
  const verification = verifyActionRefusalStatement(artifact, {
    trusted_keys: {
      [source.issuer.key_id]: {
        issuer_id: source.issuer.issuer_id,
        public_key: source.issuer.public_key,
      },
    },
    expected: {
      action_digest: source.action_digest,
      relying_party_id: 'arena:emilia:public',
    },
    now: source.refused_at,
    max_future_skew_sec: 0,
  });
  if (!verification.verified
      || verification.refusal_digest !== source.refusal_digest
      || actionRefusalStatementDigest(artifact) !== source.source_artifact_digest
      || artifact['@version'] !== 'EP-ACTION-REFUSAL-STATEMENT-v1'
      || artifact.refusal_id !== `refusal:${input.attempt_id}`
      || artifact.refused_at !== source.refused_at
      || artifact.action_digest !== source.action_digest) {
    fail(503, 'agent_adoption_refusal_source_invalid');
  }

  const result = {
    adoption_id: bond.adoptionId,
    bond_id: bond.bondId,
    bond_digest: bond.bondDigest,
    source_session_id: trial.arena_session_id,
    source_attempt_id: input.attempt_id,
    source_commitment: source.source_commitment as string,
    source_artifact_digest: source.source_artifact_digest as string,
    action_digest: source.action_digest as string,
    refusal_digest: source.refusal_digest as string,
    refused_at: source.refused_at as string,
  } as Record<string, unknown>;
  Object.defineProperty(result, 'source_token', {
    value: trial.arena_token,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return Object.freeze(result);
}
