// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import type { SupabaseClient } from '@supabase/supabase-js';

import { open, seal } from '@/lib/crypto/secret-box';
import {
  loadPublicArenaRefusal,
  provisionArenaSession,
  publishArenaRefusal,
  submitArenaAttempt,
} from '@/lib/arena/service';
import { verifyArenaPublicProjection } from '@/lib/arena/refusal';

const TRIAL_VERSION = 'EP-AGENT-ADOPTION-TRIAL-v1';
const TRIAL_TOKEN = /^epenc:v1:[A-Za-z0-9_-]{40,8192}$/;
const SESSION_ID = /^[0-9a-f-]{36}$/;
const BOND_DIGEST = /^sha256:[0-9a-f]{64}$/;
const ARENA_SESSION_ID = /^arena_session_[0-9a-f]{32}$/;
const ARENA_TOKEN = /^ep_arena_[0-9a-f]{64}$/;
const ARENA_ATTEMPT_ID = /^arena_attempt_[0-9a-f]{32}$/;
const ARENA_SHARE_ID = /^arena_share_[0-9a-f]{40}$/;
const ATTEMPTS = new Set([
  'attempt_in_bounds_v1',
  'attempt_over_limit_v1',
  'attempt_unlisted_target_v1',
]);

export type AgentAdoptionAuthorization = Readonly<{
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

export class AgentAdoptionTrialError extends Error {
  constructor(public status: number, public code: string, message = code) {
    super(message);
    this.name = 'AgentAdoptionTrialError';
  }
}

function fail(status: number, code: string): never {
  throw new AgentAdoptionTrialError(status, code);
}

function activeBond(authorization: AgentAdoptionAuthorization): {
  adoptionId: string;
  bondId: string;
  bondDigest: string;
  agentLabel: string;
  totalAmount: number;
  maxAmountPerAction: number;
  allowedTargets: string[];
} {
  const session = authorization?.session;
  const bond = session?.operating_bond;
  const allowance = bond?.allowance;
  const constraints = bond?.constraints;
  if (session?.status !== 'active'
      || session?.adoption_id !== authorization.sessionId
      || session?.bond_count !== 1
      || !SESSION_ID.test(session?.latest_bond_id ?? '')
      || !BOND_DIGEST.test(session?.bond_digest ?? '')
      || session.latest_bond_digest !== session.bond_digest
      || typeof session.agent_label !== 'string'
      || session.agent_label.length < 1 || session.agent_label.length > 80
      || !Number.isSafeInteger(allowance?.total) || allowance.total < 1 || allowance.total > 10_000
      || !Number.isSafeInteger(allowance?.max_per_action) || allowance.max_per_action < 1
      || allowance.max_per_action > allowance.total
      || !Array.isArray(constraints?.allowed_targets)
      || constraints.allowed_targets.length < 1 || constraints.allowed_targets.length > 32
      || constraints.allowed_targets.some((target: unknown) => (
        typeof target !== 'string' || target.length < 1 || target.length > 128
      ))) {
    fail(409, 'agent_adoption_bond_not_asserted');
  }
  return {
    adoptionId: session.adoption_id,
    bondId: session.latest_bond_id,
    bondDigest: session.bond_digest,
    agentLabel: session.agent_label,
    totalAmount: allowance.total,
    maxAmountPerAction: allowance.max_per_action,
    allowedTargets: [...constraints.allowed_targets],
  };
}

function parseTrialToken(value: unknown, expected: ReturnType<typeof activeBond>, now: number): TrialEnvelope {
  if (typeof value !== 'string' || !TRIAL_TOKEN.test(value)) {
    fail(401, 'agent_adoption_trial_invalid');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(open(value));
  } catch {
    fail(401, 'agent_adoption_trial_invalid');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.getPrototypeOf(parsed) !== Object.prototype
      || Reflect.ownKeys(parsed).length !== 7) {
    fail(401, 'agent_adoption_trial_invalid');
  }
  const envelope = parsed as Record<string, unknown>;
  if (envelope['@version'] !== TRIAL_VERSION
      || envelope.adoption_id !== expected.adoptionId
      || envelope.bond_id !== expected.bondId
      || envelope.bond_digest !== expected.bondDigest
      || typeof envelope.arena_session_id !== 'string'
      || !ARENA_SESSION_ID.test(envelope.arena_session_id)
      || typeof envelope.arena_token !== 'string'
      || !ARENA_TOKEN.test(envelope.arena_token)
      || typeof envelope.expires_at !== 'string'
      || !Number.isFinite(Date.parse(envelope.expires_at))
      || now >= Date.parse(envelope.expires_at)) {
    fail(401, 'agent_adoption_trial_invalid');
  }
  return envelope as TrialEnvelope;
}

export async function provisionBoundAgentTrial({
  authorization,
  client,
  now = Date.now(),
}: {
  authorization: AgentAdoptionAuthorization;
  client?: SupabaseClient;
  now?: number;
}) {
  const bound = activeBond(authorization);
  const arena = await provisionArenaSession({
    agentName: bound.agentLabel,
    profile: {
      totalAmount: bound.totalAmount,
      maxAmountPerAction: bound.maxAmountPerAction,
      allowedTargets: bound.allowedTargets,
    },
    client,
    now,
  });
  if (!ARENA_SESSION_ID.test(arena.session_id)
      || !ARENA_TOKEN.test(arena.token)
      || typeof arena.allowance?.expires_at !== 'string') {
    fail(503, 'agent_adoption_trial_unavailable');
  }
  const envelope: TrialEnvelope = {
    '@version': TRIAL_VERSION,
    adoption_id: bound.adoptionId,
    bond_id: bound.bondId,
    bond_digest: bound.bondDigest,
    arena_session_id: arena.session_id,
    arena_token: arena.token,
    expires_at: arena.allowance.expires_at,
  };
  const trialToken = seal(JSON.stringify(envelope));
  if (typeof trialToken !== 'string' || !TRIAL_TOKEN.test(trialToken)) {
    fail(503, 'agent_adoption_trial_unavailable');
  }
  return Object.freeze({
    session_id: bound.adoptionId,
    authority_state: 'asserted' as const,
    passkey_asserted: true,
    bond_id: bound.bondId,
    bond_digest: bound.bondDigest,
    trial_token: trialToken,
    trial_expires_at: envelope.expires_at,
  });
}

function attemptInput(input: unknown): { templateId: string; trialToken: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype
      || Reflect.ownKeys(input).length !== 2
      || !Object.hasOwn(input, 'attempt_template_id')
      || !Object.hasOwn(input, 'trial_token')) {
    fail(400, 'agent_adoption_attempt_invalid');
  }
  const value = input as Record<string, unknown>;
  if (typeof value.attempt_template_id !== 'string'
      || !ATTEMPTS.has(value.attempt_template_id)
      || typeof value.trial_token !== 'string') {
    fail(400, 'agent_adoption_attempt_invalid');
  }
  return { templateId: value.attempt_template_id, trialToken: value.trial_token };
}

export async function submitBoundAgentTrial({
  authorization,
  input,
  client,
  now = Date.now(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: SupabaseClient;
  now?: number;
}) {
  const bound = activeBond(authorization);
  const parsed = attemptInput(input);
  const trial = parseTrialToken(parsed.trialToken, bound, now);
  const target = parsed.templateId === 'attempt_unlisted_target_v1'
    ? (bound.allowedTargets.includes('unlisted.demo') ? 'outside.demo' : 'unlisted.demo')
    : bound.allowedTargets[0];
  const amount = parsed.templateId === 'attempt_over_limit_v1' ? 900
    : parsed.templateId === 'attempt_unlisted_target_v1' ? 20 : 30;
  const purpose = parsed.templateId === 'attempt_over_limit_v1'
    ? 'synthetic-adoption-over-limit'
    : parsed.templateId === 'attempt_unlisted_target_v1'
      ? 'synthetic-adoption-unlisted-target'
      : 'synthetic-adoption-in-bounds';
  const arenaRequest = new Request(
    `https://www.emiliaprotocol.ai/api/arena/sessions/${trial.arena_session_id}/attempts`,
    { headers: { authorization: `Bearer ${trial.arena_token}` } },
  );
  const result: any = await submitArenaAttempt({
    request: arenaRequest,
    sessionId: trial.arena_session_id,
    input: {
      operation_id: `adopt:${crypto.randomUUID()}`,
      target,
      amount,
      purpose,
    },
    client,
    now,
  });
  const reasonCodes: Record<string, string> = {
    allowance_per_action_limit_exceeded: 'per_action_limit_exceeded',
    allowance_target_not_allowed: 'target_not_allowed',
    allowance_aggregate_limit_exceeded: 'allowance_exhausted',
  };
  if (result?.decision !== 'allow' && result?.decision !== 'refuse') {
    fail(503, 'agent_adoption_trial_decision_invalid');
  }
  const reasonCode = result.decision === 'allow' ? 'within_allowance' : reasonCodes[result.reason];
  if (!reasonCode) fail(503, 'agent_adoption_trial_decision_invalid');
  if (typeof result.attempt_id !== 'string'
      || typeof result.action_digest !== 'string'
      || !BOND_DIGEST.test(result.action_digest)) {
    fail(503, 'agent_adoption_trial_decision_invalid');
  }
  return Object.freeze({
    attempt_id: result.attempt_id,
    template_id: parsed.templateId,
    decision: result.decision === 'allow' ? 'permit' as const : 'refuse' as const,
    reason_code: reasonCode,
    synthetic_credits: amount,
    target_template_id: target,
    action_digest: result.action_digest,
    ...(result.decision === 'refuse' && typeof result.refusal_digest === 'string'
      ? { refusal_digest: result.refusal_digest }
      : {}),
  });
}

/**
 * Read and verify the signed refusal bound to this adoption trial without
 * publishing it. Agent Record creation signs these immutable bindings first;
 * the database then publishes the Arena projection and stores the record in
 * one transaction.
 */
export async function prepareBoundAgentTrialRefusal({
  authorization,
  input,
  client,
  now = Date.now(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: SupabaseClient;
  now?: number;
}) {
  const bound = activeBond(authorization);
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype
      || Reflect.ownKeys(input).length !== 2
      || !Object.hasOwn(input, 'trial_token')
      || !Object.hasOwn(input, 'attempt_id')) {
    fail(400, 'agent_adoption_refusal_publication_invalid');
  }
  const value = input as Record<string, unknown>;
  if (typeof value.trial_token !== 'string'
      || typeof value.attempt_id !== 'string'
      || !ARENA_ATTEMPT_ID.test(value.attempt_id)) {
    fail(400, 'agent_adoption_refusal_publication_invalid');
  }
  const trial = parseTrialToken(value.trial_token, bound, now);
  const tokenHash = crypto.createHash('sha256').update(trial.arena_token, 'utf8').digest('hex');
  const store = client ?? (await import('@/lib/supabase')).getServiceClient();
  let prepared: any;
  try {
    prepared = await store.rpc('read_agent_record_arena_source', {
      p_arena_token_hash: tokenHash,
      p_arena_session_id: trial.arena_session_id,
      p_arena_attempt_id: value.attempt_id,
    });
  } catch {
    fail(503, 'agent_adoption_refusal_publication_invalid');
  }
  if (prepared?.error) {
    fail(
      prepared.error.code === 'P0002' ? 404 : 503,
      'agent_adoption_refusal_publication_invalid',
    );
  }
  const source = prepared?.data;
  if (!source || typeof source !== 'object' || Array.isArray(source)
      || Object.getPrototypeOf(source) !== Object.prototype
      || Reflect.ownKeys(source).length !== 3
      || source.arena_session_id !== trial.arena_session_id
      || source.attempt_id !== value.attempt_id
      || !source.public_refusal_projection
      || typeof source.public_refusal_projection !== 'object') {
    fail(503, 'agent_adoption_refusal_publication_invalid');
  }
  const projection = source.public_refusal_projection;
  const verification = verifyArenaPublicProjection(projection, now);
  if (!verification.integrity_verified
      || projection.profile !== 'EP-ARENA-PUBLIC-REFUSAL-v1'
      || projection.attempt?.attempt_id !== value.attempt_id
      || projection.attempt?.decision !== 'refuse'
      || !BOND_DIGEST.test(projection.attempt?.action_digest ?? '')
      || !BOND_DIGEST.test(projection.refusal_digest ?? '')
      || projection.refusal_artifact?.['@version'] !== 'EP-ACTION-REFUSAL-STATEMENT-v1') {
    fail(503, 'agent_adoption_refusal_publication_invalid');
  }
  return Object.freeze({
    adoption_id: bound.adoptionId,
    bond_id: bound.bondId,
    bond_digest: bound.bondDigest,
    agent_label: bound.agentLabel,
    arena_session_id: trial.arena_session_id,
    arena_token_hash: tokenHash,
    action_digest: projection.attempt.action_digest,
    refusal_digest: projection.refusal_digest,
    refused_at: projection.attempt.created_at,
    public_refusal_projection: projection,
  });
}

/**
 * Publish and re-read one signed refusal from the exact Arena session sealed
 * into this adoption's trial capability. Agent Record creation deliberately
 * uses prepareBoundAgentTrialRefusal instead so publication occurs inside its
 * database transaction; this bridge remains for explicit Arena publication.
 */
export async function publishBoundAgentTrialRefusal({
  authorization,
  input,
  client,
  now = Date.now(),
}: {
  authorization: AgentAdoptionAuthorization;
  input: unknown;
  client?: SupabaseClient;
  now?: number;
}) {
  const bound = activeBond(authorization);
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype
      || Reflect.ownKeys(input).length !== 2
      || !Object.hasOwn(input, 'trial_token')
      || !Object.hasOwn(input, 'attempt_id')) {
    fail(400, 'agent_adoption_refusal_publication_invalid');
  }
  const value = input as Record<string, unknown>;
  if (typeof value.trial_token !== 'string'
      || typeof value.attempt_id !== 'string'
      || !ARENA_ATTEMPT_ID.test(value.attempt_id)) {
    fail(400, 'agent_adoption_refusal_publication_invalid');
  }
  const trial = parseTrialToken(value.trial_token, bound, now);
  const request = new Request(
    `https://www.emiliaprotocol.ai/api/arena/sessions/${trial.arena_session_id}/attempts/${value.attempt_id}/publish`,
    { headers: { authorization: `Bearer ${trial.arena_token}` } },
  );
  const published = await publishArenaRefusal({
    request,
    sessionId: trial.arena_session_id,
    attemptId: value.attempt_id,
    client,
    now,
  });
  if (!ARENA_SHARE_ID.test(published?.share_id ?? '')) {
    fail(503, 'agent_adoption_refusal_publication_invalid');
  }
  const publicRefusal: any = await loadPublicArenaRefusal(published.share_id, client);
  if (!publicRefusal
      || publicRefusal.share_id !== published.share_id
      || publicRefusal.verification?.integrity_verified !== true
      || publicRefusal.projection?.attempt?.attempt_id !== value.attempt_id
      || publicRefusal.projection?.attempt?.decision !== 'refuse'
      || !BOND_DIGEST.test(publicRefusal.projection?.attempt?.action_digest ?? '')
      || !BOND_DIGEST.test(publicRefusal.projection?.refusal_digest ?? '')) {
    fail(503, 'agent_adoption_refusal_publication_invalid');
  }
  return Object.freeze({
    adoption_id: bound.adoptionId,
    bond_id: bound.bondId,
    bond_digest: bound.bondDigest,
    agent_label: bound.agentLabel,
    arena_share_id: published.share_id,
    action_digest: publicRefusal.projection.attempt.action_digest,
    refusal_digest: publicRefusal.projection.refusal_digest,
    refused_at: publicRefusal.projection.attempt.created_at,
    public_refusal_projection: publicRefusal.projection,
  });
}
