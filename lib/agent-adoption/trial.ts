// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import type { SupabaseClient } from '@supabase/supabase-js';

import { open, seal } from '@/lib/crypto/secret-box';
import { provisionArenaSession, submitArenaAttempt } from '@/lib/arena/service';

const TRIAL_VERSION = 'EP-AGENT-ADOPTION-TRIAL-v1';
const TRIAL_TOKEN = /^epenc:v1:[A-Za-z0-9_-]{40,8192}$/;
const SESSION_ID = /^[0-9a-f-]{36}$/;
const BOND_DIGEST = /^sha256:[0-9a-f]{64}$/;
const ARENA_SESSION_ID = /^arena_session_[0-9a-f]{32}$/;
const ARENA_TOKEN = /^ep_arena_[0-9a-f]{64}$/;
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
