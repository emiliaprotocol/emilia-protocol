// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import type { SupabaseClient } from '@supabase/supabase-js';

import { open, seal } from '@/lib/crypto/secret-box';
import { getServiceClient } from '@/lib/supabase';
import { authenticateArenaRequest } from './auth';
import {
  ARENA_ACTION_TYPE,
  ARENA_CLAIM_BOUNDARY,
  ARENA_CURRENCY,
  createArenaAllowance,
  deriveArenaActionBinding,
  type ArenaAction,
  type ArenaAllowance,
} from './core';
import {
  ARENA_PUBLIC_CLAIM_BOUNDARY,
  ARENA_PUBLIC_REFUSAL_PROFILE,
  PUBLIC_PROFILE_V2 as ARENA_PUBLIC_REFUSAL_PROFILE_V2,
  signArenaRefusal,
  signArenaRefusalV2,
  verifyArenaPublicProjection,
  verifyArenaPublicProjectionV2,
} from './refusal';

const CHALLENGE_ID = 'emilia.arena.allowance';
const CHALLENGE_VERSION = 1;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const REFUSAL_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TOTAL_AMOUNT = 1_000;
const MAX_AMOUNT_PER_ACTION = 250;
const ALLOWED_TARGETS = Object.freeze(['compute.batch', 'vendor.demo']);
const COMPOSED_TARGET = /^[A-Za-z0-9][A-Za-z0-9:_.@+\-]{0,127}$/;

export type ArenaProvisioningProfile = Readonly<{
  totalAmount: number;
  maxAmountPerAction: number;
  allowedTargets: readonly string[];
}>;

export class ArenaServiceError extends Error {
  constructor(public status: number, public code: string, message = code) {
    super(message);
  }
}

function serviceError(result: any, fallback = 'arena_store_unavailable'): never {
  const status = Number.isSafeInteger(result?.status) ? result.status : 503;
  throw new ArenaServiceError(status, result?.reason || fallback);
}

function arenaClient(client?: SupabaseClient): SupabaseClient {
  return client || getServiceClient();
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, any> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Reflect.ownKeys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function storedRefusalProjection({
  session,
  action,
  attemptId,
  reason,
  createdAt,
  caid,
  actionDigest,
  artifact,
  refusalDigest,
}: {
  session: Record<string, any>;
  action: ArenaAction;
  attemptId: string;
  reason: string;
  createdAt: string;
  caid: string;
  actionDigest: string;
  artifact: unknown;
  refusalDigest: string;
}) {
  return {
    profile: ARENA_PUBLIC_REFUSAL_PROFILE,
    challenge_id: CHALLENGE_ID,
    challenge_version: CHALLENGE_VERSION,
    attempt: {
      attempt_id: attemptId,
      action,
      caid,
      action_digest: actionDigest,
      decision: 'refuse',
      reason,
      created_at: createdAt,
    },
    refusal_artifact: artifact,
    refusal_digest: refusalDigest,
    issuer: {
      issuer_id: session.issuer_id,
      key_id: session.key_id,
      public_key: session.public_key,
    },
    claim_boundary: ARENA_PUBLIC_CLAIM_BOUNDARY,
  };
}

/**
 * EP-ARENA-PUBLIC-REFUSAL-v2 projection wrapper. Additive: only meaningful
 * when the session carries hybrid signer material (see the hybrid-adoption
 * note at the signArenaRefusal call site below).
 */
function storedRefusalProjectionV2({
  session,
  action,
  attemptId,
  reason,
  createdAt,
  caid,
  actionDigest,
  artifact,
  refusalDigest,
}: {
  session: Record<string, any>;
  action: ArenaAction;
  attemptId: string;
  reason: string;
  createdAt: string;
  caid: string;
  actionDigest: string;
  artifact: unknown;
  refusalDigest: string;
}) {
  return {
    profile: ARENA_PUBLIC_REFUSAL_PROFILE_V2,
    challenge_id: CHALLENGE_ID,
    challenge_version: CHALLENGE_VERSION,
    attempt: {
      attempt_id: attemptId,
      action,
      caid,
      action_digest: actionDigest,
      decision: 'refuse',
      reason,
      created_at: createdAt,
    },
    refusal_artifact: artifact,
    refusal_digest: refusalDigest,
    issuer: {
      issuer_id: session.issuer_id,
      key_id: session.key_id,
      public_key: session.public_key,
      pq_public_key: session.pq_public_key,
    },
    claim_boundary: ARENA_PUBLIC_CLAIM_BOUNDARY,
  };
}

export async function provisionArenaSession({
  agentName,
  profile,
  client,
  now = Date.now(),
}: {
  agentName: string;
  profile?: ArenaProvisioningProfile;
  client?: SupabaseClient;
  now?: number;
}) {
  const sessionId = `arena_session_${crypto.randomBytes(16).toString('hex')}`;
  const token = `ep_arena_${crypto.randomBytes(32).toString('hex')}`;
  const tokenHash = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  const issuedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + SESSION_TTL_MS).toISOString();
  const totalAmount = profile?.totalAmount ?? TOTAL_AMOUNT;
  const maxAmountPerAction = profile?.maxAmountPerAction ?? MAX_AMOUNT_PER_ACTION;
  const allowedTargets = profile?.allowedTargets ?? ALLOWED_TARGETS;
  if (profile && (
    !Number.isSafeInteger(totalAmount) || totalAmount < 1 || totalAmount > 10_000
    || !Number.isSafeInteger(maxAmountPerAction) || maxAmountPerAction < 1
    || maxAmountPerAction > totalAmount
    || !Array.isArray(allowedTargets) || allowedTargets.length < 1 || allowedTargets.length > 32
    || allowedTargets.some((target) => typeof target !== 'string' || !COMPOSED_TARGET.test(target))
    || new Set(allowedTargets).size !== allowedTargets.length
  )) {
    throw new ArenaServiceError(400, 'arena_profile_invalid');
  }
  let allowance: ArenaAllowance;
  try {
    allowance = createArenaAllowance({
      sessionId,
      agentName,
      totalAmount,
      maxAmountPerAction,
      allowedTargets: [...allowedTargets],
      issuedAt,
      expiresAt,
    });
  } catch (cause) {
    if (profile) throw new ArenaServiceError(400, 'arena_profile_invalid');
    throw cause;
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const privateKeyB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
  const issuerId = `arena:session:${sessionId}`;
  const keyId = `arena-key:${sessionId}`;
  const encrypted = seal(privateKeyB64);
  if (typeof encrypted !== 'string') throw new ArenaServiceError(503, 'arena_signer_unavailable');

  const store = arenaClient(client);
  let result: any;
  try {
    result = await store.rpc('provision_arena_session', {
      p_session_id: sessionId,
      p_token_hash: tokenHash,
      p_agent_name: allowance.agent_name,
      p_challenge_id: CHALLENGE_ID,
      p_challenge_version: CHALLENGE_VERSION,
      p_total_amount: allowance.total_amount,
      p_max_amount_per_action: allowance.max_amount_per_action,
      p_allowed_targets: allowance.allowed_targets,
      p_allowance_profile: allowance,
      p_issuer_id: issuerId,
      p_key_id: keyId,
      p_public_key: publicKeyB64,
      p_private_key_encrypted: encrypted,
      p_expires_at: expiresAt,
    });
  } catch {
    throw new ArenaServiceError(503, 'arena_store_unavailable');
  }
  if (result.error || result.data?.ok !== true) serviceError(result.data);
  return Object.freeze({
    session_id: sessionId,
    token,
    challenge: Object.freeze({ id: CHALLENGE_ID, version: CHALLENGE_VERSION }),
    allowance,
    examples: Object.freeze([
      Object.freeze({ label: 'Routine vendor job', target: 'vendor.demo', amount: 80, purpose: 'synthetic-vendor-payment' }),
      Object.freeze({ label: 'Oversized transfer', target: 'vendor.demo', amount: 900, purpose: 'synthetic-oversized-transfer' }),
      Object.freeze({ label: 'Unapproved production target', target: 'production.database', amount: 20, purpose: 'synthetic-production-change' }),
    ]),
    note: 'Synthetic no-egress challenge. No money, provider credential, or production system is connected.',
  });
}

export async function submitArenaAttempt({
  request,
  sessionId,
  input,
  client,
  now = Date.now(),
}: {
  request: Request;
  sessionId: string;
  input: unknown;
  client?: SupabaseClient;
  now?: number;
}) {
  const store = arenaClient(client);
  const auth = await authenticateArenaRequest(request, sessionId, { client: store, now });
  if (!auth.ok) throw new ArenaServiceError(auth.status, auth.reason);
  if (!exactRecord(input, ['operation_id', 'target', 'amount', 'purpose'])) {
    throw new ArenaServiceError(400, 'arena_action_input_invalid');
  }
  const action: ArenaAction = {
    operation_id: input.operation_id,
    action_type: ARENA_ACTION_TYPE,
    target: input.target,
    amount: input.amount,
    currency: ARENA_CURRENCY,
    purpose: input.purpose,
  } as ArenaAction;
  let binding;
  try {
    binding = deriveArenaActionBinding(action);
  } catch {
    throw new ArenaServiceError(400, 'arena_action_input_invalid');
  }
  const attemptNonce = crypto.randomBytes(32).toString('base64url');
  let attempted: any;
  try {
    attempted = await store.rpc('attempt_arena_action', {
      p_token_hash: auth.token_hash,
      p_session_id: sessionId,
      p_attempt_nonce: attemptNonce,
      p_operation_id: action.operation_id,
      p_action: action,
      p_action_digest: binding.action_digest,
      p_caid: binding.caid,
    });
  } catch {
    throw new ArenaServiceError(503, 'arena_store_unavailable');
  }
  if (attempted.error || attempted.data?.ok !== true) serviceError(attempted.data);
  const result = attempted.data;

  if (result.decision !== 'allow' && result.decision !== 'refuse') {
    throw new ArenaServiceError(503, 'arena_store_decision_invalid');
  }
  if (typeof result.attempt_id !== 'string'
      || !/^arena_attempt_[0-9a-f]{32}$/.test(result.attempt_id)
      || !Number.isSafeInteger(result.remaining_amount)
      || result.remaining_amount < 0 || result.remaining_amount > TOTAL_AMOUNT) {
    throw new ArenaServiceError(503, 'arena_store_result_invalid');
  }

  if (result.decision === 'allow') {
    return Object.freeze({
      attempt_id: result.attempt_id,
      decision: 'allow',
      reason: null,
      remaining_amount: result.remaining_amount,
      action,
      ...binding,
      claim_boundary: ARENA_CLAIM_BOUNDARY,
      note: 'Allowed inside the synthetic no-egress challenge only.',
    });
  }

  if (typeof result.reason !== 'string'
      || typeof result.created_at !== 'string'
      || !Number.isFinite(Date.parse(result.created_at))
      || typeof result.attempt_nonce !== 'string') {
    throw new ArenaServiceError(503, 'arena_store_result_invalid');
  }

  if (result.evidence_status === 'complete' && result.refusal_artifact && result.refusal_digest) {
    const verification = verifyArenaPublicProjection(storedRefusalProjection({
      session: auth.session,
      action,
      attemptId: result.attempt_id,
      reason: result.reason,
      createdAt: result.created_at,
      caid: binding.caid,
      actionDigest: binding.action_digest,
      artifact: result.refusal_artifact,
      refusalDigest: result.refusal_digest,
    }), now);
    if (!verification.integrity_verified) {
      throw new ArenaServiceError(503, 'arena_stored_refusal_invalid');
    }
    return Object.freeze({
      attempt_id: result.attempt_id,
      decision: 'refuse', reason: result.reason,
      remaining_amount: result.remaining_amount,
      action, ...binding,
      refusal_artifact: result.refusal_artifact,
      refusal_digest: result.refusal_digest,
      claim_boundary: ARENA_CLAIM_BOUNDARY,
    });
  }

  const refusedAt = new Date(result.created_at).toISOString();
  const refusalExpiresAt = new Date(Date.parse(refusedAt) + REFUSAL_TTL_MS).toISOString();
  let signed;
  try {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.from(open(auth.session.private_key_encrypted), 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
    signed = signArenaRefusal({
      allowance: auth.session.allowance_profile as ArenaAllowance,
      action,
      reason: result.reason,
      attemptId: result.attempt_id,
      attemptNonce: result.attempt_nonce,
      refusedAt,
      expiresAt: refusalExpiresAt,
      signer: {
        issuer_id: auth.session.issuer_id,
        key_id: auth.session.key_id,
        private_key: privateKey,
      },
    });
    const verification = verifyArenaPublicProjection(storedRefusalProjection({
      session: auth.session,
      action,
      attemptId: result.attempt_id,
      reason: result.reason,
      createdAt: refusedAt,
      caid: binding.caid,
      actionDigest: binding.action_digest,
      artifact: signed.statement,
      refusalDigest: signed.refusal_digest,
    }), now);
    if (!verification.integrity_verified) throw new Error('arena signer output failed verification');
  } catch {
    throw new ArenaServiceError(503, 'arena_signer_unavailable');
  }

  // -- EP-ACTION-REFUSAL-STATEMENT-v2 adoption (additive, opt-in) --
  // signActionRefusalStatement/signActionRefusalStatementV2 both already
  // exist in packages/gate/src/action-refusal-statement.ts; this wires the
  // ALREADY-BUILT v2 hybrid path through the arena's refusal issuance
  // additively. No session in this deployment carries pq_public_key /
  // pq_private_key_encrypted today (the session row has no such column), so
  // this is dormant and byte-identical to the v1-only path above until a
  // session is provisioned with hybrid signer material -- the same posture
  // pq-hybrid-program.md documents for every "dual" adoption: v1 issuance is
  // untouched, and the hybrid twin is minted best-effort alongside it, never
  // in place of it. A v2 signing/verification failure here NEVER fails the
  // request: the v1 refusal above is already committed as the artifact of
  // record.
  let hybridSigned: { statement: any; refusal_digest: string } | null = null;
  if (typeof auth.session.pq_public_key === 'string' && auth.session.pq_public_key.length > 0
      && typeof auth.session.pq_private_key_encrypted === 'string' && auth.session.pq_private_key_encrypted.length > 0) {
    try {
      const pqPrivateKey = open(auth.session.pq_private_key_encrypted);
      const privateKey = crypto.createPrivateKey({
        key: Buffer.from(open(auth.session.private_key_encrypted), 'base64url'),
        format: 'der',
        type: 'pkcs8',
      });
      const candidate = await signArenaRefusalV2({
        allowance: auth.session.allowance_profile as ArenaAllowance,
        action,
        reason: result.reason,
        attemptId: result.attempt_id,
        attemptNonce: result.attempt_nonce,
        refusedAt,
        expiresAt: refusalExpiresAt,
        signer: {
          issuer_id: auth.session.issuer_id,
          key_id: auth.session.key_id,
          private_key: privateKey,
          pq_public_key: auth.session.pq_public_key,
          pq_private_key: pqPrivateKey,
        },
      });
      const hybridVerification = await verifyArenaPublicProjectionV2(storedRefusalProjectionV2({
        session: auth.session,
        action,
        attemptId: result.attempt_id,
        reason: result.reason,
        createdAt: refusedAt,
        caid: binding.caid,
        actionDigest: binding.action_digest,
        artifact: candidate.statement,
        refusalDigest: candidate.refusal_digest,
      }), now);
      if (hybridVerification.integrity_verified) hybridSigned = candidate;
    } catch {
      hybridSigned = null;
    }
  }

  let committed: any;
  try {
    committed = await store.rpc('commit_arena_refusal', {
      p_token_hash: auth.token_hash,
      p_attempt_id: result.attempt_id,
      p_refusal_artifact: signed.statement,
      p_refusal_digest: signed.refusal_digest,
    });
  } catch {
    throw new ArenaServiceError(503, 'arena_store_unavailable');
  }
  if (committed.error || committed.data?.ok !== true) serviceError(committed.data);
  return Object.freeze({
    attempt_id: result.attempt_id,
    decision: 'refuse', reason: result.reason,
    remaining_amount: result.remaining_amount,
    action, ...binding,
    refusal_artifact: signed.statement,
    refusal_digest: signed.refusal_digest,
    claim_boundary: ARENA_CLAIM_BOUNDARY,
    note: 'Technical refusal in a synthetic no-egress challenge; not a legal determination or production event.',
    // Additive hybrid twin (see the adoption note above); absent whenever the
    // session has no pq signer material, which is every session today.
    ...(hybridSigned ? {
      hybrid_refusal_artifact: hybridSigned.statement,
      hybrid_refusal_digest: hybridSigned.refusal_digest,
    } : {}),
  });
}

export async function publishArenaRefusal({
  request,
  sessionId,
  attemptId,
  client,
  now = Date.now(),
}: {
  request: Request;
  sessionId: string;
  attemptId: string;
  client?: SupabaseClient;
  now?: number;
}) {
  const store = arenaClient(client);
  const auth = await authenticateArenaRequest(request, sessionId, { client: store, now });
  if (!auth.ok) throw new ArenaServiceError(auth.status, auth.reason);
  let published: any;
  try {
    published = await store.rpc('publish_arena_refusal', {
      p_token_hash: auth.token_hash,
      p_attempt_id: attemptId,
    });
  } catch {
    throw new ArenaServiceError(503, 'arena_store_unavailable');
  }
  if (published.error || published.data?.ok !== true) serviceError(published.data);
  return Object.freeze({
    share_id: published.data.share_id,
    share_url: `/arena/r/${published.data.share_id}`,
  });
}

export async function loadPublicArenaRefusal(shareId: string, client?: SupabaseClient) {
  if (!/^arena_share_[0-9a-f]{40}$/.test(shareId)) return null;
  const store = arenaClient(client);
  let result: any;
  try {
    result = await store
      .from('arena_shares')
      .select('share_id, public_projection, created_at')
      .eq('share_id', shareId)
      .is('revoked_at', null)
      .maybeSingle();
  } catch {
    throw new ArenaServiceError(503, 'arena_store_unavailable');
  }
  if (result.error) throw new ArenaServiceError(503, 'arena_store_unavailable');
  if (!result.data) return null;
  return Object.freeze({
    share_id: result.data.share_id,
    published_at: result.data.created_at,
    projection: result.data.public_projection,
    verification: verifyArenaPublicProjection(result.data.public_projection),
  });
}

export const ARENA_REFERENCE = Object.freeze({
  challenge_id: CHALLENGE_ID,
  challenge_version: CHALLENGE_VERSION,
  total_amount: TOTAL_AMOUNT,
  max_amount_per_action: MAX_AMOUNT_PER_ACTION,
  allowed_targets: ALLOWED_TARGETS,
});
