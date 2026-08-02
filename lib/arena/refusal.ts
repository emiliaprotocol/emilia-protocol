// SPDX-License-Identifier: Apache-2.0
import type { KeyLike } from 'node:crypto';

import {
  ACTION_REFUSAL_CLAIM_BOUNDARY,
  actionRefusalStatementDigest,
  signActionRefusalStatement,
  verifyActionRefusalStatement,
} from '@/packages/gate/action-refusal-statement.js';
import {
  buildArenaRefusalInput,
  arenaRequirementForReason,
  deriveArenaActionBinding,
  type ArenaAction,
  type ArenaAllowance,
} from './core';

const PUBLIC_PROFILE = 'EP-ARENA-PUBLIC-REFUSAL-v1';
const PUBLIC_BOUNDARY =
  'synthetic_challenge_not_identity_competence_certification_money_or_production_authority';

export function signArenaRefusal({
  allowance,
  action,
  reason,
  attemptId,
  attemptNonce,
  refusedAt,
  expiresAt,
  signer,
}: {
  allowance: ArenaAllowance;
  action: ArenaAction;
  reason: string;
  attemptId: string;
  attemptNonce: string;
  refusedAt: string;
  expiresAt: string;
  signer: { issuer_id: string; key_id: string; private_key: KeyLike };
}) {
  const binding = deriveArenaActionBinding(action);
  const statement = signActionRefusalStatement(buildArenaRefusalInput({
    allowance,
    action,
    binding,
    reason,
    refusalId: `refusal:${attemptId}`,
    relyingPartyId: 'arena:emilia:public',
    nonce: attemptNonce,
    refusedAt,
    expiresAt,
  }) as any, signer);
  return Object.freeze({
    statement,
    refusal_digest: actionRefusalStatementDigest(statement),
    binding,
  });
}

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).every((key) => typeof key === 'string');
}

function canonicalInstant(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const epochMilliseconds = Date.parse(value);
  if (!Number.isFinite(epochMilliseconds)) return null;
  return new Date(epochMilliseconds).toISOString();
}

function refusedResult(reason: string, currentReason = reason) {
  return {
    integrity_verified: false as const,
    currently_valid: false,
    reason,
    current_reason: currentReason,
    accepted: null,
    issuer_trust: 'arena_session_key_from_public_record' as const,
    claim_boundary: PUBLIC_BOUNDARY,
  };
}

/**
 * Verify a public Arena projection. The key is carried by the immutable public
 * record, so this proves artifact integrity and projection consistency—not
 * external issuer identity, civil identity, competence, or authorization.
 */
export function verifyArenaPublicProjection(projection: unknown, now = Date.now()) {
  try {
    if (!isRecord(projection) || projection.profile !== PUBLIC_PROFILE
        || projection.claim_boundary !== PUBLIC_BOUNDARY
        || !isRecord(projection.attempt) || !isRecord(projection.attempt.action)
        || !isRecord(projection.issuer) || !isRecord(projection.refusal_artifact)
        || projection.attempt.decision !== 'refuse'
        || typeof projection.attempt.reason !== 'string'
        || typeof projection.attempt.attempt_id !== 'string'
        || typeof projection.attempt.created_at !== 'string'
        || typeof projection.refusal_digest !== 'string'
        || typeof projection.issuer.issuer_id !== 'string'
        || typeof projection.issuer.key_id !== 'string'
        || typeof projection.issuer.public_key !== 'string'
        || projection.challenge_id !== 'emilia.arena.allowance'
        || projection.challenge_version !== 1) {
      return refusedResult('arena_projection_invalid');
    }
    const binding = deriveArenaActionBinding(projection.attempt.action);
    const expectedRequirement = arenaRequirementForReason(projection.attempt.reason);
    if (binding.caid !== projection.attempt.caid
        || binding.action_digest !== projection.attempt.action_digest
        || expectedRequirement === null
        || projection.refusal_artifact.refusal_id !== `refusal:${projection.attempt.attempt_id}`
        || projection.refusal_artifact.refusal_class !== 'authorization_refused'
        || projection.refusal_artifact.claim_boundary !== ACTION_REFUSAL_CLAIM_BOUNDARY
        || actionRefusalStatementDigest(projection.refusal_artifact) !== projection.refusal_digest) {
      return refusedResult('arena_projection_binding_mismatch');
    }
    const statement = projection.refusal_artifact;
    if (!isRecord(statement.program) || typeof statement.nonce !== 'string') {
      return refusedResult('arena_refusal_invalid');
    }
    const statementRefusedAt = canonicalInstant(statement.refused_at);
    const attemptCreatedAt = canonicalInstant(projection.attempt.created_at);
    if (!Array.isArray(statement.failed_requirement_ids)
        || statement.failed_requirement_ids.length !== 1
        || statement.failed_requirement_ids[0] !== expectedRequirement
        || statementRefusedAt === null
        || attemptCreatedAt === null
        || statementRefusedAt !== attemptCreatedAt) {
      return refusedResult('arena_projection_binding_mismatch');
    }
    const trustedKeys = {
      [projection.issuer.key_id]: {
        issuer_id: projection.issuer.issuer_id,
        public_key: projection.issuer.public_key,
      },
    };
    const expected = {
      caid: binding.caid,
      action_digest: binding.action_digest,
      relying_party_id: 'arena:emilia:public',
      program_id: statement.program.program_id,
      program_version: statement.program.version,
      source_digest: statement.program.source_digest,
      program_digest: statement.program.program_digest,
      nonce: statement.nonce,
    };
    const atIssuance = verifyActionRefusalStatement(statement, {
      trusted_keys: trustedKeys,
      expected,
      now: Date.parse(statement.refused_at),
      max_future_skew_sec: 0,
    });
    if (!atIssuance.verified || atIssuance.refusal_digest !== projection.refusal_digest) {
      return refusedResult(atIssuance.reason || 'arena_refusal_invalid');
    }
    const current = verifyActionRefusalStatement(statement, {
      trusted_keys: trustedKeys,
      expected,
      now,
      max_future_skew_sec: 0,
    });
    return {
      integrity_verified: true as const,
      currently_valid: current.verified,
      reason: null,
      current_reason: current.reason,
      accepted: null,
      issuer_trust: 'arena_session_key_from_public_record' as const,
      refusal_digest: projection.refusal_digest,
      caid: binding.caid,
      action_digest: binding.action_digest,
      claim_boundary: PUBLIC_BOUNDARY,
    };
  } catch {
    return refusedResult('arena_projection_invalid');
  }
}

export const ARENA_PUBLIC_REFUSAL_PROFILE = PUBLIC_PROFILE;
export const ARENA_PUBLIC_CLAIM_BOUNDARY = PUBLIC_BOUNDARY;
