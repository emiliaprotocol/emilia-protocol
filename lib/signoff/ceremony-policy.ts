// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { canonicalize } from '../canonical-json.js';

export const SIGNOFF_CEREMONY_PROFILE = 'EP-SIGNOFF-CEREMONY-v1';

export type SignoffCeremonyPolicy = Readonly<{
  profile: typeof SIGNOFF_CEREMONY_PROFILE;
  minimum_review_ms: number;
  max_approvals: number;
  window_seconds: number;
  confirmation_required: boolean;
}>;

export type SignoffCeremonyBinding = Readonly<{
  profile: typeof SIGNOFF_CEREMONY_PROFILE;
  policy_digest: string;
  confirmation_hash: string;
  review_started_at: string;
  minimum_review_ms: number;
  max_approvals: number;
  window_seconds: number;
}>;

function integerEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^[0-9]+$/.test(raw)) throw new Error(`${name} must be an integer from ${min} through ${max}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} through ${max}`);
  }
  return value;
}

/** Server-owned defaults. Request bodies cannot weaken these controls. */
export function signoffCeremonyPolicy(): SignoffCeremonyPolicy {
  return Object.freeze({
    profile: SIGNOFF_CEREMONY_PROFILE,
    minimum_review_ms: integerEnv('EMILIA_CLASS_A_MINIMUM_REVIEW_MS', 3_000, 3_000, 300_000),
    max_approvals: integerEnv('EMILIA_CLASS_A_MAX_APPROVALS_PER_HOUR', 5, 1, 5),
    window_seconds: 3_600,
    confirmation_required: true,
  });
}

export function signoffCeremonyPolicyDigest(policy: SignoffCeremonyPolicy): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(policy), 'utf8').digest('hex')}`;
}

/**
 * Bounded ASCII phrase derived from the exact action hash. It makes bulk
 * approval require action-specific attention without echoing hostile text from
 * the action into a trusted control prompt.
 */
export function signoffConfirmationPhrase(actionType: unknown, actionHash: unknown): string {
  if (typeof actionType !== 'string' || actionType.length === 0 || actionType.length > 128) {
    throw new TypeError('actionType is required for signoff confirmation');
  }
  if (typeof actionHash !== 'string' || !/^(?:sha256:)?[0-9a-f]{64}$/.test(actionHash)) {
    throw new TypeError('actionHash must be SHA-256 for signoff confirmation');
  }
  const label = actionType
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .toUpperCase()
    .slice(0, 48);
  const digest = actionHash.replace(/^sha256:/, '').slice(-8).toUpperCase();
  return `AUTHORIZE ${label} ${digest}`;
}

export function confirmationPhraseHash(phrase: string): string {
  if (typeof phrase !== 'string' || phrase.length === 0 || phrase.length > 96) {
    throw new TypeError('confirmation phrase must be a bounded non-empty string');
  }
  return `sha256:${crypto.createHash('sha256').update(phrase, 'utf8').digest('hex')}`;
}

export function buildCeremonyBinding({
  policy,
  phrase,
  reviewStartedAt,
}: {
  policy: SignoffCeremonyPolicy;
  phrase: string;
  reviewStartedAt: string;
}): SignoffCeremonyBinding {
  const reviewMs = Date.parse(reviewStartedAt);
  if (!Number.isFinite(reviewMs) || new Date(reviewMs).toISOString() !== reviewStartedAt) {
    throw new TypeError('reviewStartedAt must be canonical ISO time');
  }
  return Object.freeze({
    profile: SIGNOFF_CEREMONY_PROFILE,
    policy_digest: signoffCeremonyPolicyDigest(policy),
    confirmation_hash: confirmationPhraseHash(phrase),
    review_started_at: reviewStartedAt,
    minimum_review_ms: policy.minimum_review_ms,
    max_approvals: policy.max_approvals,
    window_seconds: policy.window_seconds,
  });
}

const signoffCeremony = {
  SIGNOFF_CEREMONY_PROFILE,
  signoffCeremonyPolicy,
  signoffCeremonyPolicyDigest,
  signoffConfirmationPhrase,
  confirmationPhraseHash,
  buildCeremonyBinding,
};

export default signoffCeremony;
