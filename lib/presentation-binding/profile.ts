// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';

import { actionHash, canonicalize } from '../../packages/issue/index.js';
import { verifyDisplayAttestation } from '../wysiwys/render.js';

export const RECEIPT_PRESENTATION_PROFILE = 'EP-PRESENTATION-BINDING-v1';
export const MOBILE_PRESENTATION_PROFILE = 'EP-MOBILE-PRESENTATION-v1';
export const OASNT_DISPLAY_PROFILE = 'OASNT-dsp-v1';

export const PRESENTATION_REFUSAL = Object.freeze({
  UNBOUND: 'display-unbound',
  MISMATCH: 'display-mismatch',
  UNTRUSTED: 'display-untrusted',
});

type JsonRecord = Record<string, any>;

export type NativeOasntResult = {
  valid: boolean;
  action_match: boolean;
};

export type PresentationBindingInput = {
  action: JsonRecord;
  evidence?: JsonRecord | null;
  signedContext?: JsonRecord | null;
  contextVerified?: boolean;
  displaySignerKeys?: Record<string, { public_key: string }>;
  verifyNativeOasnt?: (token: JsonRecord, action: JsonRecord) => NativeOasntResult;
};

export type PresentationBindingResult = {
  valid: boolean;
  profile: string | null;
  reason: string | null;
  checks: Record<string, boolean>;
};

function digestCanonical(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function digestUtf8B64u(value: string): string {
  return crypto.createHash('sha256').update(Buffer.from(value, 'utf8')).digest('base64url');
}

function refusal(reason: string, profile: string | null, checks: Record<string, boolean>): PresentationBindingResult {
  return { valid: false, profile, reason, checks };
}

/**
 * Evaluate presentation evidence only after the caller has verified the base
 * authorization receipt. This function does not confer authority and does not
 * prove what pixels reached a human. It answers the narrower question: does a
 * required, trusted presentation-evidence profile bind to the exact action?
 */
export function verifyPresentationBinding({
  action,
  evidence = null,
  signedContext = null,
  contextVerified = false,
  displaySignerKeys = {},
  verifyNativeOasnt,
}: PresentationBindingInput): PresentationBindingResult {
  const checks = {
    evidence_present: Boolean(evidence),
    native_or_context_verified: false,
    action_bound: false,
    display_digest_match: false,
  };
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    return refusal(PRESENTATION_REFUSAL.UNBOUND, null, checks);
  }

  const profile = typeof evidence.profile === 'string' ? evidence.profile : null;
  if (profile === MOBILE_PRESENTATION_PROFILE) {
    if (!contextVerified || !signedContext || typeof signedContext !== 'object') {
      return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
    }
    checks.native_or_context_verified = true;
    let expected: string;
    let expectedActionHash: string;
    try {
      expected = digestCanonical(evidence.presentation);
      expectedActionHash = actionHash(action);
    } catch {
      return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
    }
    checks.action_bound = signedContext.action_hash === expectedActionHash
      && evidence.action_hash === expectedActionHash;
    checks.display_digest_match = signedContext.display_hash === expected;
    if (!checks.action_bound || !checks.display_digest_match) {
      return refusal(PRESENTATION_REFUSAL.MISMATCH, profile, checks);
    }
    return { valid: true, profile, reason: null, checks };
  }

  if (profile === 'EP-DISPLAY-ATTESTATION-v1') {
    let result;
    try {
      result = verifyDisplayAttestation(action, evidence.attestation, {
        requireDisplayAttestation: true,
        requireSignedAttestation: true,
        displaySignerKeys,
      });
    } catch {
      return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
    }
    checks.native_or_context_verified = Boolean(result.checks?.proof_signed);
    checks.action_bound = Boolean(result.checks?.display_hash_match);
    checks.display_digest_match = Boolean(result.checks?.display_hash_match);
    if (result.valid) return { valid: true, profile, reason: null, checks };
    if (!checks.action_bound || !checks.display_digest_match) {
      return refusal(PRESENTATION_REFUSAL.MISMATCH, profile, checks);
    }
    return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
  }

  if (profile === OASNT_DISPLAY_PROFILE) {
    if (typeof verifyNativeOasnt !== 'function') {
      return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
    }
    let native: NativeOasntResult;
    try {
      native = verifyNativeOasnt(evidence.token, action);
    } catch {
      return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
    }
    checks.native_or_context_verified = native?.valid === true;
    checks.action_bound = native?.action_match === true;
    checks.display_digest_match = typeof evidence.canonical_display === 'string'
      && typeof evidence.token?.dsp === 'string'
      && digestUtf8B64u(evidence.canonical_display) === evidence.token.dsp;
    if (!checks.native_or_context_verified) {
      return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
    }
    if (!checks.action_bound || !checks.display_digest_match) {
      return refusal(PRESENTATION_REFUSAL.MISMATCH, profile, checks);
    }
    return { valid: true, profile, reason: null, checks };
  }

  return refusal(PRESENTATION_REFUSAL.UNTRUSTED, profile, checks);
}
