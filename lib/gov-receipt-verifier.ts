// SPDX-License-Identifier: Apache-2.0
//
// Government/high-assurance verifier policy.
//
// Core verification stays in packages/verify and packages/require-receipt. This
// file is the deployment posture wrapper: production pins issuer keys, disables
// inline/self-asserted keys, and runs Trust Receipt verification in strict mode.

import { getGovVerifierConfig, getPinnedApproverKeys, getPinnedQuorumPolicies } from './env.js';
import { verifyEmiliaReceipt, evaluateReceiptAssurance } from '../packages/require-receipt/index.js';
import { verifyTrustReceipt } from '../packages/verify/index.js';
import { createDefaultActionControlManifest, findActionControl } from '../packages/gate/action-control-manifest.js';

/**
 * @param {object} [params]
 * @param {string} [params.action]
 * @param {number} [params.maxAgeSec]
 * @param {string[]} [params.allowedOutcomes]
 * @param {ReturnType<typeof getGovVerifierConfig>} [params.config]
 */
export function productionReceiptVerifierOptions({
  action,
  maxAgeSec = 900,
  allowedOutcomes = ['allow', 'allow_with_signoff'],
  config = getGovVerifierConfig(),
}: {
  action?: string;
  maxAgeSec?: number;
  allowedOutcomes?: string[];
  config?: ReturnType<typeof getGovVerifierConfig>;
} = {}) {
  return {
    trustedKeys: config.trustedIssuerKeys,
    // Production/reference endpoints never accept self-asserted issuer keys.
    // Integrity-only demos live under /api/demo/* and opt into allowInlineKey
    // locally so the trust boundary is impossible to confuse.
    allowInlineKey: false,
    action,
    maxAgeSec,
    allowedOutcomes,
  };
}

export function verifyReceiptForProduction(doc, opts = {}) {
  return verifyEmiliaReceipt(doc, productionReceiptVerifierOptions(opts));
}

// The default EMILIA action-control manifest is the source of truth for which
// assurance tier a guarded action_type demands (payment.release=class_a,
// deploy.production=quorum, …). Built once — it is deterministic and frozen.
const DEFAULT_ACTION_CONTROL_MANIFEST = createDefaultActionControlManifest();

/**
 * Resolve the assurance tier the action-control manifest requires for an
 * action. Unknown/pass-through actions default to 'software' (no proof needed).
 *
 * @param {string} [action] canonical action_type (absent/unknown actions fall through to 'software')
 * @param {object} [opts]
 * @param {object} [opts.manifest] override manifest (defaults to the built-in)
 * @returns {'software'|'class_a'|'quorum'}
 */
export function requiredAssuranceForAction(action, { manifest = DEFAULT_ACTION_CONTROL_MANIFEST } = {}) {
  const control = action ? findActionControl(manifest, { action_type: action }) : null;
  if (control && control.receipt_required === false) return 'software';
  return control?.assurance_class || 'software';
}

/**
 * Enforce the manifest-required assurance tier for a verified receipt on a
 * production/reference demand endpoint. A Class-A/quorum tier is only PROVEN
 * when the receipt's assurance_proof verifies against pinned approver keys —
 * a self-asserted `allow_with_signoff` / `quorum` field is software-tier until
 * proven, so a software-tier receipt on a quorum action fails closed here.
 *
 * @param {object} doc EP-RECEIPT-v1 document (already signature-verified)
 * @param {object} [opts]
 * @param {string} [opts.action] canonical action_type (used to resolve the tier)
 * @param {'software'|'class_a'|'quorum'} [opts.requiredTier] explicit override
 * @param {object} [opts.approverKeys] pinned approver keys (defaults to env)
 * @param {object} [opts.manifest] action-control manifest override
 * @param {ReturnType<typeof getGovVerifierConfig>} [opts.config] verifier config override
 * @param {object} [opts.quorumPolicies] pinned quorum policies (defaults to env)
 * @param {string} [opts.rpId] relying-party id override
 * @param {string[]} [opts.allowedOrigins] allowed origins override
 * @param {object} [opts.quorumPolicy] explicit quorum policy override
 * @returns {{ ok: boolean, have: string, need: string, reason: string|null, approvers?: string[] }}
 */
export function enforceReceiptAssuranceForProduction(doc, opts: {
  action?: string;
  requiredTier?: 'software' | 'class_a' | 'quorum';
  approverKeys?: object;
  manifest?: object;
  config?: ReturnType<typeof getGovVerifierConfig>;
  quorumPolicies?: object;
  rpId?: string;
  allowedOrigins?: string[];
  quorumPolicy?: object;
} = {}) {
  const need = opts.requiredTier || requiredAssuranceForAction(opts.action, { manifest: opts.manifest });
  const config = opts.config || getGovVerifierConfig();
  const quorumPolicies = opts.quorumPolicies || getPinnedQuorumPolicies();
  return (evaluateReceiptAssurance(doc, need, {
    approverKeys: opts.approverKeys || getPinnedApproverKeys(),
    rpId: opts.rpId || config.rpId,
    allowedOrigins: opts.allowedOrigins || config.allowedOrigins,
    quorumPolicy: opts.quorumPolicy || quorumPolicies[opts.action as string] || null,
  }) as any);
}

export function assertGovVerifierReady(config = getGovVerifierConfig(), {
  action = null,
  requiredTier = 'software',
  approverKeys = getPinnedApproverKeys(),
  quorumPolicies = getPinnedQuorumPolicies(),
} = {}) {
  const errors: string[] = [];
  if (config.trustedIssuerKeys.length === 0) {
    errors.push('EP_TRUSTED_ISSUER_KEYS must pin at least one issuer key for non-demo guarded endpoints');
  }
  if (requiredTier === 'class_a' || requiredTier === 'quorum') {
    if (!approverKeys || Object.keys(approverKeys).length === 0) errors.push('EP_PINNED_APPROVER_KEYS must pin approver identities and keys');
    if (!config.rpId) errors.push('EP_WEBAUTHN_RP_ID must pin the relying-party id');
    if (!Array.isArray(config.allowedOrigins) || config.allowedOrigins.length === 0) errors.push('EP_WEBAUTHN_ALLOWED_ORIGINS must pin at least one exact origin');
  }
  if (requiredTier === 'quorum' && (!action || !quorumPolicies[action])) {
    errors.push(`EP_QUORUM_POLICIES must pin a policy for ${action || 'the guarded action'}`);
  }
  return { ok: errors.length === 0, errors };
}

export function verifyTrustReceiptForGov(receipt, opts: {
  approverKeys?: object;
  logPublicKey?: string;
  rpId?: string | null;
  allowedOrigins?: string[];
  expectedPolicyHash?: string | null;
} = {}) {
  const {
    approverKeys,
    logPublicKey,
    rpId = getGovVerifierConfig().rpId,
    allowedOrigins = getGovVerifierConfig().allowedOrigins,
    expectedPolicyHash = getGovVerifierConfig().expectedPolicyHash,
  } = opts;
  // verifyTrustReceipt's declared options type requires approverKeys/logPublicKey
  // and only string|undefined (not null) for rpId/expectedPolicyHash; this gov
  // wrapper is deliberately more permissive (matches verifyTrustReceipt's own
  // fail-closed handling of missing/null values), so the boundary is asserted
  // here rather than tightened.
  const result = verifyTrustReceipt(receipt, {
    approverKeys: approverKeys || {},
    logPublicKey,
    strict: true,
    rpId,
    allowedOrigins,
    expectedPolicyHash,
  } as Parameters<typeof verifyTrustReceipt>[1]);
  return {
    ...result,
    gov: {
      ok: result.valid && result.strict?.enabled === true && result.strict?.valid === true,
      strict_required: true,
    },
  };
}
