// SPDX-License-Identifier: Apache-2.0
//
// Government/high-assurance verifier policy.
//
// Core verification stays in packages/verify and packages/require-receipt. This
// file is the deployment posture wrapper: production pins issuer keys, disables
// inline/self-asserted keys, and runs Trust Receipt verification in strict mode.

import { getGovVerifierConfig, getPinnedApproverKeys } from './env.js';
import { verifyEmiliaReceipt, evaluateReceiptAssurance } from '../packages/require-receipt/index.js';
import { verifyTrustReceipt } from '../packages/verify/index.js';
import { createDefaultActionControlManifest, findActionControl } from '../packages/gate/action-control-manifest.js';

export function productionReceiptVerifierOptions({
  action,
  maxAgeSec = 900,
  allowedOutcomes = ['allow', 'allow_with_signoff'],
  config = getGovVerifierConfig(),
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
 * @param {string} action canonical action_type
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
 * @returns {{ ok: boolean, have: string, need: string, reason: string }}
 */
export function enforceReceiptAssuranceForProduction(doc, opts = {}) {
  const need = opts.requiredTier || requiredAssuranceForAction(opts.action, { manifest: opts.manifest });
  return evaluateReceiptAssurance(doc, need, {
    approverKeys: opts.approverKeys || getPinnedApproverKeys(),
  });
}

export function assertGovVerifierReady(config = getGovVerifierConfig()) {
  const errors = [];
  if (config.trustedIssuerKeys.length === 0) {
    errors.push('EP_TRUSTED_ISSUER_KEYS must pin at least one issuer key for non-demo guarded endpoints');
  }
  return { ok: errors.length === 0, errors };
}

export function verifyTrustReceiptForGov(receipt, opts = {}) {
  const {
    approverKeys,
    logPublicKey,
    rpId = getGovVerifierConfig().rpId,
    expectedPolicyHash = getGovVerifierConfig().expectedPolicyHash,
  } = opts;
  const result = verifyTrustReceipt(receipt, {
    approverKeys,
    logPublicKey,
    strict: true,
    rpId,
    expectedPolicyHash,
  });
  return {
    ...result,
    gov: {
      ok: result.valid && result.strict?.enabled === true && result.strict?.valid === true,
      strict_required: true,
    },
  };
}
