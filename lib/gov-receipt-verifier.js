// SPDX-License-Identifier: Apache-2.0
//
// Government/high-assurance verifier policy.
//
// Core verification stays in packages/verify and packages/require-receipt. This
// file is the deployment posture wrapper: production pins issuer keys, disables
// inline/self-asserted keys, and runs Trust Receipt verification in strict mode.

import { getGovVerifierConfig } from './env.js';
import { verifyEmiliaReceipt } from '../packages/require-receipt/index.js';
import { verifyTrustReceipt } from '../packages/verify/index.js';

export function productionReceiptVerifierOptions({
  action,
  maxAgeSec = 900,
  allowedOutcomes = ['allow', 'allow_with_signoff'],
  config = getGovVerifierConfig(),
} = {}) {
  return {
    trustedKeys: config.trustedIssuerKeys,
    // Strict mode refuses inline/self-asserted keys; the non-strict public
    // playground still accepts them so the 10-minute wedge works on /api/v1/guarded.
    allowInlineKey: !config.govStrict,
    action,
    maxAgeSec,
    allowedOutcomes,
  };
}

export function verifyReceiptForProduction(doc, opts = {}) {
  return verifyEmiliaReceipt(doc, productionReceiptVerifierOptions(opts));
}

export function assertGovVerifierReady(config = getGovVerifierConfig()) {
  const errors = [];
  if (config.govStrict && config.trustedIssuerKeys.length === 0) {
    errors.push('EP_TRUSTED_ISSUER_KEYS must pin at least one issuer key in production/government mode');
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
