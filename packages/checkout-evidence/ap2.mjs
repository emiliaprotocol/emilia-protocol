// SPDX-License-Identifier: Apache-2.0
/**
 * AP2 v0.2 capture helper.
 *
 * This helper stores the compact native artifacts needed by AP2's dispute
 * verification procedure. It deliberately does not implement AP2 signature,
 * disclosure, constraint, or trust-anchor verification. Supply a native AP2
 * verifier to verifyCheckoutEvidencePacket().
 */

import { _internals } from './index.mjs';

const NAMES = Object.freeze([
  'checkout_mandate',
  'checkout_receipt',
  'payment_mandate',
  'payment_receipt',
]);

export function captureAp2V02Evidence(input, { required = true } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('AP2 evidence must be an object');
  const artifacts = {};
  for (const name of NAMES) {
    const value = input[name];
    if (typeof value !== 'string' || value.length < 16 || value.length > 4 * 1024 * 1024) {
      throw new Error(`AP2 ${name} must be a non-empty compact serialization`);
    }
    artifacts[name] = _internals.artifactEnvelope({
      media_type: 'application/sd-jwt',
      content: value,
    }, `ap2.${name}`);
  }
  return Object.freeze({
    profile: 'ap2-v0.2',
    required: required === true,
    artifacts: Object.freeze(artifacts),
  });
}
