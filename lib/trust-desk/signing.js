// Generated from signing.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * AI Trust Desk — signing-key resolution.
 *
 * @license Apache-2.0
 *
 * One accessor used by BOTH the minter (sign side) and the buyer-verify
 * endpoint (verify side) so they can never disagree on which key signed a
 * claim. HMAC today; an EP Commit receipt replaces the signature in v1.1
 * while the envelope shape stays stable.
 *
 * Key resolution:
 *   1. ATD_SIGNING_KEY (production — required)
 *   2. dev fallback (non-production only, loud warning) so the pipeline runs
 *      locally and in CI without secret provisioning. The fallback key is
 *      deterministic, so a locally-signed claim still verifies locally.
 */
import { logger } from '../logger.js';
import { sha256 } from '../crypto.js';
// Deterministic, obviously-non-secret dev key. Never used in production:
// getSigningKey() throws in production when ATD_SIGNING_KEY is unset.
const DEV_FALLBACK_KEY = 'atd-dev-signing-key-not-for-production-use';
let _warned = false;
/**
 * Returns the active HMAC signing key.
 * Throws if production and ATD_SIGNING_KEY is unset (fail closed).
 */
export function getSigningKey() {
    const envKey = process.env.ATD_SIGNING_KEY;
    if (envKey)
        return envKey;
    if (process.env.NODE_ENV === 'production') {
        throw new Error('ATD_SIGNING_KEY is required in production — refusing to sign trust claims with a dev key');
    }
    if (!_warned) {
        logger.warn('trust-desk: ATD_SIGNING_KEY unset — using dev fallback key (non-production only)');
        _warned = true;
    }
    return DEV_FALLBACK_KEY;
}
/**
 * Public, non-secret fingerprint of the active signing key. Safe to expose
 * on the verify endpoint so a buyer can confirm two claims were signed by the
 * same key without ever seeing the key itself.
 */
export function signingKeyFingerprint() {
    return `atdk_${sha256(getSigningKey()).slice(0, 16)}`;
}
