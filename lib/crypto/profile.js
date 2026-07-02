// SPDX-License-Identifier: Apache-2.0
//
// EP-CRYPTO-PROFILE — declared, fail-closed cryptographic boundary.
//
// EP's default signing algorithm is Ed25519 (fast, deterministic, the frozen
// EP-RECEIPT-v1 core). Some regulated buyers require a FIPS-140 boundary, where
// the acceptable set is different (validated modules broadly cover ECDSA P-256 /
// P-384 and RSA; EdDSA is in FIPS 186-5 but validated-module coverage is still
// thin). Rather than silently sign with whatever algorithm the code happens to
// use, a deployment DECLARES its crypto profile, and the system fails closed if
// asked to operate outside it.
//
// This module is the DECLARATION + fail-closed SELECTOR. It is additive and
// opt-in (EP_CRYPTO_PROFILE, default 'default'); it does NOT modify the frozen
// verify/issue core.
//
// IMPORTANT — what 'fips' does and does NOT do here:
//   - It DOES give you a fail-closed gate: with EP_CRYPTO_PROFILE=fips, any
//     attempt to sign/accept an algorithm outside the FIPS set is refused, and
//     gov-readiness (scripts/gov-readiness-check.mjs) asserts the profile is
//     satisfiable (custody + allowed alg) before the deployment is called ready.
//   - It does NOT by itself make EP FIPS-validated. Full FIPS operation ALSO
//     requires (a) signing inside a FIPS 140-validated module (a KMS/HSM custody
//     signer, see lib/key-custody.js), and (b) the verifier accepting P-256
//     issuer signatures — a conformance-gated addition tracked in
//     draft-schrock-ep-pqc / the assurance-classes work. Until (b) ships in the
//     frozen verifier, 'fips' is a policy boundary + custody requirement, not a
//     shipped end-to-end P-256 receipt path. This module is deliberately honest
//     about that seam so no one mistakes "profile set" for "FIPS validated."

const PROFILES = Object.freeze({
  default: Object.freeze({
    id: 'default',
    // Ed25519 for issuer/receipt signing; ES256 (ECDSA P-256) for WebAuthn
    // Class-A device signoffs. Both are in the shipped, conformance-covered core.
    sign_algs: Object.freeze(['Ed25519', 'ES256']),
    hash: 'SHA-256',
    fips_boundary: false,
    description: 'EP default: Ed25519 issuer signatures + ES256 WebAuthn signoffs.',
  }),
  fips: Object.freeze({
    id: 'fips',
    // Conservative FIPS-140 set: ES256 (ECDSA P-256, broadly validated). Ed25519
    // is EXCLUDED by default because validated EdDSA modules are still rare;
    // enable it explicitly only against a module whose FIPS certificate covers
    // EdDSA. Signing MUST occur in a validated module (custody kms/hsm).
    sign_algs: Object.freeze(['ES256']),
    hash: 'SHA-256',
    fips_boundary: true,
    requires_custody: true,
    description: 'FIPS-140 boundary: ES256 only, signed inside a validated module (KMS/HSM custody required).',
  }),
});

export const CRYPTO_PROFILE_IDS = Object.freeze(Object.keys(PROFILES));

/**
 * Resolve the active crypto profile. Fail closed: an unrecognized
 * EP_CRYPTO_PROFILE is a configuration error, not a silent fallback to default.
 * @param {string} [profileId] explicit override (defaults to EP_CRYPTO_PROFILE env, else 'default')
 * @returns {Readonly<{id,sign_algs,hash,fips_boundary,description,requires_custody?}>}
 */
export function getActiveCryptoProfile(profileId) {
  const id = (profileId || process.env.EP_CRYPTO_PROFILE || 'default').trim();
  const profile = PROFILES[id];
  if (!profile) {
    const err = new Error(
      `Unknown EP_CRYPTO_PROFILE "${id}". Allowed: ${CRYPTO_PROFILE_IDS.join(', ')}. Refusing to run with an undeclared crypto boundary (fail closed).`,
    );
    err.code = 'unknown_crypto_profile';
    throw err;
  }
  return profile;
}

/**
 * Is a signing algorithm permitted under a profile? Pure predicate.
 * @param {string} alg canonical alg id ('Ed25519' | 'ES256' | ...)
 */
export function isAlgAllowed(alg, profile = getActiveCryptoProfile()) {
  return profile.sign_algs.includes(alg);
}

/**
 * Fail-closed assertion for a signing algorithm under the active profile. Throws
 * with a stable code so callers can surface it as a config/authorization error
 * rather than sign outside the declared boundary.
 * @returns {{ ok: true, profile: string }}
 */
export function assertAlgAllowed(alg, profile = getActiveCryptoProfile()) {
  if (!isAlgAllowed(alg, profile)) {
    const err = new Error(
      `Algorithm "${alg}" is not permitted under crypto profile "${profile.id}" (allowed: ${profile.sign_algs.join(', ')}). `
      + (profile.fips_boundary
        ? 'This deployment declares a FIPS boundary; signing outside the validated set is refused.'
        : 'Refusing to sign outside the declared crypto boundary.'),
    );
    err.code = 'alg_outside_crypto_profile';
    throw err;
  }
  return { ok: true, profile: profile.id };
}

/**
 * Assert a deployment's config actually SATISFIES its declared profile — used by
 * gov-readiness. A fips profile that isn't backed by a validated module (custody
 * mode kms/hsm) is not truly at its boundary, so we surface that as not-ready.
 * @param {object} opts
 * @param {string} [opts.custodyMode] EP_KEY_CUSTODY_MODE ('kms'|'hsm'|'env'|'local-dev')
 * @param {string} [opts.profileId]
 * @returns {{ ok: boolean, profile: string, reasons: string[] }}
 */
export function assertProfileSatisfied({ custodyMode, profileId } = {}) {
  const profile = getActiveCryptoProfile(profileId);
  const reasons = [];
  if (profile.requires_custody && !['kms', 'hsm'].includes(custodyMode)) {
    reasons.push(
      `crypto profile "${profile.id}" requires signing in a validated module `
      + `(EP_KEY_CUSTODY_MODE=kms or hsm), but custody mode is "${custodyMode || 'unset'}".`,
    );
  }
  return { ok: reasons.length === 0, profile: profile.id, reasons };
}

export const _profilesForTest = PROFILES;
