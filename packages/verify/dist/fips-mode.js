// SPDX-License-Identifier: Apache-2.0
/**
 * EP-FIPS-MODE-v1 -- runtime crypto posture reporting and operation policy
 * for EP deployments that run against a FIPS 140-3 validated OpenSSL provider.
 *
 * WHAT THIS EARNS, AND NOTHING MORE. Running this module in a process whose
 * OpenSSL is operating under a CMVP-validated FIPS provider earns exactly one
 * sentence:
 *
 *     "FIPS-based algorithms, with a validated-provider deployment mode."
 *
 * That sentence is the ceiling: EP is not FIPS compliant and not FIPS validated.
 * No EP package, receipt, or deployment carries a CMVP certificate.
 * Validation is a property of a CRYPTOGRAPHIC MODULE, awarded to that module by
 * the NIST/CCCS Cryptographic Module Validation Program (CMVP) against a
 * specific security policy, on specific platforms, at a specific version. It is
 * never a property of an application that links the module. EP is an
 * application. This module exists partly so nobody has to take that on faith:
 * it REPORTS the posture instead of asserting a status.
 *
 * The repository-wide language-governance guard
 * (scripts/check-language-governance.ts) enforces the same boundary across the
 * whole repo, refusing the compliant/validated/certified forms of that claim in
 * public-facing files unless the line negates them.
 *
 * WHAT "FIPS MODE ACTIVE" ACTUALLY MEANS. crypto.getFips() === 1 means the
 * running Node process has asked OpenSSL to operate in FIPS mode. Four things
 * it does NOT mean:
 *   1. It does not mean a working FIPS provider is loaded. This was measured,
 *      not assumed: on Node v26.5.0 with statically linked OpenSSL 3.6.3 and no
 *      fipsmodule configuration, crypto.setFips(true) SUCCEEDS and getFips()
 *      returns 1, after which every EVP operation, SHA-256 included, fails with
 *      ERR_OSSL_EVP_UNSUPPORTED. The flag is set and nothing works. That is why
 *      this module probes an actual digest and reports `openssl_operational`
 *      alongside the flag, and why assertClassicalFips() requires both.
 *   2. It does not mean the provider on this machine is the CMVP-validated
 *      build. An operator can build a FIPS provider from source; only the exact
 *      validated binary on a validated platform is inside a certificate.
 *   3. It does not cover anything implemented in JavaScript. Nothing in a JS
 *      implementation is inside any validated module boundary, no matter what
 *      getFips() returns.
 *   4. It does not make the application compliant with any policy regime. That
 *      is an assessment about a system, performed by an assessor.
 *
 * THE ED25519 TRAP. "The operation succeeded" and "the operation was inside the
 * validated boundary" are different facts, and for Ed25519 they diverge. EdDSA
 * is an approved signature algorithm under NIST FIPS 186-5 (effective
 * 2023-02-03), yet neither of upstream OpenSSL's own certificates lists it as
 * Approved: CMVP #4282 (FIPS 140-2, OpenSSL 3.0.8/3.0.9) and CMVP #4985 (FIPS
 * 140-3, OpenSSL 3.1.2) both place Ed25519 and Ed448 in their non-Approved
 * tables. Meanwhile OpenSSL 3.0.x REGISTERS Ed25519 with property fips=yes, so
 * a 3.0.x deployment signs Ed25519 happily under an active FIPS mode, outside
 * the certificate, with no error. (3.1.x through 3.3.x register it fips=no, so
 * it fails there; 3.4.0 onward register it fips=yes again, and no upstream
 * certificate covers 3.4 or 3.5 yet.) Because no runtime check can settle
 * this, boundary membership is an OPERATOR DECLARATION read off the security
 * policy, and an undeclared boundary refuses. Certificate-by-certificate detail
 * is in docs/deployment/FIPS-MODE.md.
 *
 * THE ML-DSA TRUTH, HARD-CODED. EP's ML-DSA-65 (FIPS 204) backend is
 * @noble/post-quantum, a pure-JavaScript implementation. It is not a validated
 * module, it is not inside any CMVP certificate, and it does not become one by
 * running in a process with FIPS mode active. `mldsa_validated_module` is
 * therefore the literal `false` in every posture this module can produce; it is
 * not a probe result and no option changes it. A deployment that wants ML-DSA
 * operations under a FIPS posture must acknowledge that explicitly by passing
 * `allow_unvalidated_mldsa: true`. The default is a named REFUSAL.
 *
 * WHAT THIS MODULE DOES NOT DO. It DECIDES; it does not wrap signing or
 * verification. It has no dependency on the agility, hybrid, or issuance
 * modules and none of them import it. Integrators consult
 * checkOperationPolicy() at their own call sites (see the one-line adoption
 * recipe in docs/deployment/FIPS-MODE.md) and refuse on `permitted === false`.
 *
 * FAIL-CLOSED, NEVER THROWS. Every exported function returns a named,
 * structured result. Malformed input, an unknown algorithm, or an
 * undeterminable FIPS status is a refusal carrying a reason, never an
 * exception and never a silent pass. An INDETERMINATE posture never authorizes.
 *
 * ZERO DEPENDENCIES. node:crypto and process only.
 *
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
export const FIPS_MODE_VERSION = 'EP-FIPS-MODE-v1';
/**
 * The closed set of algorithm identifiers this policy module answers for.
 * Ed25519 and ML-DSA-65 mirror the EP-SIG-AGILITY-v1 registry; ES256 is the
 * EP-CRYPTO-PROFILE `fips` profile's signing algorithm; SHA-256 is the digest
 * under every EP canonicalization and Merkle path. An identifier outside this
 * set is a REFUSAL ('unknown_algorithm'), never a pass-through.
 */
export const FIPS_POLICY_ALGORITHMS = Object.freeze([
    'Ed25519',
    'ES256',
    'SHA-256',
    'ML-DSA-65',
]);
export const FIPS_REASONS = Object.freeze({
    /** FIPS mode is verifiably NOT active in this process. */
    FIPS_MODE_INACTIVE: 'fips_mode_inactive',
    /** This build cannot report a FIPS status at all. Indeterminate, not "off". */
    FIPS_STATUS_UNAVAILABLE: 'fips_status_unavailable',
    /**
     * The FIPS flag is set but OpenSSL cannot service a basic approved operation.
     * The overwhelmingly common cause is --force-fips or setFips(true) on a build
     * with no fipsmodule.cnf / no FIPS provider available.
     */
    OPENSSL_PROVIDER_NOT_OPERATIONAL: 'openssl_provider_not_operational',
    /** FIPS flag is set and the OpenSSL liveness probe was skipped. Indeterminate. */
    OPENSSL_PROVIDER_UNPROBED: 'openssl_provider_unprobed',
    /** ML-DSA here is pure JavaScript, outside every validated module boundary. */
    MLDSA_IMPLEMENTATION_UNVALIDATED: 'mldsa_implementation_unvalidated',
    /** FIPS mode is active and the selected provider has no working Ed25519. */
    ED25519_UNAVAILABLE_IN_PROVIDER: 'ed25519_unavailable_in_provider',
    /** FIPS mode is active and Ed25519 support was never probed. Indeterminate. */
    ED25519_PROVIDER_SUPPORT_UNKNOWN: 'ed25519_provider_support_unknown',
    /**
     * Ed25519 works, but the operator declared it OUTSIDE their provider's
     * validated boundary. This is the OpenSSL 3.0.x trap: the provider signs
     * happily while CMVP certificate #4282 lists Ed25519 as non-Approved.
     */
    ED25519_OUTSIDE_VALIDATED_BOUNDARY: 'ed25519_outside_validated_boundary',
    /**
     * FIPS mode is active and the operator never declared whether their
     * certificate covers Ed25519. A runtime probe cannot answer this, so an
     * undeclared boundary is INDETERMINATE and does not authorize.
     */
    ED25519_BOUNDARY_UNDECLARED: 'ed25519_boundary_undeclared',
    /** Algorithm identifier outside the closed registry above. */
    UNKNOWN_ALGORITHM: 'unknown_algorithm',
    /** The posture argument is not a posture object this module produced. */
    MALFORMED_POSTURE: 'malformed_posture',
});
/** The single ML-DSA backend EP ships. Named, so the posture is auditable. */
const MLDSA_BACKEND = '@noble/post-quantum (pure JavaScript, FIPS 204 ML-DSA-65)';
// ---------------------------------------------------------------------------
// Probes (defensive: node:crypto's FIPS surface behaves differently across
// builds, and a posture reporter that throws is worse than useless)
// ---------------------------------------------------------------------------
/**
 * Read the process FIPS status without ever throwing.
 *
 * crypto.getFips() is documented to return 1 when FIPS mode is on, but it is
 * absent on some builds and throws on others (notably builds compiled without
 * FIPS support, where touching the FIPS surface raises
 * ERR_CRYPTO_FIPS_UNAVAILABLE). Both of those are 'unavailable': we do not
 * know, which is not the same as knowing it is off.
 */
export function readFipsStatus() {
    try {
        const getFips = crypto.getFips;
        if (typeof getFips !== 'function')
            return 'unavailable';
        const value = getFips.call(crypto);
        if (value === 1 || value === true)
            return 'active';
        if (value === 0 || value === false)
            return 'inactive';
        return 'unavailable';
    }
    catch {
        return 'unavailable';
    }
}
/**
 * Probe whether the OpenSSL path can service a basic approved operation, by
 * taking an actual SHA-256 digest. Returns false on any failure, never throws.
 *
 * MEASURED, NOT ASSUMED: on a Node build with no FIPS provider configured,
 * crypto.setFips(true) succeeds and getFips() returns 1, yet this probe fails
 * with ERR_OSSL_EVP_UNSUPPORTED. Reporting the flag without this probe would
 * describe such a process as "FIPS mode active" when in fact no cryptography
 * works at all.
 */
export function probeOpensslOperational() {
    try {
        return crypto.createHash('sha256').update('ep-fips-probe').digest('hex').length === 64;
    }
    catch {
        return false;
    }
}
/**
 * Probe whether Ed25519 actually works in this process: generate a key pair,
 * sign a fixed message, verify the signature. Returns false on any failure and
 * NEVER throws.
 *
 * This exists because Ed25519's availability under an active FIPS mode is a
 * property of the selected OpenSSL FIPS provider version, and a provider that
 * does not carry Ed25519 makes these calls fail rather than silently producing
 * a signature from outside the boundary. A runtime probe is the only honest
 * answer; see docs/deployment/FIPS-MODE.md for which provider versions carry
 * which algorithms.
 */
export function probeEd25519() {
    try {
        const pair = crypto.generateKeyPairSync('ed25519');
        const message = Buffer.from('ep-fips-probe');
        const sig = crypto.sign(null, message, pair.privateKey);
        return crypto.verify(null, message, pair.publicKey, sig) === true;
    }
    catch {
        return false;
    }
}
/**
 * Probe results memoized per observed FIPS status, so that consulting the
 * policy on every operation does not re-run an Ed25519 key generation. The key
 * is the status itself: flipping FIPS mode at runtime (crypto.setFips) changes
 * the key and re-runs the probes, so the cache can never report a stale answer
 * across a mode change.
 */
const PROBE_CACHE = new Map();
function probesFor(status) {
    const cached = PROBE_CACHE.get(status);
    if (cached)
        return cached;
    const fresh = { openssl: probeOpensslOperational(), ed25519: probeEd25519() };
    PROBE_CACHE.set(status, fresh);
    return fresh;
}
/** Discard memoized probe results. Exposed for tests and for operators who
 * reconfigure providers mid-process. Never throws. */
export function resetFipsProbeCache() {
    PROBE_CACHE.clear();
}
// ---------------------------------------------------------------------------
// getFipsPosture
// ---------------------------------------------------------------------------
/**
 * Report the crypto posture of the RUNNING process. Never throws.
 *
 * The result is a plain, JSON-serializable object with no timestamps and no
 * randomness, so it is stable enough to log at startup, attach to an assurance
 * package, or compare across two machines.
 */
export function getFipsPosture(options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const fips_status = readFipsStatus();
    let openssl_version = null;
    let node_version = null;
    try {
        const versions = globalThis
            .process?.versions;
        if (versions && typeof versions.openssl === 'string')
            openssl_version = versions.openssl;
        if (versions && typeof versions.node === 'string')
            node_version = versions.node;
    }
    catch {
        // leave both null
    }
    const probes = opts.probe === false ? null : probesFor(fips_status);
    return {
        version: FIPS_MODE_VERSION,
        fips_status,
        fips_mode_active: fips_status === 'active',
        openssl_version,
        node_version,
        openssl_operational: probes === null ? null : probes.openssl,
        ed25519_operational: probes === null ? null : probes.ed25519,
        ed25519_in_validated_boundary: typeof opts.ed25519InValidatedBoundary === 'boolean'
            ? opts.ed25519InValidatedBoundary
            : null,
        mldsa_backend: MLDSA_BACKEND,
        // Hard-coded truth. A pure-JavaScript FIPS 204 implementation is not a
        // CMVP-validated module and never becomes one at runtime.
        mldsa_validated_module: false,
    };
}
/** One-line, log-friendly rendering of a posture. Never throws. */
export function formatFipsPosture(posture) {
    if (!isFipsPosture(posture))
        return `${FIPS_MODE_VERSION} posture=malformed`;
    return [
        FIPS_MODE_VERSION,
        `fips=${posture.fips_status}`,
        `openssl=${posture.openssl_version ?? 'unknown'}`,
        `node=${posture.node_version ?? 'unknown'}`,
        `openssl_operational=${tri(posture.openssl_operational)}`,
        `ed25519_operational=${tri(posture.ed25519_operational)}`,
        `ed25519_in_validated_boundary=${posture.ed25519_in_validated_boundary === null ? 'undeclared' : String(posture.ed25519_in_validated_boundary)}`,
        'mldsa_validated_module=false',
    ].join(' ');
}
function tri(value) {
    return value === null ? 'unprobed' : String(value);
}
/** Structural check so an arbitrary object cannot masquerade as a posture. */
function isFipsPosture(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const p = value;
    if (p.fips_status !== 'active' && p.fips_status !== 'inactive' && p.fips_status !== 'unavailable') {
        return false;
    }
    if (typeof p.fips_mode_active !== 'boolean')
        return false;
    if (p.openssl_operational !== null && typeof p.openssl_operational !== 'boolean')
        return false;
    if (p.ed25519_operational !== null && typeof p.ed25519_operational !== 'boolean')
        return false;
    if (p.ed25519_in_validated_boundary !== null
        && typeof p.ed25519_in_validated_boundary !== 'boolean')
        return false;
    return true;
}
function resolvePosture(supplied) {
    if (supplied === undefined)
        return getFipsPosture();
    return isFipsPosture(supplied) ? supplied : null;
}
// ---------------------------------------------------------------------------
// assertClassicalFips
// ---------------------------------------------------------------------------
/**
 * ok:true ONLY when FIPS mode is verifiably active AND OpenSSL-backed
 * ("classical") operations verifiably work in this process. Both conditions
 * are required, because the flag alone is not evidence of anything: see the
 * measured ERR_OSSL_EVP_UNSUPPORTED case in the module header.
 *
 * Refusal reasons, all named:
 *   - 'fips_mode_inactive'              -- getFips() answered 0.
 *   - 'fips_status_unavailable'         -- no answer obtainable. Indeterminate.
 *   - 'openssl_provider_not_operational'-- flag set, SHA-256 probe failed.
 *   - 'openssl_provider_unprobed'       -- flag set, probe skipped. Indeterminate.
 *   - 'malformed_posture'               -- the supplied posture is not ours.
 *
 * ok:true still does not mean the deployment is FIPS 140-3 validated. It means
 * the process asked OpenSSL for FIPS mode, OpenSSL said yes, and an approved
 * operation actually completed. Whether the provider binary on this host is the
 * CMVP-validated one, on a validated platform, at a validated version, is an
 * operator fact recorded in docs/deployment/FIPS-MODE.md, not something any
 * amount of runtime probing can establish.
 */
export function assertClassicalFips(options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const posture = resolvePosture(opts.posture);
    if (!posture) {
        return {
            ok: false,
            reason: FIPS_REASONS.MALFORMED_POSTURE,
            posture: getFipsPosture({ probe: false }),
        };
    }
    if (posture.fips_status !== 'active') {
        const reason = posture.fips_status === 'inactive'
            ? FIPS_REASONS.FIPS_MODE_INACTIVE
            : FIPS_REASONS.FIPS_STATUS_UNAVAILABLE;
        return { ok: false, reason, posture };
    }
    if (posture.openssl_operational === false) {
        return { ok: false, reason: FIPS_REASONS.OPENSSL_PROVIDER_NOT_OPERATIONAL, posture };
    }
    if (posture.openssl_operational === null) {
        return { ok: false, reason: FIPS_REASONS.OPENSSL_PROVIDER_UNPROBED, posture };
    }
    return { ok: true, reason: null, posture };
}
// ---------------------------------------------------------------------------
// mldsaPolicy
// ---------------------------------------------------------------------------
/**
 * The explicit-flag machinery for ML-DSA.
 *
 * The acknowledgment is ARMED whenever FIPS mode is not verifiably inactive,
 * that is for fips_status 'active' and for 'unavailable'. 'unavailable' arms it
 * because an indeterminate posture never authorizes: a process that cannot say
 * whether it is running under a validated provider is not a process that gets
 * to run unvalidated post-quantum signing by default.
 *
 * On a plainly non-FIPS deployment (fips_status 'inactive', which is the normal
 * case and what EP's own test suite runs under) the acknowledgment is not
 * required and ML-DSA is permitted, because there is no FIPS posture to
 * contradict. This is exactly why adopting checkOperationPolicy() at ML-DSA
 * call sites does not change behavior for existing non-FIPS deployments.
 *
 * Only the literal `true` acknowledges. A truthy string, 1, or {} does not.
 */
export function mldsaPolicy(options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const posture = resolvePosture(opts.posture);
    const acknowledged = opts.allow_unvalidated_mldsa === true;
    if (!posture) {
        return {
            permitted: false,
            reason: FIPS_REASONS.MALFORMED_POSTURE,
            acknowledgment_required: true,
            acknowledged,
            fips_status: 'unavailable',
            validated_module: false,
        };
    }
    const acknowledgment_required = posture.fips_status !== 'inactive';
    if (!acknowledgment_required || acknowledged) {
        return {
            permitted: true,
            reason: null,
            acknowledgment_required,
            acknowledged,
            fips_status: posture.fips_status,
            validated_module: false,
        };
    }
    return {
        permitted: false,
        reason: FIPS_REASONS.MLDSA_IMPLEMENTATION_UNVALIDATED,
        acknowledgment_required,
        acknowledged,
        fips_status: posture.fips_status,
        validated_module: false,
    };
}
// ---------------------------------------------------------------------------
// checkOperationPolicy -- the one call site integrators consult
// ---------------------------------------------------------------------------
function isPolicyAlgorithm(alg) {
    return typeof alg === 'string'
        && FIPS_POLICY_ALGORITHMS.includes(alg);
}
/**
 * Decide whether one cryptographic operation is permitted under the given
 * posture. This is the function issuance and verification call sites consult;
 * it never performs, wraps, or intercepts the operation itself.
 *
 * Decision table:
 *
 *   alg outside the closed registry  -> REFUSE 'unknown_algorithm'
 *   posture not a posture object     -> REFUSE 'malformed_posture'
 *
 *   ML-DSA-65   -> mldsaPolicy(): permitted when FIPS is verifiably inactive,
 *                  or when allow_unvalidated_mldsa === true. Otherwise REFUSE
 *                  'mldsa_implementation_unvalidated'.
 *
 *   Ed25519,    -> all OpenSSL-backed. When FIPS mode is NOT active they are
 *   ES256,         permitted and the provider question does not arise. Under an
 *   SHA-256        ACTIVE FIPS mode, in order:
 *                    openssl_operational === false -> REFUSE
 *                      'openssl_provider_not_operational'
 *                    openssl_operational === null  -> REFUSE
 *                      'openssl_provider_unprobed'
 *                  and then, for Ed25519 only, because Ed25519 is neither
 *                  carried by every OpenSSL FIPS provider version nor Approved
 *                  in every certificate:
 *                    ed25519_operational === false -> REFUSE
 *                      'ed25519_unavailable_in_provider'
 *                    ed25519_operational === null  -> REFUSE
 *                      'ed25519_provider_support_unknown'
 *                    ed25519_in_validated_boundary === false -> REFUSE
 *                      'ed25519_outside_validated_boundary'
 *                    ed25519_in_validated_boundary === null  -> REFUSE
 *                      'ed25519_boundary_undeclared'
 *                  Unprobed and undeclared are both INDETERMINATE, and
 *                  indeterminate never authorizes. The last two checks exist
 *                  because the runtime says yes on OpenSSL 3.0.x while
 *                  certificate #4282 says Ed25519 is non-Approved.
 *                  (SHA-256 covers EP canonicalization digests and Merkle
 *                  hashing, which go through node:crypto createHash and are
 *                  therefore OpenSSL-backed, not JavaScript.)
 *
 * `permitted: true` is a statement about this process's posture, never a
 * statement that the operation or its output is FIPS 140-3 validated.
 */
export function checkOperationPolicy(alg, posture, options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const acknowledged = opts.allow_unvalidated_mldsa === true;
    const algLabel = typeof alg === 'string' ? alg : null;
    if (!isPolicyAlgorithm(alg)) {
        return {
            alg: algLabel,
            permitted: false,
            reason: FIPS_REASONS.UNKNOWN_ALGORITHM,
            boundary: null,
            fips_status: null,
            acknowledged,
        };
    }
    const resolved = resolvePosture(posture);
    if (!resolved) {
        return {
            alg,
            permitted: false,
            reason: FIPS_REASONS.MALFORMED_POSTURE,
            boundary: null,
            fips_status: null,
            acknowledged,
        };
    }
    if (alg === 'ML-DSA-65') {
        const decision = mldsaPolicy({ posture: resolved, allow_unvalidated_mldsa: acknowledged });
        return {
            alg,
            permitted: decision.permitted,
            reason: decision.reason,
            boundary: 'javascript_outside_any_validated_module',
            fips_status: resolved.fips_status,
            acknowledged,
        };
    }
    // Everything below is OpenSSL-backed. Under an ACTIVE FIPS mode the provider
    // must be shown to work before any of it is permitted; the flag alone is not
    // evidence (see the module header's measured ERR_OSSL_EVP_UNSUPPORTED case).
    const refuse = (reason) => ({
        alg,
        permitted: false,
        reason,
        boundary: 'openssl_provider',
        fips_status: resolved.fips_status,
        acknowledged,
    });
    if (resolved.fips_status === 'active') {
        if (resolved.openssl_operational === false) {
            return refuse(FIPS_REASONS.OPENSSL_PROVIDER_NOT_OPERATIONAL);
        }
        if (resolved.openssl_operational === null) {
            return refuse(FIPS_REASONS.OPENSSL_PROVIDER_UNPROBED);
        }
        if (alg === 'Ed25519') {
            if (resolved.ed25519_operational === false) {
                return refuse(FIPS_REASONS.ED25519_UNAVAILABLE_IN_PROVIDER);
            }
            if (resolved.ed25519_operational === null) {
                return refuse(FIPS_REASONS.ED25519_PROVIDER_SUPPORT_UNKNOWN);
            }
            // Ed25519 WORKS here. That is not the same as being inside the
            // certificate, and on OpenSSL 3.0.x it demonstrably is not.
            if (resolved.ed25519_in_validated_boundary === false) {
                return refuse(FIPS_REASONS.ED25519_OUTSIDE_VALIDATED_BOUNDARY);
            }
            if (resolved.ed25519_in_validated_boundary === null) {
                return refuse(FIPS_REASONS.ED25519_BOUNDARY_UNDECLARED);
            }
        }
    }
    return {
        alg,
        permitted: true,
        reason: null,
        boundary: 'openssl_provider',
        fips_status: resolved.fips_status,
        acknowledged,
    };
}
//# sourceMappingURL=fips-mode.js.map