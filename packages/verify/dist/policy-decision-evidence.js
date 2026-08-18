// SPDX-License-Identifier: Apache-2.0
/**
 * Signed local-policy decision evidence for AEB composition.
 *
 * This module does not implement a policy engine and does not convert a
 * machine-policy ALLOW into human authorization. It lets an OPA or Cerbos
 * integration sign the exact decision it observed, then exposes that result as
 * one relying-party-pinned AEB evidence leg. A consequential Gate policy can
 * require this leg together with independent human authorization evidence.
 */
import crypto from 'node:crypto';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- narrowed and cross-checked below.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
import { signAgileSet, verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, } from './pq-signature-agility.js';
import { strictJsonGate } from './strict-json.js';
export const POLICY_DECISION_EVIDENCE_VERSION = 'EP-POLICY-DECISION-EVIDENCE-v1';
export const POLICY_DECISION_EVIDENCE_TYP = 'ep-policy-decision-evidence+jwt';
export const POLICY_DECISION_EVIDENCE_ADAPTER_ID = 'native:policy-decision-evidence';
export const POLICY_DECISION_EVIDENCE_ADAPTER_VERSION = '1';
export const POLICY_DECISION_EVIDENCE_CONFIG_VERSION = 'EP-POLICY-DECISION-EVIDENCE-CONFIG-v1';
export const POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION = 'EP-POLICY-DECISION-EVIDENCE-ROOT-v1';
export const POLICY_DECISION_EVIDENCE_MAPPING_VERSION = 'EP-POLICY-DECISION-CAID-MAPPING-v1';
export const POLICY_DECISION_EVIDENCE_MAPPER_ID = 'mapper:policy-decision-exact-action-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+\.[1-9][0-9]*$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#@-]{0,511}$/;
const URI_RE = /^https:\/\/[^\s]+$/;
const HEADER_KEYS = new Set(['alg', 'typ', 'kid']);
const CLAIM_KEYS = new Set([
    'ep_version', 'iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'engine', 'policy_id',
    'policy_digest', 'policy_decision', 'action', 'action_digest', 'native_decision_ref',
    'native_result_digest',
]);
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
    'allowed_engines', 'allowed_policy_digests', 'clock_skew_seconds', 'max_decision_age_seconds',
]);
const SUBJECT_KEYS = new Set(['id', 'kind']);
const ROOT_KEYS = new Set(['@version', 'issuer', 'key_id', 'algorithm', 'public_key']);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, allowed) {
    const keys = Reflect.ownKeys(value);
    return keys.length === allowed.size
        && keys.every((key) => typeof key === 'string' && allowed.has(key));
}
function validIdentifier(value) {
    return typeof value === 'string' && IDENTIFIER_RE.test(value)
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function validRole(value) {
    return validIdentifier(value) && /^[a-z][a-z0-9-]*$/.test(value);
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function safeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function sortedUniqueStrings(value, predicate) {
    return Array.isArray(value) && value.length > 0 && value.every(predicate)
        && new Set(value).size === value.length;
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ invalid_value: true });
    }
}
function sameDigest(left, right) {
    try {
        return digestAeb(left) === digestAeb(right);
    }
    catch {
        return false;
    }
}
function canonicalAction(value, actionType) {
    if (!isRecord(value) || typeof value.action_type !== 'string'
        || !ACTION_TYPE_RE.test(value.action_type)
        || (actionType !== undefined && value.action_type !== actionType)
        || !isRecord(value.parameters))
        return null;
    try {
        return JSON.parse(canonicalizeAeb(value));
    }
    catch {
        return null;
    }
}
function validPrivateKey(key) {
    return key instanceof crypto.KeyObject && key.type === 'private' && key.asymmetricKeyType === 'ed25519';
}
function decodeBase64url(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    try {
        const decoded = Buffer.from(value, 'base64url');
        return decoded.length > 0 && decoded.toString('base64url') === value ? decoded : null;
    }
    catch {
        return null;
    }
}
function publicKey(spki) {
    const der = decodeBase64url(spki);
    if (!der)
        return null;
    try {
        const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
        return key.asymmetricKeyType === 'ed25519'
            && key.export({ type: 'spki', format: 'der' }).equals(der) ? key : null;
    }
    catch {
        return null;
    }
}
function parseJsonSegment(value) {
    const decoded = decodeBase64url(value);
    if (!decoded)
        return null;
    const text = decoded.toString('utf8');
    if (!strictJsonGate(text).ok)
        return null;
    try {
        const parsed = JSON.parse(text);
        return isRecord(parsed) ? parsed : null;
    }
    catch {
        return null;
    }
}
function cloneClaims(value) {
    return JSON.parse(canonicalizeAeb(value));
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== POLICY_DECISION_EVIDENCE_CONFIG_VERSION
        || !validRole(value.evidence_role) || !isRecord(value.subject)
        || !exactKeys(value.subject, SUBJECT_KEYS) || !validIdentifier(value.subject.id)
        || !['workload', 'system'].includes(String(value.subject.kind))
        || typeof value.issuer !== 'string' || !URI_RE.test(value.issuer)
        || typeof value.audience !== 'string' || !URI_RE.test(value.audience)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || !sortedUniqueStrings(value.allowed_engines, (item) => item === 'opa' || item === 'cerbos')
        || !sortedUniqueStrings(value.allowed_policy_digests, validDigest)
        || !safeInteger(value.clock_skew_seconds) || !safeInteger(value.max_decision_age_seconds)
        || Number(value.max_decision_age_seconds) === 0)
        return null;
    return JSON.parse(canonicalizeAeb(value));
}
function parseRoot(value, issuer) {
    if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
        || value['@version'] !== POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION
        || value.issuer !== issuer || !validIdentifier(value.key_id)
        || value.algorithm !== 'EdDSA' || typeof value.public_key !== 'string')
        return null;
    const key = publicKey(value.public_key);
    return key ? { ...JSON.parse(canonicalizeAeb(value)), key } : null;
}
function parseConstructorPins(input) {
    const config = parseConfig(input?.config);
    if (!config || !Array.isArray(input?.trust_roots) || input.trust_roots.length !== 1) {
        throw new TypeError('one valid relying-party-pinned policy decision root is required');
    }
    const root = parseRoot(input.trust_roots[0], config.issuer);
    if (!root)
        throw new TypeError('valid Ed25519 policy decision root required');
    return {
        config,
        root,
        configDigest: digestAeb(config),
        rootsDigest: digestAeb(input.trust_roots),
    };
}
function makeClaims(input, engine, decision, nativeResult) {
    const action = canonicalAction(input.action);
    if (!action || typeof input.issuer !== 'string' || !URI_RE.test(input.issuer)
        || !validIdentifier(input.subject) || typeof input.audience !== 'string' || !URI_RE.test(input.audience)
        || !safeInteger(input.issued_at) || !safeInteger(input.expires_at)
        || input.expires_at <= input.issued_at || !validIdentifier(input.decision_id)
        || !validIdentifier(input.policy_id) || !validDigest(input.policy_digest)
        || !validIdentifier(input.native_decision_ref)) {
        throw new TypeError('valid strict policy decision projection required');
    }
    // The native result digest must fail, not silently omit, executable or
    // non-JSON material such as Symbols, accessors, sparse arrays, or cycles.
    const nativeResultDigest = digestAeb(nativeResult);
    return {
        ep_version: POLICY_DECISION_EVIDENCE_VERSION,
        iss: input.issuer,
        sub: input.subject,
        aud: input.audience,
        iat: input.issued_at,
        exp: input.expires_at,
        jti: input.decision_id,
        engine,
        policy_id: input.policy_id,
        policy_digest: input.policy_digest,
        policy_decision: decision,
        action,
        action_digest: digestAeb(action),
        native_decision_ref: input.native_decision_ref,
        native_result_digest: nativeResultDigest,
    };
}
/** Project an OPA boolean result. Non-boolean results are explicitly indeterminate. */
export function projectOpaPolicyDecision(input) {
    const decision = input.result === true
        ? 'ALLOW' : input.result === false ? 'DENY' : 'INDETERMINATE';
    return makeClaims(input, 'opa', decision, input.result);
}
/** Project a Cerbos CheckResources effect. Unknown effects are explicitly indeterminate. */
export function projectCerbosPolicyDecision(input) {
    const decision = input.effect === 'EFFECT_ALLOW'
        ? 'ALLOW' : input.effect === 'EFFECT_DENY' ? 'DENY' : 'INDETERMINATE';
    return makeClaims(input, 'cerbos', decision, input.effect);
}
function signableClaims(value) {
    if (!isRecord(value) || !exactKeys(value, CLAIM_KEYS)
        || value.ep_version !== POLICY_DECISION_EVIDENCE_VERSION
        || typeof value.iss !== 'string' || !URI_RE.test(value.iss)
        || !validIdentifier(value.sub) || typeof value.aud !== 'string' || !URI_RE.test(value.aud)
        || !safeInteger(value.iat) || !safeInteger(value.exp) || Number(value.exp) <= Number(value.iat)
        || !validIdentifier(value.jti) || !['opa', 'cerbos'].includes(String(value.engine))
        || !validIdentifier(value.policy_id) || !validDigest(value.policy_digest)
        || !['ALLOW', 'DENY', 'INDETERMINATE'].includes(String(value.policy_decision))
        || !validDigest(value.action_digest) || !validIdentifier(value.native_decision_ref)
        || !validDigest(value.native_result_digest))
        return false;
    const action = canonicalAction(value.action);
    return action !== null && digestAeb(action) === value.action_digest;
}
/** Sign a normalized policy-engine observation with the local bridge key. */
export function signPolicyDecisionEvidence(claims, signer) {
    if (!signableClaims(claims) || !validIdentifier(signer?.key_id) || !validPrivateKey(signer?.private_key)) {
        throw new TypeError('valid closed policy decision claims and Ed25519 signer required');
    }
    const header = canonicalizeAeb({ alg: 'EdDSA', typ: POLICY_DECISION_EVIDENCE_TYP, kid: signer.key_id });
    const payload = canonicalizeAeb(claims);
    const protectedHeader = Buffer.from(header, 'utf8').toString('base64url');
    const encodedPayload = Buffer.from(payload, 'utf8').toString('base64url');
    const signingInput = `${protectedHeader}.${encodedPayload}`;
    const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), signer.private_key).toString('base64url');
    return `${signingInput}.${signature}`;
}
function parseClaims(value, config) {
    if (!signableClaims(value) || value.iss !== config.issuer || value.aud !== config.audience
        || !config.allowed_engines.includes(value.engine)
        || !config.allowed_policy_digests.includes(value.policy_digest)
        || canonicalAction(value.action, config.action_type) === null)
        return null;
    return cloneClaims(value);
}
function verifyStatement(artifact, pins, now) {
    if (typeof artifact !== 'string') {
        return { ok: false, reason: 'policy-decision:artifact_malformed', acceptance: 'REJECTED', verified: false };
    }
    const parts = artifact.split('.');
    if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
        return { ok: false, reason: 'policy-decision:jws_malformed', acceptance: 'REJECTED', verified: false };
    }
    const header = parseJsonSegment(parts[0]);
    const payload = parseJsonSegment(parts[1]);
    const signature = decodeBase64url(parts[2]);
    if (!header || !payload || !signature || signature.length !== 64
        || !exactKeys(header, HEADER_KEYS) || header.alg !== 'EdDSA'
        || header.typ !== POLICY_DECISION_EVIDENCE_TYP || header.kid !== pins.root.key_id
        || !crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), pins.root.key, signature)) {
        return { ok: false, reason: 'policy-decision:signature_or_header_invalid', acceptance: 'REJECTED', verified: false };
    }
    const claims = parseClaims(payload, pins.config);
    if (!claims) {
        return { ok: false, reason: 'policy-decision:claims_or_policy_pin_invalid', acceptance: 'REJECTED', verified: true };
    }
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) {
        return { ok: false, reason: 'policy-decision:now_invalid', acceptance: 'INDETERMINATE', verified: true };
    }
    const nowSeconds = Math.floor(nowMs / 1000);
    if (claims.iat > nowSeconds + pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'policy-decision:issued_in_future', acceptance: 'INDETERMINATE', verified: true };
    }
    if (claims.exp <= nowSeconds - pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'policy-decision:expired', acceptance: 'REJECTED', verified: true };
    }
    if (nowSeconds - claims.iat > pins.config.max_decision_age_seconds + pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'policy-decision:too_old', acceptance: 'INDETERMINATE', verified: true };
    }
    return {
        ok: true,
        value: { claims, replayUnit: digestAeb({ issuer: claims.iss, decision_id: claims.jti }) },
    };
}
function statusDigest(status) {
    return safeDigest({
        checked_at: status?.checked_at,
        expires_at: status?.expires_at,
        revocation_checked: status?.revocation_checked,
        revoked: status?.revoked,
        consumed: status?.consumed,
        unavailable: status?.unavailable === true,
    });
}
function statusDisposition(status, now) {
    const reasons = [];
    const nowMs = Date.parse(now);
    const checkedMs = Date.parse(status?.checked_at);
    const expiresMs = Date.parse(status?.expires_at);
    if (status?.unavailable === true)
        reasons.push('status_unavailable');
    if (status?.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    if (status?.revoked === true)
        reasons.push('evidence_revoked');
    if (status?.consumed === true)
        reasons.push('evidence_consumed');
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
        reasons.push('status_time_invalid');
    }
    else {
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (expiresMs <= nowMs)
            reasons.push('status_expired');
    }
    const unique = [...new Set(reasons)].sort();
    if (status?.revoked === true || status?.consumed === true
        || (Number.isFinite(expiresMs) && expiresMs <= nowMs)) {
        return { acceptance: 'REJECTED', reasons: unique };
    }
    return unique.length === 0
        ? { acceptance: 'ACCEPTED', reasons: [] }
        : { acceptance: 'INDETERMINATE', reasons: unique };
}
function combineAcceptance(left, right) {
    if (left === 'REJECTED' || right === 'REJECTED')
        return 'REJECTED';
    if (left === 'INDETERMINATE' || right === 'INDETERMINATE')
        return 'INDETERMINATE';
    return 'ACCEPTED';
}
export function createPolicyDecisionEvidenceActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': POLICY_DECISION_EVIDENCE_MAPPING_VERSION,
        source: 'signed-local-policy-decision-exact-action',
        action_type: actionType,
        suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: [
                    { name: 'action_type', type: 'string' },
                    { name: 'parameters', type: 'object' },
                ],
                optional_fields: [],
            }],
    };
}
function validMappingProfile(profile, actionType) {
    if (!isRecord(profile) || profile.version !== POLICY_DECISION_EVIDENCE_MAPPING_VERSION
        || profile.mapper_id !== POLICY_DECISION_EVIDENCE_MAPPER_ID
        || !isRecord(profile.resolver) || profile.resolver.id !== POLICY_DECISION_EVIDENCE_MAPPER_ID
        || profile.resolver.version !== '1' || !validDigest(profile.resolver.implementation_digest)
        || !isRecord(profile.semantic_equivalence)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !isRecord(profile.definition)
        || !sameDigest(profile.definition, createPolicyDecisionEvidenceActionDefinition(actionType))
        || !Array.isArray(profile.definition.definitions))
        return null;
    return profile.definition.definitions;
}
function fallback(input, pins) {
    const evidenceDigest = safeDigest(input.artifact);
    return {
        native_verification: 'FAILED',
        acceptance: 'REJECTED',
        evidence_digest: evidenceDigest,
        status_digest: statusDigest(input.status),
        evidence_role: pins.config.evidence_role,
        subject: { ...pins.config.subject },
        replay_unit: evidenceDigest,
        reasons: [],
    };
}
/**
 * Build the AEB adapter under relying-party-pinned config and bridge keys.
 * The bridge key proves only what this local integration observed. It does not
 * prove complete mediation, policy correctness, human intent, or authorization.
 */
export function createPolicyDecisionEvidenceAdapter(constructorPins) {
    const pins = parseConstructorPins(constructorPins);
    return Object.freeze({
        id: POLICY_DECISION_EVIDENCE_ADAPTER_ID,
        version: POLICY_DECISION_EVIDENCE_ADAPTER_VERSION,
        verifyNative(input) {
            const result = fallback(input, pins);
            try {
                if (safeDigest(input.adapter_config) !== pins.configDigest
                    || safeDigest(input.trust_roots) !== pins.rootsDigest) {
                    result.reasons = ['policy-decision:constructor_pin_mismatch'];
                    return result;
                }
                const verified = verifyStatement(input.artifact, pins, input.now);
                if (!verified.ok) {
                    result.native_verification = verified.verified ? 'VERIFIED' : 'FAILED';
                    result.acceptance = verified.acceptance;
                    result.reasons = [verified.reason];
                    return result;
                }
                result.native_verification = 'VERIFIED';
                result.replay_unit = verified.value.replayUnit;
                const status = statusDisposition(input.status, input.now);
                const decisionAcceptance = verified.value.claims.policy_decision === 'ALLOW'
                    ? 'ACCEPTED'
                    : verified.value.claims.policy_decision === 'DENY' ? 'REJECTED' : 'INDETERMINATE';
                result.acceptance = combineAcceptance(decisionAcceptance, status.acceptance);
                result.reasons = [
                    ...(verified.value.claims.policy_decision === 'ALLOW'
                        ? [] : [`policy-decision:${verified.value.claims.policy_decision.toLowerCase()}`]),
                    ...status.reasons,
                ];
                return result;
            }
            catch {
                result.reasons = ['policy-decision:unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
                }
                if (safeDigest(input.adapter_config) !== pins.configDigest
                    || safeDigest(input.trust_roots) !== pins.rootsDigest) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
                }
                const definitions = validMappingProfile(input.profile, pins.config.action_type);
                if (!definitions) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
                }
                const statement = verifyStatement(input.artifact, pins, input.now);
                if (!statement.ok || statement.value.claims.policy_decision !== 'ALLOW') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
                }
                const expected = canonicalAction(input.expected_action, pins.config.action_type);
                const action = canonicalAction(statement.value.claims.action, pins.config.action_type);
                if (!expected || !action) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
                }
                const actionDigest = digestAeb(action);
                if (!sameDigest(action, expected)) {
                    return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['exact_action_projection_mismatch'] };
                }
                let computed;
                try {
                    computed = computeCaid(action, { suite: 'jcs-sha256', definitions });
                }
                catch {
                    computed = null;
                }
                if (!isRecord(computed) || typeof computed.caid !== 'string'
                    || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
                }
                if (computed.digest !== actionDigest) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
                }
                return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
            }
            catch {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['policy-decision:unexpected_mapping_error'] };
            }
        },
    });
}
// ===========================================================================
// EP-POLICY-DECISION-EVIDENCE-v2 -- the hybrid (Ed25519 + ML-DSA-65) statement
// ===========================================================================
/**
 * Same five-move migration as EP-REVOCATION-v2, and the same reason the JOSE
 * `alg` header disappears in v2 as in EP-AUTHORIZATION-SERVER-CONFIRMATION-v2:
 * this repository carries no traceable JOSE algorithm identifier for ML-DSA-65
 * (the only in-tree ML-DSA algorithm identifier is the COSE one, RFC 9964, in
 * packages/verify/src/aeb-mcgraw-delegation-adapter.ts), and
 * docs/protocol/pq-hybrid-program.md records the JOSE registration as unfinished
 * draft work. Rather than squat on the JOSE registry with an invented value,
 * the v2 protected header carries no `alg` at all: each signature carries its
 * own label from EP's own closed registry (EP-SIG-AGILITY-v1), and the header
 * commits to the required SET.
 *
 *   1. VERSION BUMP. `ep_version` becomes the v2 marker and `typ` changes, so
 *      the unchanged v1 parser (signableClaims / verifyStatement) refuses a v2
 *      statement on the version marker before touching a signature, without
 *      throwing. Asserted by test.
 *   2. SET SHAPE. `signatures: [{ alg, sig, key_id }]`, the EP-SIG-AGILITY-v1
 *      AgileSignature shape, one entry per registered algorithm.
 *   3. ANTI-STRIPPING BYTES. `required_algorithms` is a member of the protected
 *      header, which is inside the ASCII `<protected>.<payload>` signing input
 *      both legs cover. The verifier rebuilds the expected header from the PIN
 *      and the REGISTERED set and requires byte equality.
 *   4. V1 COMPATIBILITY. signPolicyDecisionEvidence() and the synchronous
 *      AebAdapter path are unchanged and stay synchronous. ML-DSA verification
 *      is async and AebAdapter.verifyNative() is synchronous by contract, so v2
 *      is a separate async entry point; there is no hybrid adapter here.
 *   5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *      is `pq_backend_unavailable` and never a pass on the classical leg.
 *
 * COORDINATION BOUNDARY. The signer is an OPA or Cerbos integration that
 * vendored this helper. Shipping the v2 verifier does not make any policy-engine
 * integration emit v2 statements: each one must deploy an ML-DSA-65 key and the
 * v2 signer first. Opt-in; not deployed, default, or certified.
 *
 * UNCHANGED BOUNDARY. v2 changes the signature algebra and nothing else. A
 * verified statement still proves only that a pinned integration observed and
 * signed this machine-policy decision. A machine ALLOW is still not human
 * authorization.
 */
export const POLICY_DECISION_EVIDENCE_V2_VERSION = 'EP-POLICY-DECISION-EVIDENCE-v2';
export const POLICY_DECISION_EVIDENCE_V2_TYP = 'ep-policy-decision-evidence+hybrid';
/** The registered required algorithm set, in canonical order. */
export const POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const V2_HEADER_KEYS = new Set(['ep_version', 'typ', 'kid', 'pq_kid', 'required_algorithms']);
const V2_SIGNATURE_KEYS = new Set(['alg', 'sig', 'key_id']);
const V2_STATEMENT_KEYS = new Set(['protected', 'payload', 'signatures']);
function policyV2SetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS[i]);
}
/** The v2 protected header; `required_algorithms` is a signed member of it. */
export function policyDecisionEvidenceV2ProtectedHeader(keyId, pqKeyId, requiredAlgorithms = POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS) {
    if (!policyV2SetMatchesRegistered(requiredAlgorithms)) {
        throw new Error('policyDecisionEvidenceV2ProtectedHeader: algorithm set is not the registered EP-POLICY-DECISION-EVIDENCE-v2 set');
    }
    return {
        ep_version: POLICY_DECISION_EVIDENCE_V2_VERSION,
        typ: POLICY_DECISION_EVIDENCE_V2_TYP,
        kid: keyId,
        pq_kid: pqKeyId,
        required_algorithms: [...requiredAlgorithms],
    };
}
/** ASCII `<protected>.<payload>`: the exact v1 signing-input convention. */
export function policyDecisionEvidenceV2SigningInput(protectedB64u, payloadB64u) {
    return Buffer.from(`${protectedB64u}.${payloadB64u}`, 'ascii');
}
function v2SignableClaims(value) {
    if (!isRecord(value) || value.ep_version !== POLICY_DECISION_EVIDENCE_V2_VERSION)
        return false;
    // Reuse the v1 claim validator verbatim by swapping only the version marker,
    // so the two versions cannot drift on claim semantics.
    return signableClaims({ ...value, ep_version: POLICY_DECISION_EVIDENCE_VERSION });
}
/** Sign a v2 policy decision statement under BOTH registered algorithms. */
export async function signPolicyDecisionEvidenceV2(claims, signer, options = {}) {
    if (!v2SignableClaims(claims)
        || !validIdentifier(signer?.key_id) || !validIdentifier(signer?.pq_key_id)
        || !validPrivateKey(signer?.private_key)) {
        throw new TypeError('valid closed v2 policy decision claims and Ed25519 + ML-DSA-65 signer required');
    }
    const header = canonicalizeAeb(policyDecisionEvidenceV2ProtectedHeader(signer.key_id, signer.pq_key_id));
    const payload = canonicalizeAeb(claims);
    const protectedB64u = Buffer.from(header, 'utf8').toString('base64url');
    const payloadB64u = Buffer.from(payload, 'utf8').toString('base64url');
    const signatures = await signAgileSet(new Uint8Array(policyDecisionEvidenceV2SigningInput(protectedB64u, payloadB64u)), [
        { alg: 'Ed25519', private_key: signer.private_key, key_id: signer.key_id },
        { alg: 'ML-DSA-65', private_key: signer.pq_secret_key, key_id: signer.pq_key_id },
    ], options);
    return {
        protected: protectedB64u,
        payload: payloadB64u,
        signatures: signatures.map((s) => ({ alg: s.alg, sig: s.sig, key_id: String(s.key_id ?? '') })),
    };
}
/**
 * verifyPolicyDecisionEvidenceV2 -- FAIL-CLOSED hybrid check against a pinned
 * key pair and a pinned adapter config. Never throws on caller input; a v2
 * statement NEVER verifies on one leg alone.
 *
 * SCOPE. Header shape, committed algorithm set, both legs under pinned keys,
 * and closed claim validity against the config. Freshness, engine/policy
 * allow-lists beyond the closed claim check, status, and AEB acceptance stay
 * with the unchanged synchronous v1 adapter.
 */
export async function verifyPolicyDecisionEvidenceV2(statement, pin, config, options = {}) {
    const checks = {
        structure: true,
        version: true,
        algorithm_set: true,
        legs_present: true,
        engine_key_pinned: true,
        claims_valid: true,
        signature_valid: true,
        signature_binds_statement: true,
    };
    const errors = [];
    const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
    const done = (claims) => ({ valid: Object.values(checks).every(Boolean), checks, errors, ...(claims ? { claims } : {}) });
    if (!isRecord(statement) || !exactKeys(statement, V2_STATEMENT_KEYS)
        || typeof statement.protected !== 'string' || typeof statement.payload !== 'string') {
        fail('structure', 'statement must be the exact closed { protected, payload, signatures } shape');
        fail('signature_valid', 'statement shape refused before any signature was inspected');
        return done();
    }
    const header = parseJsonSegment(statement.protected);
    const rawClaims = parseJsonSegment(statement.payload);
    if (!header || !rawClaims) {
        fail('structure', 'protected header and payload must be strict-JSON base64url segments');
        fail('signature_valid', 'statement segments refused before any signature was inspected');
        return done();
    }
    if (!exactKeys(header, V2_HEADER_KEYS)) {
        fail('structure', 'protected header must use the exact closed v2 key set');
    }
    if (header.ep_version !== POLICY_DECISION_EVIDENCE_V2_VERSION) {
        fail('version', `unsupported version: ${String(header.ep_version)}`);
    }
    if (header.typ !== POLICY_DECISION_EVIDENCE_V2_TYP) {
        fail('structure', `protected header typ must be ${POLICY_DECISION_EVIDENCE_V2_TYP}`);
    }
    if (!policyV2SetMatchesRegistered(header.required_algorithms)) {
        fail('algorithm_set', `protected header required_algorithms must be exactly ${JSON.stringify([...POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    const signatures = Array.isArray(statement.signatures) ? statement.signatures : null;
    if (!signatures || signatures.length === 0) {
        fail('legs_present', 'signatures must carry one entry per required algorithm');
    }
    else {
        const presented = new Set();
        let malformed = false;
        for (const s of signatures) {
            if (!isRecord(s) || !exactKeys(s, V2_SIGNATURE_KEYS)
                || typeof s.alg !== 'string' || typeof s.sig !== 'string' || typeof s.key_id !== 'string') {
                fail('legs_present', 'each signatures entry must be { alg, sig, key_id }');
                malformed = true;
                break;
            }
            if (presented.has(s.alg)) {
                fail('legs_present', `duplicate signature for algorithm "${s.alg}"`);
                malformed = true;
                break;
            }
            presented.add(s.alg);
        }
        if (!malformed) {
            for (const alg of POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS) {
                if (!presented.has(alg))
                    fail('legs_present', `missing required ${alg} signature (leg stripped)`);
            }
            for (const alg of presented) {
                if (!POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                    fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
                }
            }
        }
    }
    const pinnedEd = isRecord(pin) && typeof pin.public_key === 'string' ? pin.public_key : '';
    const pinnedPq = isRecord(pin) && typeof pin.pq_public_key === 'string' ? pin.pq_public_key : '';
    if (!pinnedEd || !pinnedPq
        || !validIdentifier(pin?.key_id)
        || !validIdentifier(pin?.pq_key_id)) {
        fail('engine_key_pinned', 'a pinned Ed25519 + ML-DSA-65 policy-engine key pair is required (identified but not trusted)');
    }
    else {
        if (publicKey(pinnedEd) === null) {
            fail('engine_key_pinned', 'pinned Ed25519 key is not a canonical Ed25519 SPKI');
        }
        const pqBytes = decodeBase64url(pinnedPq);
        if (!pqBytes || pqBytes.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
            fail('engine_key_pinned', `pinned ML-DSA-65 key must be ${ML_DSA_65_PUBLIC_KEY_BYTES} raw bytes, base64url`);
        }
        if (header.kid !== pin.key_id) {
            fail('engine_key_pinned', 'protected header kid != pinned Ed25519 key_id');
        }
        if (header.pq_kid !== pin.pq_key_id) {
            fail('engine_key_pinned', 'protected header pq_kid != pinned ML-DSA-65 key_id');
        }
    }
    if (checks.engine_key_pinned) {
        let expected = null;
        try {
            expected = Buffer.from(canonicalizeAeb(policyDecisionEvidenceV2ProtectedHeader(pin.key_id, pin.pq_key_id)), 'utf8').toString('base64url');
        }
        catch {
            expected = null;
        }
        if (expected === null || expected !== statement.protected) {
            fail('structure', 'protected header does not equal the header rebuilt from the pin and the registered algorithm set');
        }
    }
    const parsedConfig = parseConfig(config);
    if (!parsedConfig) {
        fail('claims_valid', 'a valid pinned adapter configuration is required');
    }
    else if (!v2SignableClaims(rawClaims)
        || rawClaims.iss !== parsedConfig.issuer || rawClaims.aud !== parsedConfig.audience
        || !parsedConfig.allowed_engines.includes(rawClaims.engine)
        || !parsedConfig.allowed_policy_digests.includes(rawClaims.policy_digest)
        || canonicalAction(rawClaims.action, parsedConfig.action_type) === null) {
        fail('claims_valid', 'claims are not the exact closed v2 claim set for this pinned configuration');
    }
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(policyDecisionEvidenceV2SigningInput(statement.protected, statement.payload)), signatures ?? [], [
            { alg: 'Ed25519', public_key: pinnedEd, key_id: pin?.key_id },
            { alg: 'ML-DSA-65', public_key: pinnedPq, key_id: pin?.pq_key_id },
        ], {
            ...options,
            policy: 'hybrid_all',
            requiredAlgorithms: [...POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        setResult = null;
    }
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        const failedLeg = Array.isArray(setResult?.results)
            ? setResult.results.find((r) => r?.verified !== true) ?? null
            : null;
        fail('signature_valid', `policy decision signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
        if (failedLeg?.reason === 'signature_invalid') {
            fail('signature_binds_statement', 'signature set does not bind the presented protected header and payload bytes');
        }
    }
    return done(checks.claims_valid ? rawClaims : undefined);
}
//# sourceMappingURL=policy-decision-evidence.js.map