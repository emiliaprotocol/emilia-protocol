// SPDX-License-Identifier: Apache-2.0
/**
 * Source-locked CCS v1.4 conformance-vector adapter for AEB-ADAPTER-v1.
 *
 * A CCS ALLOW is machine-policy evidence. It never becomes execution
 * authority. The relying party still constructs one exact action, pins one
 * mapping profile, evaluates status, and makes a separate local authorization
 * decision at the consequence boundary.
 */
import crypto from 'node:crypto';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- narrowed and checked below.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeAeb, digestAeb, mappingProfileDigest, } from './aeb-adapter-contract.js';
import { canonicalizeFiniteJson } from './strict-json.js';
export const CCS_V14_VECTOR_REPOSITORY = 'https://github.com/DSHCorrectover/ccs-conformance-vectors';
export const CCS_V14_VECTOR_COMMIT = 'a3503b2bc48922f92a28c372003885a0831da02b';
export const CCS_V14_VECTOR_MANIFEST_SHA256 = '3e77eae3045eb2bc824c52b8d022b75029beaf56623841ce7c035a99e65a2ddd';
export const CCS_V14_SOURCE_LOCK = `ccs-v1.4.0-conformance-github@${CCS_V14_VECTOR_COMMIT}`;
export const CCS_V14_AEB_ADAPTER_ID = 'native:ccs-v1.4.0-conformance-ed25519';
export const CCS_V14_AEB_ADAPTER_VERSION = '1';
export const CCS_V14_AEB_CONFIG_VERSION = 'AEB-CCS-V1.4.0-CONFORMANCE-CONFIG-v1';
export const CCS_V14_AEB_TRUST_ROOT_VERSION = 'AEB-CCS-V1.4.0-CONFORMANCE-ROOT-v1';
export const CCS_V14_CAID_MAPPING_VERSION = 'AEB-CCS-V1.4.0-GITHUB-ACTION-MAPPING-v1';
export const CCS_V14_CAID_MAPPER_ID = 'mapper:ccs-v1.4.0-github-action-v1';
const DIGEST_RE = /^[0-9a-f]{64}$/;
const FINGERPRINT_RE = /^[0-9a-f]{16}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#@-]{0,511}$/;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+\.[1-9][0-9]*$/;
const ARTIFACT_KEYS = new Set(['receipt', 'tool_args', 'response_body']);
const RECEIPT_KEYS = new Set([
    'trace_id', 'receipt_version', 'verdict', 'timestamp', 'tool',
    'tool_call_id', 'params_hash', 'args_digest', 'rule_summary',
    'rule_version', 'request_hash', 'response_hash', 'runtime_context_hash',
    'config_hash', 'verifier_source_class', 'deployment_mode', 'issuer',
    'audience', 'nonce', 'sequence', 'issued_at', 'expires_at',
    'max_clock_skew', 'action', 'signature', 'signing_algorithm',
    'public_key_fingerprint', 'public_key', 'verified_at', 'latency_us',
]);
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
    'allowed_actions', 'allowed_tools', 'required_rule_version',
    'max_receipt_age_seconds', 'max_status_age_seconds',
    'max_clock_skew_seconds', 'deployment_scope',
]);
const ROOT_KEYS = new Set([
    '@version', 'issuer', 'key_id', 'algorithm', 'public_key_raw_base64',
    'public_key_fingerprint_sha256_16',
]);
const SUBJECT_KEYS = new Set(['id', 'kind']);
const ACTION_KEYS = new Set(['action_type', 'parameters']);
const ACTION_PARAMETER_KEYS = new Set(['tool', 'arguments']);
const PROFILE_KEYS = new Set([
    'version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver',
    'semantic_equivalence', 'profile_digest',
]);
const RESOLVER_KEYS = new Set(['id', 'version', 'implementation_digest']);
const EQUIVALENCE_KEYS = new Set([
    'assertion', 'loss_policy', 'omitted_material_fields', 'omitted_nonmaterial_fields',
]);
const MAPPING_PROFILE_ID = 'ccs-v14-github-action';
const MAPPING_REGISTRY_REF = 'mapping:ccs-v14-github-action';
const OMITTED_NONMATERIAL_FIELDS = Object.freeze([
    'trace_id', 'receipt_version', 'verdict', 'timestamp', 'tool_call_id',
    'params_hash', 'rule_summary', 'rule_version', 'request_hash',
    'response_hash', 'runtime_context_hash', 'config_hash',
    'verifier_source_class', 'deployment_mode', 'issuer', 'audience',
    'nonce', 'sequence', 'issued_at', 'expires_at', 'max_clock_skew',
    'action', 'signature', 'signing_algorithm', 'public_key_fingerprint',
    'public_key', 'verified_at', 'latency_us',
]);
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
function validText(value, max = 4096) {
    return typeof value === 'string' && value.length > 0 && value.length <= max
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function safeNonNegative(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}
function safeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function decodeBase64(value, bytes) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value))
        return null;
    try {
        const decoded = Buffer.from(value, 'base64');
        return decoded.length === bytes && decoded.toString('base64') === value ? decoded : null;
    }
    catch {
        return null;
    }
}
function finiteClone(value) {
    try {
        return JSON.parse(canonicalizeFiniteJson(value));
    }
    catch {
        return null;
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
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ invalid_value: true });
    }
}
// AEB normalizes an omitted `unavailable` bit to false before binding status.
// Mirror that representation so the adapter result is byte-identical to the
// evaluator's independently derived status digest.
function statusDigest(status) {
    return digestAeb({
        checked_at: status.checked_at,
        expires_at: status.expires_at,
        revocation_checked: status.revocation_checked,
        revoked: status.revoked,
        consumed: status.consumed,
        unavailable: status.unavailable === true,
    });
}
function sha256Finite(value) {
    try {
        return crypto.createHash('sha256')
            .update(canonicalizeFiniteJson(value), 'utf8').digest('hex');
    }
    catch {
        return null;
    }
}
function parseReceipt(value) {
    if (!isRecord(value) || !exactKeys(value, RECEIPT_KEYS)
        || value.receipt_version !== '1.4'
        || !['allow', 'block'].includes(String(value.verdict))
        || !safeNonNegative(value.timestamp)
        || !validText(value.trace_id) || !validText(value.tool_call_id)
        || !validText(value.tool) || !TOKEN_RE.test(String(value.tool))
        || !DIGEST_RE.test(String(value.params_hash))
        || !DIGEST_RE.test(String(value.args_digest))
        || !DIGEST_RE.test(String(value.request_hash))
        || !DIGEST_RE.test(String(value.response_hash))
        || !DIGEST_RE.test(String(value.runtime_context_hash))
        || !DIGEST_RE.test(String(value.config_hash))
        || !validText(value.rule_summary) || !validText(value.rule_version)
        || !validText(value.verifier_source_class) || !validText(value.deployment_mode)
        || !validText(value.issuer) || !validText(value.audience)
        || !validText(value.nonce) || !safeInteger(value.sequence)
        || !safeNonNegative(value.issued_at) || !safeNonNegative(value.expires_at)
        || !safeNonNegative(value.max_clock_skew) || !validText(value.action)
        || value.signing_algorithm !== 'Ed25519'
        || !FINGERPRINT_RE.test(String(value.public_key_fingerprint))
        || !decodeBase64(value.public_key, 32) || !decodeBase64(value.signature, 64)
        || !safeNonNegative(value.verified_at) || !safeNonNegative(value.latency_us))
        return null;
    return finiteClone(value);
}
function parseArtifact(value) {
    if (!isRecord(value) || !exactKeys(value, ARTIFACT_KEYS) || !isRecord(value.tool_args))
        return null;
    const receipt = parseReceipt(value.receipt);
    const args = finiteClone(value.tool_args);
    const response = finiteClone(value.response_body);
    return receipt && isRecord(args) && response !== null
        ? { receipt, tool_args: args, response_body: response }
        : null;
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== CCS_V14_AEB_CONFIG_VERSION
        || !validText(value.evidence_role) || !isRecord(value.subject)
        || !exactKeys(value.subject, SUBJECT_KEYS)
        || !validText(value.subject.id)
        || !['human', 'workload', 'organization', 'system'].includes(String(value.subject.kind))
        || !validText(value.issuer) || !validText(value.audience)
        || !ACTION_TYPE_RE.test(String(value.action_type))
        || !Array.isArray(value.allowed_actions) || value.allowed_actions.length === 0
        || !value.allowed_actions.every((item) => validText(item, 256))
        || new Set(value.allowed_actions).size !== value.allowed_actions.length
        || !Array.isArray(value.allowed_tools) || value.allowed_tools.length === 0
        || !value.allowed_tools.every((item) => validText(item, 256) && TOKEN_RE.test(item))
        || new Set(value.allowed_tools).size !== value.allowed_tools.length
        || !validText(value.required_rule_version)
        || !safeInteger(value.max_receipt_age_seconds)
        || !safeInteger(value.max_status_age_seconds)
        || !safeInteger(value.max_clock_skew_seconds)
        || value.deployment_scope !== 'pinned-ed25519-issuer')
        return null;
    return finiteClone(value);
}
function parseRoot(value, config) {
    if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
        || value['@version'] !== CCS_V14_AEB_TRUST_ROOT_VERSION
        || value.issuer !== config.issuer || !validText(value.key_id)
        || value.algorithm !== 'Ed25519'
        || !FINGERPRINT_RE.test(String(value.public_key_fingerprint_sha256_16)))
        return null;
    const raw = decodeBase64(value.public_key_raw_base64, 32);
    if (!raw || crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16)
        !== value.public_key_fingerprint_sha256_16)
        return null;
    const root = finiteClone(value);
    return root ? { root, raw } : null;
}
function publicKey(raw) {
    return crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]),
        format: 'der',
        type: 'spki',
    });
}
function verifySignature(receipt, raw) {
    try {
        const unsigned = { ...receipt };
        delete unsigned.signature;
        return crypto.verify(null, Buffer.from(canonicalizeFiniteJson(unsigned), 'utf8'), publicKey(raw), Buffer.from(receipt.signature, 'base64'));
    }
    catch {
        return false;
    }
}
function statusResult(status, now, maxAge) {
    const nowMs = Date.parse(now);
    const checkedMs = Date.parse(status.checked_at);
    const expiresMs = Date.parse(status.expires_at);
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
        return { acceptance: 'INDETERMINATE', reasons: ['ccs:v14_status_time_invalid'] };
    }
    if (status.unavailable === true || !status.revocation_checked) {
        return { acceptance: 'INDETERMINATE', reasons: ['ccs:v14_status_unavailable'] };
    }
    if (status.revoked || status.consumed || nowMs > expiresMs || checkedMs > nowMs
        || nowMs - checkedMs > maxAge * 1000) {
        return { acceptance: 'REJECTED', reasons: ['ccs:v14_status_not_current'] };
    }
    return { acceptance: 'ACCEPTED', reasons: [] };
}
function combine(left, right) {
    if (left === 'REJECTED' || right === 'REJECTED')
        return 'REJECTED';
    if (left === 'INDETERMINATE' || right === 'INDETERMINATE')
        return 'INDETERMINATE';
    return 'ACCEPTED';
}
function canonicalAction(value, actionType) {
    if (!isRecord(value) || !exactKeys(value, ACTION_KEYS)
        || value.action_type !== actionType || !isRecord(value.parameters)
        || !exactKeys(value.parameters, ACTION_PARAMETER_KEYS)
        || !TOKEN_RE.test(String(value.parameters.tool)) || !isRecord(value.parameters.arguments))
        return null;
    return finiteClone({
        action_type: actionType,
        parameters: { tool: value.parameters.tool, arguments: value.parameters.arguments },
    });
}
export function createCcsV14AebActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': CCS_V14_CAID_MAPPING_VERSION,
        source: CCS_V14_SOURCE_LOCK,
        source_media_type: 'application/x-ccs-receipt+json',
        projection: 'ccs-v14-signed-tool-and-full-args-digest-v1',
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
function validProfile(profile, actionType) {
    const resolverDigest = digestAeb({ implementation: CCS_V14_CAID_MAPPER_ID, version: '1' });
    if (!isRecord(profile) || !exactKeys(profile, PROFILE_KEYS)
        || profile.version !== CCS_V14_CAID_MAPPING_VERSION
        || profile.registry_entry_ref !== MAPPING_REGISTRY_REF
        || profile.mapper_id !== CCS_V14_CAID_MAPPER_ID
        || !isRecord(profile.resolver) || !exactKeys(profile.resolver, RESOLVER_KEYS)
        || profile.resolver.id !== CCS_V14_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || profile.resolver.implementation_digest !== resolverDigest
        || !isRecord(profile.semantic_equivalence)
        || !exactKeys(profile.semantic_equivalence, EQUIVALENCE_KEYS)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !sameDigest(profile.semantic_equivalence.omitted_nonmaterial_fields, OMITTED_NONMATERIAL_FIELDS)
        || !sameDigest(profile.definition, createCcsV14AebActionDefinition(actionType))
        || profile.profile_digest !== mappingProfileDigest(MAPPING_PROFILE_ID, profile)
        || !isRecord(profile.definition) || !Array.isArray(profile.definition.definitions))
        return null;
    return profile.definition.definitions;
}
export function createCcsV14AebAdapter(constructorPins) {
    const config = parseConfig(constructorPins.config);
    if (!config || !Array.isArray(constructorPins.trust_roots) || constructorPins.trust_roots.length !== 1) {
        throw new TypeError('ccs_v14_adapter_pins_invalid');
    }
    const parsedRoot = parseRoot(constructorPins.trust_roots[0], config);
    if (!parsedRoot)
        throw new TypeError('ccs_v14_adapter_root_invalid');
    const pinnedConfig = config;
    const pinnedRoot = parsedRoot;
    const configDigest = digestAeb(pinnedConfig);
    const rootsDigest = digestAeb([pinnedRoot.root]);
    function fallback(input) {
        const evidenceDigest = safeDigest(input.artifact);
        return {
            native_verification: 'FAILED',
            acceptance: 'REJECTED',
            evidence_digest: evidenceDigest,
            status_digest: statusDigest(input.status),
            evidence_role: pinnedConfig.evidence_role,
            subject: { ...pinnedConfig.subject },
            replay_unit: evidenceDigest,
            reasons: [],
        };
    }
    function verifyArtifact(value, now) {
        const artifact = parseArtifact(value);
        if (!artifact)
            return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:v14_artifact_malformed' };
        const receipt = artifact.receipt;
        if (!verifySignature(receipt, pinnedRoot.raw)) {
            return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:v14_signature_invalid' };
        }
        if (receipt.public_key !== pinnedRoot.root.public_key_raw_base64
            || receipt.public_key_fingerprint !== pinnedRoot.root.public_key_fingerprint_sha256_16) {
            return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v14_key_binding_mismatch' };
        }
        if (receipt.issuer !== pinnedConfig.issuer) {
            return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v14_issuer_mismatch' };
        }
        if (receipt.audience !== pinnedConfig.audience) {
            return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v14_audience_mismatch' };
        }
        if (!pinnedConfig.allowed_tools.includes(receipt.tool)
            || !pinnedConfig.allowed_actions.includes(receipt.action)
            || receipt.rule_version !== pinnedConfig.required_rule_version) {
            return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v14_policy_pin_mismatch' };
        }
        if (sha256Finite(artifact.tool_args) !== receipt.args_digest
            || sha256Finite(artifact.response_body) !== receipt.response_hash) {
            return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v14_companion_hash_mismatch' };
        }
        const nowSeconds = Date.parse(now) / 1000;
        if (!Number.isFinite(nowSeconds)) {
            return { ok: false, verified: true, acceptance: 'INDETERMINATE', reason: 'ccs:v14_current_time_invalid' };
        }
        if (receipt.max_clock_skew > pinnedConfig.max_clock_skew_seconds
            || receipt.expires_at < receipt.issued_at
            || receipt.issued_at > receipt.timestamp
            || Math.abs(receipt.timestamp - receipt.verified_at) > receipt.max_clock_skew
            || nowSeconds < receipt.issued_at - receipt.max_clock_skew
            || nowSeconds > receipt.expires_at + receipt.max_clock_skew
            || nowSeconds - receipt.issued_at > pinnedConfig.max_receipt_age_seconds) {
            return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v14_time_bounds_invalid' };
        }
        return {
            ok: true,
            artifact,
            replay: digestAeb({
                source: CCS_V14_SOURCE_LOCK,
                issuer: receipt.issuer,
                nonce: receipt.nonce,
                action: receipt.action,
                args_digest: receipt.args_digest,
            }),
        };
    }
    return Object.freeze({
        id: CCS_V14_AEB_ADAPTER_ID,
        version: CCS_V14_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            const result = fallback(input);
            try {
                if (safeDigest(input.adapter_config) !== configDigest
                    || safeDigest(input.trust_roots) !== rootsDigest) {
                    result.reasons = ['ccs:v14_constructor_pin_mismatch'];
                    return result;
                }
                const verified = verifyArtifact(input.artifact, input.now);
                if (!verified.ok) {
                    result.native_verification = verified.verified ? 'VERIFIED' : 'FAILED';
                    result.acceptance = verified.acceptance;
                    result.reasons = [verified.reason];
                    return result;
                }
                const status = statusResult(input.status, input.now, pinnedConfig.max_status_age_seconds);
                const verdictAcceptance = verified.artifact.receipt.verdict === 'allow'
                    ? 'ACCEPTED' : 'REJECTED';
                result.native_verification = 'VERIFIED';
                result.acceptance = combine(verdictAcceptance, status.acceptance);
                result.replay_unit = verified.replay;
                result.reasons = [
                    ...(verified.artifact.receipt.verdict === 'allow' ? [] : ['ccs:block']),
                    ...status.reasons,
                ];
                return result;
            }
            catch {
                result.reasons = ['ccs:v14_unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
                }
                if (safeDigest(input.adapter_config) !== configDigest
                    || safeDigest(input.trust_roots) !== rootsDigest) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
                }
                const definitions = validProfile(input.profile, pinnedConfig.action_type);
                if (!definitions) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
                }
                const verified = verifyArtifact(input.artifact, input.now);
                if (!verified.ok || verified.artifact.receipt.verdict !== 'allow') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
                }
                const expected = canonicalAction(input.expected_action, pinnedConfig.action_type);
                if (!expected || !isRecord(expected.parameters) || !isRecord(expected.parameters.arguments)) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
                }
                const receipt = verified.artifact.receipt;
                const actionDigest = digestAeb(expected);
                const semanticMatch = expected.parameters.tool === receipt.tool
                    && receipt.args_digest === sha256Finite(expected.parameters.arguments)
                    && receipt.action === `${String(expected.parameters.tool)}.execute`
                    && sameDigest(expected.parameters.arguments, verified.artifact.tool_args);
                if (!semanticMatch) {
                    return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['ccs:v14_exact_action_projection_mismatch'] };
                }
                const computed = computeCaid(expected, { suite: 'jcs-sha256', definitions });
                if (!isRecord(computed) || typeof computed.caid !== 'string') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: actionDigest, reasons: ['ccs:v14_caid_derivation_failed'] };
                }
                return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
            }
            catch {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ccs:v14_unexpected_mapping_error'] };
            }
        },
    });
}
export function ccsV14ArtifactDigest(artifact) {
    return digestAeb(JSON.parse(canonicalizeAeb(artifact)));
}
//# sourceMappingURL=aeb-ccs-v14-adapter.js.map