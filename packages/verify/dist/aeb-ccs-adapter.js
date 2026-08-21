// SPDX-License-Identifier: Apache-2.0
/**
 * Source-locked CCS adapters for AEB-ADAPTER-v1.
 *
 * The package-backed profile verifies the Ed25519 L1 receipt published with
 * ccs-verifier 1.1.14. A separate adapter implements the 22-field v1.3 shape
 * source-locked to draft-correctover-ccs-05. The historical 1.1.0 profile
 * remains available only for reproducing the older HMAC result shape; none of
 * these byte contracts is silently upgraded or relabeled as another.
 *
 * A CCS ALLOW is exposed only as machine-policy-decision evidence. It is not
 * human authorization, execution authority, provider entry, or effect proof.
 */
import crypto from 'node:crypto';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- narrowed and cross-checked below.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeAeb, digestAeb, mappingProfileDigest, } from './aeb-adapter-contract.js';
import { canonicalizeFiniteJson } from './strict-json.js';
export const CCS_PYPI_DISTRIBUTION_VERSION = '1.1.0';
export const CCS_PYPI_RUNTIME_VERSION = '0.4.1';
export const CCS_PYPI_SOURCE_LOCK = 'ccs-verifier-pypi-1.1.0-runtime-0.4.1';
export const CCS_PYPI_ARTIFACT_VERSION = 'CCS-PYPI-0.4.1-RESULT-v1';
export const CCS_AEB_ADAPTER_ID = 'native:ccs-pypi-hmac-0.4.1';
export const CCS_AEB_ADAPTER_VERSION = '1';
export const CCS_AEB_CONFIG_VERSION = 'AEB-CCS-PYPI-HMAC-CONFIG-v1';
export const CCS_AEB_TRUST_ROOT_VERSION = 'AEB-CCS-PYPI-HMAC-ROOT-v1';
export const CCS_CAID_MAPPING_VERSION = 'AEB-CCS-TOOL-ACTION-MAPPING-v1';
export const CCS_CAID_MAPPER_ID = 'mapper:ccs-pypi-tool-action-v1';
export const CCS_L1_PYPI_DISTRIBUTION_VERSION = '1.1.14';
export const CCS_L1_PYPI_SDIST_SHA256 = '9f75676e5b3d6ace8e91742d8b78b6d15b2d4250414326c17cc9e1aa361ec318';
export const CCS_L1_PYPI_WHEEL_SHA256 = '04a7857253bac2fca25611d17280cebf92fd0a7a2987a4d7ece973d492b17c83';
export const CCS_L1_REFERENCE_VECTOR_SHA256 = '5260e619c010d36729c57c5e8814613215e65e09abfba8a6a1d93f07e919762f';
export const CCS_L1_PYPI_SOURCE_LOCK = 'ccs-verifier-pypi-1.1.14-ed25519-l1';
export const CCS_L1_AEB_ADAPTER_ID = 'native:ccs-pypi-ed25519-l1-1.1.14';
export const CCS_L1_AEB_ADAPTER_VERSION = '1';
export const CCS_L1_AEB_CONFIG_VERSION = 'AEB-CCS-PYPI-ED25519-CONFIG-v1';
export const CCS_L1_AEB_TRUST_ROOT_VERSION = 'AEB-CCS-PYPI-ED25519-ROOT-v1';
export const CCS_L1_CAID_MAPPING_VERSION = 'AEB-CCS-L1-TOOL-ACTION-MAPPING-v1';
export const CCS_L1_CAID_MAPPER_ID = 'mapper:ccs-pypi-l1-tool-action-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const HEX_16_RE = /^[0-9a-f]{16}$/;
const HEX_32_RE = /^[0-9a-f]{32}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#@-]{0,511}$/;
const CCS_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
const ROLE_RE = /^[a-z][a-z0-9-]{0,127}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+\.[1-9][0-9]*$/;
const ARTIFACT_KEYS = new Set(['@version', 'command', 'result']);
const COMMAND_KEYS = new Set(['agent_id', 'tool', 'params', 'timestamp', 'trace_id']);
const RESULT_KEYS = new Set([
    'trace_id', 'verdict', 'block_reason', 'rule_results', 'receipt', 'verified_at',
    'tool', 'params_hash', 'error_code',
]);
const RULE_RESULT_KEYS = new Set(['rule_name', 'verdict', 'reason', 'latency_us', 'error_code']);
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
    'allowed_tools', 'required_rules', 'max_receipt_age_seconds', 'params_hash_bits',
    'deployment_scope',
]);
const SUBJECT_KEYS = new Set(['id', 'kind']);
const ROOT_KEYS = new Set([
    '@version', 'issuer', 'audience', 'key_id', 'algorithm', 'secret_base64url',
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
function validIdentifier(value) {
    return typeof value === 'string' && IDENTIFIER_RE.test(value)
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function validCcsToken(value) {
    // The shipped HMAC input is colon-delimited without escaping. Excluding the
    // delimiter from signed token fields prevents cross-field ambiguity.
    return typeof value === 'string' && CCS_TOKEN_RE.test(value);
}
function validText(value) {
    return typeof value === 'string' && value.length <= 4096
        && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function validHttpsUri(value) {
    return typeof value === 'string' && /^https:\/\/[^\s]+$/.test(value);
}
function safeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function finiteNonNegative(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}
function sortedUniqueStrings(value, predicate) {
    return Array.isArray(value) && value.length > 0 && value.every(predicate)
        && new Set(value).size === value.length;
}
function decodeBase64url(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    try {
        const decoded = Buffer.from(value, 'base64url');
        return decoded.length >= 32 && decoded.toString('base64url') === value ? decoded : null;
    }
    catch {
        return null;
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
function sameDigest(left, right) {
    try {
        return digestAeb(left) === digestAeb(right);
    }
    catch {
        return false;
    }
}
function strictJsonClone(value) {
    try {
        return JSON.parse(canonicalizeAeb(value));
    }
    catch {
        return null;
    }
}
function normalizeCcsInteropJson(value) {
    if (value === null || typeof value === 'boolean')
        return value;
    if (typeof value === 'string') {
        return /^[\x20-\x7e]*$/.test(value) ? value : undefined;
    }
    if (typeof value === 'number') {
        return Number.isSafeInteger(value) ? value : undefined;
    }
    if (Array.isArray(value)) {
        const normalized = value.map(normalizeCcsInteropJson);
        return normalized.some((item) => item === undefined) ? undefined : normalized;
    }
    if (isRecord(value)) {
        const output = {};
        for (const key of Object.keys(value).sort()) {
            if (!/^[\x20-\x7e]+$/.test(key))
                return undefined;
            const normalized = normalizeCcsInteropJson(value[key]);
            if (normalized === undefined)
                return undefined;
            output[key] = normalized;
        }
        return output;
    }
    return undefined;
}
function canonicalParams(value) {
    if (!isRecord(value))
        return null;
    const normalized = normalizeCcsInteropJson(value);
    return isRecord(normalized) ? normalized : null;
}
function pythonJsonCanonical(value) {
    // CCS 0.4.1 uses json.dumps(sort_keys=True, separators=(",", ":")) over
    // ordinary JSON values. For the interoperable subset below, strict JSON plus
    // recursively sorted object keys produces the same UTF-8 bytes.
    const normalized = normalizeCcsInteropJson(value);
    if (!isRecord(normalized))
        return null;
    try {
        return JSON.stringify(normalized);
    }
    catch {
        return null;
    }
}
function paramsHash(params) {
    const canonical = pythonJsonCanonical(params);
    return canonical === null
        ? null
        : crypto.createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16);
}
function ruleSummary(results) {
    return results.map((result) => `${result.rule_name}=${result.verdict}`).join('|');
}
function receiptMacInput(artifact) {
    const result = artifact.result;
    return [
        result.trace_id,
        result.verdict,
        String(result.verified_at),
        result.tool,
        result.params_hash,
        ruleSummary(result.rule_results),
    ].join(':');
}
function validRuleResult(value) {
    return isRecord(value) && exactKeys(value, RULE_RESULT_KEYS)
        && validCcsToken(value.rule_name)
        && ['allow', 'deny', 'escalate'].includes(String(value.verdict))
        && validText(value.reason)
        && finiteNonNegative(value.latency_us)
        && Number.isSafeInteger(value.error_code);
}
function parseArtifact(value) {
    if (!isRecord(value) || !exactKeys(value, ARTIFACT_KEYS)
        || value['@version'] !== CCS_PYPI_ARTIFACT_VERSION
        || !isRecord(value.command) || !exactKeys(value.command, COMMAND_KEYS)
        || !validIdentifier(value.command.agent_id) || !validCcsToken(value.command.tool)
        || canonicalParams(value.command.params) === null
        || !finiteNonNegative(value.command.timestamp) || !validCcsToken(value.command.trace_id)
        || !isRecord(value.result) || !exactKeys(value.result, RESULT_KEYS)
        || !validCcsToken(value.result.trace_id)
        || !['allow', 'deny', 'escalate'].includes(String(value.result.verdict))
        || !validText(value.result.block_reason) || !Array.isArray(value.result.rule_results)
        || value.result.rule_results.length === 0 || !value.result.rule_results.every(validRuleResult)
        || typeof value.result.receipt !== 'string' || !HEX_32_RE.test(value.result.receipt)
        || !finiteNonNegative(value.result.verified_at) || !validCcsToken(value.result.tool)
        || typeof value.result.params_hash !== 'string' || !HEX_16_RE.test(value.result.params_hash)
        || !Number.isSafeInteger(value.result.error_code))
        return null;
    return strictJsonClone(value);
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== CCS_AEB_CONFIG_VERSION
        || typeof value.evidence_role !== 'string' || !ROLE_RE.test(value.evidence_role)
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || !validIdentifier(value.subject.id) || value.subject.kind !== 'system'
        || !validHttpsUri(value.issuer) || !validHttpsUri(value.audience)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || !sortedUniqueStrings(value.allowed_tools, validCcsToken)
        || !sortedUniqueStrings(value.required_rules, validCcsToken)
        || !safeInteger(value.max_receipt_age_seconds) || Number(value.max_receipt_age_seconds) === 0
        || value.params_hash_bits !== 64
        || value.deployment_scope !== 'single-relying-party-local-hmac')
        return null;
    return strictJsonClone(value);
}
function parseRoot(value, config) {
    if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
        || value['@version'] !== CCS_AEB_TRUST_ROOT_VERSION
        || value.issuer !== config.issuer || value.audience !== config.audience
        || !validIdentifier(value.key_id) || value.algorithm !== 'HMAC-SHA256-TRUNC128')
        return null;
    const secret = decodeBase64url(value.secret_base64url);
    const root = strictJsonClone(value);
    return secret && root ? { root, secret } : null;
}
function parsePins(input) {
    const config = parseConfig(input?.config);
    if (!config || !Array.isArray(input?.trust_roots) || input.trust_roots.length !== 1) {
        throw new TypeError('one valid relying-party-pinned CCS HMAC root is required');
    }
    const parsedRoot = parseRoot(input.trust_roots[0], config);
    if (!parsedRoot)
        throw new TypeError('valid audience-scoped CCS HMAC root required');
    return {
        config,
        root: parsedRoot.root,
        secret: parsedRoot.secret,
        configDigest: digestAeb(config),
        rootsDigest: digestAeb(input.trust_roots),
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
function verifyArtifact(value, pins, now) {
    const artifact = parseArtifact(value);
    if (!artifact) {
        return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:artifact_malformed' };
    }
    // Authenticate the native CCS result before assigning VERIFIED to any
    // later semantic refusal. The command/result envelope is checked below;
    // only the result fields covered by CCS are authenticated here.
    const expectedMac = crypto.createHmac('sha256', pins.secret)
        .update(receiptMacInput(artifact), 'utf8').digest().subarray(0, 16);
    const presentedMac = Buffer.from(artifact.result.receipt, 'hex');
    if (presentedMac.length !== expectedMac.length || !crypto.timingSafeEqual(presentedMac, expectedMac)) {
        return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:receipt_invalid' };
    }
    if (artifact.command.trace_id !== artifact.result.trace_id
        || artifact.command.tool !== artifact.result.tool) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:command_result_binding_mismatch' };
    }
    if (!pins.config.allowed_tools.includes(artifact.result.tool)) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:tool_not_pinned' };
    }
    const computedParamsHash = paramsHash(artifact.command.params);
    if (!computedParamsHash || computedParamsHash !== artifact.result.params_hash) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:params_hash_mismatch' };
    }
    const observedRules = artifact.result.rule_results.map((result) => result.rule_name);
    const rulePrefixMatches = observedRules.every((rule, index) => rule === pins.config.required_rules[index]);
    const finalRuleVerdict = artifact.result.rule_results.at(-1)?.verdict;
    const ruleVerdictsCoherent = artifact.result.verdict === 'allow'
        ? observedRules.length === pins.config.required_rules.length
            && artifact.result.rule_results.every((result) => result.verdict === 'allow')
        : artifact.result.verdict === 'escalate'
            ? observedRules.length === pins.config.required_rules.length
                && artifact.result.rule_results.every((result) => result.verdict !== 'deny')
                && artifact.result.rule_results.some((result) => result.verdict === 'escalate')
            : finalRuleVerdict === 'deny'
                && artifact.result.rule_results.slice(0, -1).every((result) => result.verdict !== 'deny');
    if (!rulePrefixMatches || observedRules.length > pins.config.required_rules.length
        || !ruleVerdictsCoherent) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:required_rules_mismatch' };
    }
    const nowSeconds = Date.parse(now) / 1000;
    if (!Number.isFinite(nowSeconds) || artifact.result.verified_at > nowSeconds
        || nowSeconds - artifact.result.verified_at > pins.config.max_receipt_age_seconds) {
        return { ok: false, verified: true, acceptance: 'INDETERMINATE', reason: 'ccs:receipt_not_fresh' };
    }
    return {
        ok: true,
        value: {
            artifact,
            replayUnit: digestAeb({
                source: CCS_PYPI_SOURCE_LOCK,
                issuer: pins.config.issuer,
                audience: pins.config.audience,
                trace_id: artifact.result.trace_id,
                receipt: artifact.result.receipt,
            }),
        },
    };
}
function combineAcceptance(left, right) {
    if (left === 'REJECTED' || right === 'REJECTED')
        return 'REJECTED';
    if (left === 'INDETERMINATE' || right === 'INDETERMINATE')
        return 'INDETERMINATE';
    return 'ACCEPTED';
}
function actionFromArtifact(artifact, actionType, projection) {
    if (projection === 'native-action') {
        return {
            action_type: actionType,
            native_action: {
                type: artifact.command.tool,
                parameters: artifact.command.params,
            },
        };
    }
    return {
        action_type: actionType,
        parameters: {
            tool: artifact.command.tool,
            arguments: artifact.command.params,
        },
    };
}
function canonicalAction(value, actionType, projection) {
    if (!isRecord(value) || value.action_type !== actionType)
        return null;
    if (projection === 'native-action') {
        if (!exactKeys(value, new Set(['action_type', 'native_action']))
            || !isRecord(value.native_action)
            || !exactKeys(value.native_action, new Set(['type', 'parameters']))
            || !validCcsToken(value.native_action.type)
            || canonicalParams(value.native_action.parameters) === null)
            return null;
        return strictJsonClone(value);
    }
    if (!exactKeys(value, new Set(['action_type', 'parameters']))
        || !isRecord(value.parameters)
        || !exactKeys(value.parameters, new Set(['tool', 'arguments']))
        || !validCcsToken(value.parameters.tool)
        || canonicalParams(value.parameters.arguments) === null)
        return null;
    return strictJsonClone(value);
}
export function createCcsAebActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': CCS_CAID_MAPPING_VERSION,
        source: CCS_PYPI_SOURCE_LOCK,
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
/**
 * Define the shared native-action projection used when CCS policy evidence is
 * joined with another independently verified evidence leg for the same action.
 */
export function createCcsNativeActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': CCS_CAID_MAPPING_VERSION,
        source: CCS_PYPI_SOURCE_LOCK,
        projection: 'ccs-native-action-v1',
        action_type: actionType,
        suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: [
                    { name: 'action_type', type: 'string' },
                    { name: 'native_action', type: 'object' },
                ],
                optional_fields: [],
            }],
    };
}
function validMappingProfile(profile, actionType) {
    if (!isRecord(profile) || profile.version !== CCS_CAID_MAPPING_VERSION
        || profile.mapper_id !== CCS_CAID_MAPPER_ID
        || !isRecord(profile.resolver) || profile.resolver.id !== CCS_CAID_MAPPER_ID
        || profile.resolver.version !== '1' || !DIGEST_RE.test(String(profile.resolver.implementation_digest))
        || !isRecord(profile.semantic_equivalence)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !isRecord(profile.definition)
        || !Array.isArray(profile.definition.definitions))
        return null;
    if (sameDigest(profile.definition, createCcsAebActionDefinition(actionType))) {
        return { definitions: profile.definition.definitions, projection: 'tool-invocation' };
    }
    if (sameDigest(profile.definition, createCcsNativeActionDefinition(actionType))) {
        return { definitions: profile.definition.definitions, projection: 'native-action' };
    }
    return null;
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
/** Build a local-HMAC CCS adapter from relying-party-owned pins. */
export function createCcsPyPiHmacAebAdapter(constructorPins) {
    const pins = parsePins(constructorPins);
    return Object.freeze({
        id: CCS_AEB_ADAPTER_ID,
        version: CCS_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            const result = fallback(input, pins);
            try {
                if (safeDigest(input.adapter_config) !== pins.configDigest
                    || safeDigest(input.trust_roots) !== pins.rootsDigest) {
                    result.reasons = ['ccs:constructor_pin_mismatch'];
                    return result;
                }
                const verified = verifyArtifact(input.artifact, pins, input.now);
                if (!verified.ok) {
                    result.native_verification = verified.verified ? 'VERIFIED' : 'FAILED';
                    result.acceptance = verified.acceptance;
                    result.reasons = [verified.reason];
                    return result;
                }
                result.native_verification = 'VERIFIED';
                result.replay_unit = verified.value.replayUnit;
                const status = statusDisposition(input.status, input.now);
                const decisionAcceptance = verified.value.artifact.result.verdict === 'allow'
                    ? 'ACCEPTED'
                    : verified.value.artifact.result.verdict === 'deny' ? 'REJECTED' : 'INDETERMINATE';
                result.acceptance = combineAcceptance(decisionAcceptance, status.acceptance);
                result.reasons = [
                    ...(verified.value.artifact.result.verdict === 'allow'
                        ? [] : [`ccs:${verified.value.artifact.result.verdict}`]),
                    ...status.reasons,
                ];
                return result;
            }
            catch {
                result.reasons = ['ccs:unexpected_adapter_error'];
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
                const mappingProfile = validMappingProfile(input.profile, pins.config.action_type);
                if (!mappingProfile) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
                }
                const verified = verifyArtifact(input.artifact, pins, input.now);
                if (!verified.ok || verified.value.artifact.result.verdict !== 'allow') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
                }
                const projected = canonicalAction(actionFromArtifact(verified.value.artifact, pins.config.action_type, mappingProfile.projection), pins.config.action_type, mappingProfile.projection);
                const expected = canonicalAction(input.expected_action, pins.config.action_type, mappingProfile.projection);
                if (!projected || !expected) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
                }
                const actionDigest = digestAeb(projected);
                if (!sameDigest(projected, expected)) {
                    return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['exact_action_projection_mismatch'] };
                }
                let computed;
                try {
                    computed = computeCaid(projected, {
                        suite: 'jcs-sha256',
                        definitions: mappingProfile.definitions,
                    });
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
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ccs:unexpected_mapping_error'] };
            }
        },
    });
}
const CCS_L1_RECEIPT_KEYS = new Set([
    'trace_id', 'receipt_version', 'verdict', 'timestamp', 'tool', 'tool_call_id',
    'params_hash', 'args_digest', 'rule_summary', 'rule_version', 'request_hash',
    'response_hash', 'runtime_context_hash', 'config_hash', 'verifier_source_class',
    'deployment_mode', 'issuer', 'audience', 'nonce', 'sequence', 'issued_at',
    'expires_at', 'max_clock_skew', 'action', 'signature', 'signing_algorithm',
    'public_key_fingerprint', 'public_key', 'verified_at', 'latency_us',
]);
const CCS_L1_CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
    'allowed_actions', 'allowed_tools', 'required_rule_version',
    'max_receipt_age_seconds', 'max_clock_skew_seconds', 'deployment_scope',
]);
const CCS_L1_ROOT_KEYS = new Set([
    '@version', 'issuer', 'key_id', 'algorithm', 'public_key_raw_base64',
    'public_key_fingerprint_sha256_16',
]);
const CCS_L1_ACTION_KEYS = new Set(['action_type', 'parameters']);
const CCS_L1_ACTION_PARAMETER_KEYS = new Set(['action', 'tool', 'arguments']);
const CCS_L1_PROFILE_KEYS = new Set([
    'version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver',
    'semantic_equivalence', 'profile_digest',
]);
const CCS_L1_RESOLVER_KEYS = new Set(['id', 'version', 'implementation_digest']);
const CCS_L1_EQUIVALENCE_KEYS = new Set([
    'assertion', 'loss_policy', 'omitted_material_fields', 'omitted_nonmaterial_fields',
]);
const CCS_L1_MAPPING_PROFILE_ID = 'ccs-l1-tool-action';
const CCS_L1_MAPPING_REGISTRY_REF = 'mapping:ccs-l1-tool-action';
const CCS_L1_OMITTED_NONMATERIAL_FIELDS = Object.freeze([
    'trace_id', 'timestamp', 'tool_call_id', 'params_hash', 'rule_summary',
    'request_hash', 'response_hash', 'runtime_context_hash', 'config_hash',
    'verifier_source_class', 'deployment_mode', 'nonce', 'sequence',
    'issued_at', 'expires_at', 'max_clock_skew', 'verified_at', 'latency_us',
]);
const HEX_64_RE = /^[0-9a-f]{64}$/;
const HEX_FP16_RE = /^[0-9a-f]{16}$/;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function decodeCanonicalBase64(value, length) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)
        || value.length % 4 !== 0)
        return null;
    try {
        const decoded = Buffer.from(value, 'base64');
        return decoded.length === length && decoded.toString('base64') === value ? decoded : null;
    }
    catch {
        return null;
    }
}
function strictFiniteJsonClone(value) {
    try {
        return JSON.parse(canonicalizeFiniteJson(value));
    }
    catch {
        return null;
    }
}
function validOptionalHash(value) {
    return value === '' || (typeof value === 'string' && HEX_64_RE.test(value));
}
function parseL1Receipt(value) {
    if (!isRecord(value) || !exactKeys(value, CCS_L1_RECEIPT_KEYS)
        || !validIdentifier(value.trace_id)
        || value.receipt_version !== '1.1'
        || !['allow', 'deny', 'escalate'].includes(String(value.verdict))
        || !finiteNonNegative(value.timestamp)
        || !validCcsToken(value.tool)
        || !(value.tool_call_id === '' || validIdentifier(value.tool_call_id))
        || !validText(value.params_hash) || value.params_hash.length === 0
        || typeof value.args_digest !== 'string' || !HEX_64_RE.test(value.args_digest)
        || !validText(value.rule_summary) || value.rule_summary.length === 0
        || !validIdentifier(value.rule_version)
        || !validOptionalHash(value.request_hash) || !validOptionalHash(value.response_hash)
        || !validOptionalHash(value.runtime_context_hash) || !validOptionalHash(value.config_hash)
        || !validIdentifier(value.verifier_source_class) || !validIdentifier(value.deployment_mode)
        || !validIdentifier(value.issuer) || !validIdentifier(value.audience)
        || !validIdentifier(value.nonce) || !safeInteger(value.sequence)
        || !finiteNonNegative(value.issued_at) || !finiteNonNegative(value.expires_at)
        || !finiteNonNegative(value.max_clock_skew) || !validIdentifier(value.action)
        || value.signing_algorithm !== 'Ed25519'
        || typeof value.public_key_fingerprint !== 'string'
        || !HEX_FP16_RE.test(value.public_key_fingerprint)
        || decodeCanonicalBase64(value.public_key, 32) === null
        || decodeCanonicalBase64(value.signature, 64) === null
        || !finiteNonNegative(value.verified_at) || !finiteNonNegative(value.latency_us))
        return null;
    return strictFiniteJsonClone(value);
}
function parseL1Config(value) {
    if (!isRecord(value) || !exactKeys(value, CCS_L1_CONFIG_KEYS)
        || value['@version'] !== CCS_L1_AEB_CONFIG_VERSION
        || typeof value.evidence_role !== 'string' || !ROLE_RE.test(value.evidence_role)
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || !validIdentifier(value.subject.id) || value.subject.kind !== 'system'
        || !validIdentifier(value.issuer) || !validIdentifier(value.audience)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || !sortedUniqueStrings(value.allowed_actions, validIdentifier)
        || !sortedUniqueStrings(value.allowed_tools, validCcsToken)
        || !validIdentifier(value.required_rule_version)
        || !safeInteger(value.max_receipt_age_seconds) || Number(value.max_receipt_age_seconds) === 0
        || !safeInteger(value.max_clock_skew_seconds)
        || value.deployment_scope !== 'pinned-ed25519-issuer')
        return null;
    return strictJsonClone(value);
}
function parseL1Root(value, config) {
    if (!isRecord(value) || !exactKeys(value, CCS_L1_ROOT_KEYS)
        || value['@version'] !== CCS_L1_AEB_TRUST_ROOT_VERSION
        || value.issuer !== config.issuer || !validIdentifier(value.key_id)
        || value.algorithm !== 'Ed25519'
        || typeof value.public_key_fingerprint_sha256_16 !== 'string'
        || !HEX_FP16_RE.test(value.public_key_fingerprint_sha256_16))
        return null;
    const key = decodeCanonicalBase64(value.public_key_raw_base64, 32);
    if (!key)
        return null;
    const fingerprint = crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
    if (fingerprint !== value.public_key_fingerprint_sha256_16)
        return null;
    const root = strictJsonClone(value);
    return root ? { root, key } : null;
}
function parseL1Pins(input) {
    const config = parseL1Config(input?.config);
    if (!config || !Array.isArray(input?.trust_roots) || input.trust_roots.length !== 1) {
        throw new TypeError('one valid relying-party-pinned CCS Ed25519 root is required');
    }
    const parsedRoot = parseL1Root(input.trust_roots[0], config);
    if (!parsedRoot)
        throw new TypeError('valid issuer-scoped CCS Ed25519 root required');
    return {
        config,
        root: parsedRoot.root,
        rootKey: parsedRoot.key,
        configDigest: digestAeb(config),
        rootsDigest: digestAeb(input.trust_roots),
    };
}
function l1SignatureValid(receipt) {
    const embedded = decodeCanonicalBase64(receipt.public_key, 32);
    const signature = decodeCanonicalBase64(receipt.signature, 64);
    if (!embedded || !signature)
        return false;
    const fingerprint = crypto.createHash('sha256').update(embedded).digest('hex').slice(0, 16);
    if (fingerprint !== receipt.public_key_fingerprint)
        return false;
    let publicKey;
    try {
        publicKey = crypto.createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, embedded]),
            format: 'der',
            type: 'spki',
        });
    }
    catch {
        return false;
    }
    const payload = { ...receipt };
    delete payload.signature;
    try {
        return crypto.verify(null, Buffer.from(canonicalizeFiniteJson(payload), 'utf8'), publicKey, signature);
    }
    catch {
        return false;
    }
}
function verifyL1Artifact(value, pins, now) {
    const receipt = parseL1Receipt(value);
    if (!receipt) {
        return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:l1_artifact_malformed' };
    }
    if (!l1SignatureValid(receipt)) {
        return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:l1_signature_invalid' };
    }
    const embedded = decodeCanonicalBase64(receipt.public_key, 32);
    if (!embedded || receipt.issuer !== pins.config.issuer
        || receipt.public_key_fingerprint !== pins.root.public_key_fingerprint_sha256_16
        || embedded.length !== pins.rootKey.length
        || !crypto.timingSafeEqual(embedded, pins.rootKey)) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_untrusted_signing_key' };
    }
    if (receipt.audience !== pins.config.audience) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_audience_mismatch' };
    }
    if (!pins.config.allowed_actions.includes(receipt.action)) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_action_not_pinned' };
    }
    if (!pins.config.allowed_tools.includes(receipt.tool)) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_tool_not_pinned' };
    }
    if (receipt.rule_version !== pins.config.required_rule_version) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_rule_version_mismatch' };
    }
    if (receipt.max_clock_skew > pins.config.max_clock_skew_seconds
        || receipt.expires_at <= receipt.issued_at
        || receipt.timestamp < receipt.issued_at
        || receipt.verified_at < receipt.issued_at
        || receipt.timestamp > receipt.expires_at + receipt.max_clock_skew
        || receipt.verified_at > receipt.expires_at + receipt.max_clock_skew) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_time_bounds_invalid' };
    }
    const nowSeconds = Date.parse(now) / 1000;
    if (!Number.isFinite(nowSeconds)) {
        return { ok: false, verified: true, acceptance: 'INDETERMINATE', reason: 'ccs:l1_current_time_invalid' };
    }
    if (nowSeconds > receipt.expires_at + receipt.max_clock_skew) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_receipt_expired' };
    }
    if (receipt.issued_at > nowSeconds + receipt.max_clock_skew) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_receipt_not_yet_valid' };
    }
    if (nowSeconds - receipt.issued_at > pins.config.max_receipt_age_seconds) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:l1_receipt_too_old' };
    }
    return {
        ok: true,
        value: {
            receipt,
            replayUnit: digestAeb({
                source: CCS_L1_PYPI_SOURCE_LOCK,
                issuer: receipt.issuer,
                audience: receipt.audience,
                public_key_fingerprint: receipt.public_key_fingerprint,
                nonce: receipt.nonce,
                sequence: receipt.sequence,
                signature: receipt.signature,
            }),
        },
    };
}
function canonicalL1Action(value, actionType) {
    if (!isRecord(value) || !exactKeys(value, CCS_L1_ACTION_KEYS)
        || value.action_type !== actionType || !isRecord(value.parameters)
        || !exactKeys(value.parameters, CCS_L1_ACTION_PARAMETER_KEYS)
        || !validIdentifier(value.parameters.action) || !validCcsToken(value.parameters.tool))
        return null;
    const argumentsValue = normalizeCcsInteropJson(value.parameters.arguments);
    if (!isRecord(argumentsValue))
        return null;
    return strictJsonClone({
        action_type: actionType,
        parameters: {
            action: value.parameters.action,
            tool: value.parameters.tool,
            arguments: argumentsValue,
        },
    });
}
function l1ArgsDigest(value) {
    try {
        return crypto.createHash('sha256')
            .update(canonicalizeFiniteJson(value), 'utf8')
            .digest('hex');
    }
    catch {
        return null;
    }
}
export function createCcsL1AebActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': CCS_L1_CAID_MAPPING_VERSION,
        source: CCS_L1_PYPI_SOURCE_LOCK,
        projection: 'ccs-l1-signed-action-and-args-digest-v1',
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
function validL1MappingProfile(profile, actionType) {
    const expectedResolverDigest = digestAeb({
        implementation: CCS_L1_CAID_MAPPER_ID,
        version: '1',
    });
    if (!isRecord(profile) || !exactKeys(profile, CCS_L1_PROFILE_KEYS)
        || profile.version !== CCS_L1_CAID_MAPPING_VERSION
        || profile.registry_entry_ref !== CCS_L1_MAPPING_REGISTRY_REF
        || profile.mapper_id !== CCS_L1_CAID_MAPPER_ID
        || !isRecord(profile.resolver) || !exactKeys(profile.resolver, CCS_L1_RESOLVER_KEYS)
        || profile.resolver.id !== CCS_L1_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || profile.resolver.implementation_digest !== expectedResolverDigest
        || !isRecord(profile.semantic_equivalence)
        || !exactKeys(profile.semantic_equivalence, CCS_L1_EQUIVALENCE_KEYS)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !sameDigest(profile.semantic_equivalence.omitted_nonmaterial_fields, CCS_L1_OMITTED_NONMATERIAL_FIELDS)
        || !isRecord(profile.definition) || !Array.isArray(profile.definition.definitions)
        || !sameDigest(profile.definition, createCcsL1AebActionDefinition(actionType))
        || profile.profile_digest !== mappingProfileDigest(CCS_L1_MAPPING_PROFILE_ID, profile))
        return null;
    return profile.definition.definitions;
}
function fallbackL1(input, pins) {
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
/** Build a source-locked CCS 1.1.14 Ed25519 L1 adapter from relying-party pins. */
export function createCcsPyPiL1AebAdapter(constructorPins) {
    const pins = parseL1Pins(constructorPins);
    return Object.freeze({
        id: CCS_L1_AEB_ADAPTER_ID,
        version: CCS_L1_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            const result = fallbackL1(input, pins);
            try {
                if (safeDigest(input.adapter_config) !== pins.configDigest
                    || safeDigest(input.trust_roots) !== pins.rootsDigest) {
                    result.reasons = ['ccs:l1_constructor_pin_mismatch'];
                    return result;
                }
                const verified = verifyL1Artifact(input.artifact, pins, input.now);
                if (!verified.ok) {
                    result.native_verification = verified.verified ? 'VERIFIED' : 'FAILED';
                    result.acceptance = verified.acceptance;
                    result.reasons = [verified.reason];
                    return result;
                }
                result.native_verification = 'VERIFIED';
                result.replay_unit = verified.value.replayUnit;
                const status = statusDisposition(input.status, input.now);
                const decisionAcceptance = verified.value.receipt.verdict === 'allow'
                    ? 'ACCEPTED'
                    : verified.value.receipt.verdict === 'deny' ? 'REJECTED' : 'INDETERMINATE';
                result.acceptance = combineAcceptance(decisionAcceptance, status.acceptance);
                result.reasons = [
                    ...(verified.value.receipt.verdict === 'allow'
                        ? [] : [`ccs:${verified.value.receipt.verdict}`]),
                    ...status.reasons,
                ];
                return result;
            }
            catch {
                result.reasons = ['ccs:l1_unexpected_adapter_error'];
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
                const definitions = validL1MappingProfile(input.profile, pins.config.action_type);
                if (!definitions) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
                }
                const verified = verifyL1Artifact(input.artifact, pins, input.now);
                if (!verified.ok || verified.value.receipt.verdict !== 'allow') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
                }
                const expected = canonicalL1Action(input.expected_action, pins.config.action_type);
                if (!expected || !isRecord(expected.parameters) || !isRecord(expected.parameters.arguments)) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
                }
                const receipt = verified.value.receipt;
                const digest = l1ArgsDigest(expected.parameters.arguments);
                const semanticMatch = expected.parameters.action === receipt.action
                    && expected.parameters.tool === receipt.tool
                    && digest === receipt.args_digest;
                const actionDigest = digestAeb(expected);
                if (!semanticMatch) {
                    return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['exact_action_projection_mismatch'] };
                }
                let computed;
                try {
                    computed = computeCaid(expected, { suite: 'jcs-sha256', definitions });
                }
                catch {
                    computed = null;
                }
                if (!isRecord(computed) || typeof computed.caid !== 'string'
                    || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)
                    || computed.digest !== actionDigest) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
                }
                return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
            }
            catch {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ccs:l1_unexpected_mapping_error'] };
            }
        },
    });
}
/**
 * CCS-05 calls the extended receipt shape "v1.3", while the latest public
 * ccs-verifier package (1.1.14) still emits its distinct receipt_version 1.1
 * shape. This profile is therefore source-locked to the Internet-Draft bytes
 * and intentionally does not relabel the package-backed adapter above.
 */
export const CCS_V13_DRAFT_URL = 'https://www.ietf.org/archive/id/draft-correctover-ccs-05.txt';
export const CCS_V13_DRAFT_SHA256 = 'c91f0fa31b1b9e5e2dfe79b99f3b554075d3a44d5309406e748b728f86767cb9';
export const CCS_V13_REFERENCE_CODEBERG_COMMIT = 'a5cddf5093724ab149059ce1f2d507b5d0aeb36d';
export const CCS_V13_REFERENCE_PYPI_VERSION = '1.1.14';
export const CCS_V13_SOURCE_LOCK = 'draft-correctover-ccs-05-v1.3-c91f0fa31b1b9e5';
export const CCS_V13_AEB_ADAPTER_ID = 'native:ccs-05-v1.3-ed25519';
export const CCS_V13_AEB_ADAPTER_VERSION = '1';
export const CCS_V13_AEB_CONFIG_VERSION = 'AEB-CCS-05-V1.3-CONFIG-v1';
export const CCS_V13_AEB_TRUST_ROOT_VERSION = 'AEB-CCS-05-V1.3-ROOT-v1';
export const CCS_V13_CAID_MAPPING_VERSION = 'AEB-CCS-05-V1.3-TOOL-ACTION-MAPPING-v1';
export const CCS_V13_CAID_MAPPER_ID = 'mapper:ccs-05-v1.3-tool-action-v1';
const CCS_V13_RECEIPT_KEYS = new Set([
    'trace_id', 'verdict', 'timestamp', 'tool', 'params_hash', 'rule_summary',
    'receipt', 'verified_at', 'block_reason', 'request_hash', 'response_hash',
    'runtime_context_hash', 'action', 'config_hash', 'issuer', 'audience',
    'nonce', 'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
]);
const CCS_V13_CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
    'allowed_tools', 'max_receipt_age_seconds', 'max_clock_skew_seconds',
    'deployment_scope',
]);
const CCS_V13_ROOT_KEYS = new Set([
    '@version', 'issuer', 'key_id', 'algorithm', 'public_key_raw_base64',
    'public_key_fingerprint_sha256_16',
]);
const CCS_V13_ACTION_KEYS = new Set(['action_type', 'parameters']);
const CCS_V13_ACTION_PARAMETER_KEYS = new Set(['tool', 'arguments']);
const CCS_V13_PROFILE_KEYS = new Set([
    'version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver',
    'semantic_equivalence', 'profile_digest',
]);
const CCS_V13_RESOLVER_KEYS = new Set(['id', 'version', 'implementation_digest']);
const CCS_V13_EQUIVALENCE_KEYS = new Set([
    'assertion', 'loss_policy', 'omitted_material_fields', 'omitted_nonmaterial_fields',
]);
const CCS_V13_MAPPING_PROFILE_ID = 'ccs-v13-tool-action';
const CCS_V13_MAPPING_REGISTRY_REF = 'mapping:ccs-v13-tool-action';
const CCS_V13_OMITTED_NONMATERIAL_FIELDS = Object.freeze([
    'trace_id', 'verdict', 'timestamp', 'params_hash', 'rule_summary', 'receipt',
    'verified_at', 'block_reason', 'request_hash', 'response_hash',
    'runtime_context_hash', 'config_hash', 'issuer', 'audience', 'nonce',
    'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
]);
const CCS_V13_ACTION_RE = /^ccs:tool-invoke:([A-Za-z0-9][A-Za-z0-9._/-]{0,255}):([0-9a-f]{64})$/;
const HEX_128_RE = /^[0-9a-f]{128}$/;
function validSha256Binding(value, optional = false) {
    return (optional && value === '') || (typeof value === 'string' && DIGEST_RE.test(value));
}
function parseV13Receipt(value) {
    if (!isRecord(value) || !exactKeys(value, CCS_V13_RECEIPT_KEYS)
        || typeof value.trace_id !== 'string' || !HEX_16_RE.test(value.trace_id)
        || !['allow', 'deny', 'escalate'].includes(String(value.verdict))
        || !finiteNonNegative(value.timestamp) || !validCcsToken(value.tool)
        || typeof value.params_hash !== 'string' || !HEX_16_RE.test(value.params_hash)
        || !validText(value.rule_summary)
        || typeof value.receipt !== 'string' || !HEX_32_RE.test(value.receipt)
        || !finiteNonNegative(value.verified_at) || !validText(value.block_reason)
        || !validSha256Binding(value.request_hash)
        || !validSha256Binding(value.response_hash, true)
        || !validSha256Binding(value.runtime_context_hash, true)
        || !validSha256Binding(value.config_hash)
        || !validHttpsUri(value.issuer) || !validHttpsUri(value.audience)
        || typeof value.nonce !== 'string' || !HEX_32_RE.test(value.nonce)
        || !safeInteger(value.sequence) || !finiteNonNegative(value.issued_at)
        || !finiteNonNegative(value.expires_at) || !finiteNonNegative(value.max_clock_skew)
        || typeof value.signature !== 'string' || !HEX_128_RE.test(value.signature))
        return null;
    const actionMatch = typeof value.action === 'string' ? CCS_V13_ACTION_RE.exec(value.action) : null;
    if (!actionMatch || actionMatch[1] !== value.tool || actionMatch[2].slice(0, 16) !== value.params_hash)
        return null;
    if (value.verdict === 'allow' ? value.block_reason !== '' : value.block_reason.length === 0)
        return null;
    return strictFiniteJsonClone(value);
}
function parseV13Config(value) {
    if (!isRecord(value) || !exactKeys(value, CCS_V13_CONFIG_KEYS)
        || value['@version'] !== CCS_V13_AEB_CONFIG_VERSION
        || typeof value.evidence_role !== 'string' || !ROLE_RE.test(value.evidence_role)
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || !validIdentifier(value.subject.id) || value.subject.kind !== 'system'
        || !validHttpsUri(value.issuer) || !validHttpsUri(value.audience)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || !sortedUniqueStrings(value.allowed_tools, validCcsToken)
        || !safeInteger(value.max_receipt_age_seconds) || Number(value.max_receipt_age_seconds) === 0
        || !safeInteger(value.max_clock_skew_seconds)
        || value.deployment_scope !== 'pinned-ed25519-issuer')
        return null;
    return strictJsonClone(value);
}
function parseV13Root(value, config) {
    if (!isRecord(value) || !exactKeys(value, CCS_V13_ROOT_KEYS)
        || value['@version'] !== CCS_V13_AEB_TRUST_ROOT_VERSION
        || value.issuer !== config.issuer || !validIdentifier(value.key_id)
        || value.algorithm !== 'Ed25519'
        || typeof value.public_key_fingerprint_sha256_16 !== 'string'
        || !HEX_FP16_RE.test(value.public_key_fingerprint_sha256_16))
        return null;
    const key = decodeCanonicalBase64(value.public_key_raw_base64, 32);
    if (!key)
        return null;
    const fingerprint = crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
    if (fingerprint !== value.public_key_fingerprint_sha256_16)
        return null;
    const root = strictJsonClone(value);
    return root ? { root, key } : null;
}
function parseV13Pins(input) {
    const config = parseV13Config(input?.config);
    if (!config || !Array.isArray(input?.trust_roots) || input.trust_roots.length !== 1) {
        throw new TypeError('one valid relying-party-pinned CCS-05 v1.3 Ed25519 root is required');
    }
    const parsedRoot = parseV13Root(input.trust_roots[0], config);
    if (!parsedRoot)
        throw new TypeError('valid issuer-scoped CCS-05 v1.3 Ed25519 root required');
    return {
        config,
        root: parsedRoot.root,
        rootKey: parsedRoot.key,
        configDigest: digestAeb(config),
        rootsDigest: digestAeb(input.trust_roots),
    };
}
function verifyV13Signature(receipt, rawPublicKey) {
    const signature = Buffer.from(receipt.signature, 'hex');
    if (signature.length !== 64)
        return false;
    let publicKey;
    try {
        publicKey = crypto.createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
            format: 'der',
            type: 'spki',
        });
    }
    catch {
        return false;
    }
    const payload = { ...receipt };
    delete payload.signature;
    try {
        return crypto.verify(null, Buffer.from(canonicalizeFiniteJson(payload), 'utf8'), publicKey, signature);
    }
    catch {
        return false;
    }
}
function verifyV13Artifact(value, pins, now) {
    const receipt = parseV13Receipt(value);
    if (!receipt) {
        return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:v13_artifact_malformed' };
    }
    if (!verifyV13Signature(receipt, pins.rootKey)) {
        return { ok: false, verified: false, acceptance: 'REJECTED', reason: 'ccs:v13_signature_invalid' };
    }
    if (receipt.issuer !== pins.config.issuer) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_untrusted_issuer' };
    }
    if (receipt.audience !== pins.config.audience) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_audience_mismatch' };
    }
    if (!pins.config.allowed_tools.includes(receipt.tool)) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_tool_not_pinned' };
    }
    if (receipt.max_clock_skew > pins.config.max_clock_skew_seconds
        || receipt.expires_at <= receipt.issued_at
        || receipt.timestamp < receipt.issued_at
        || receipt.verified_at < receipt.issued_at
        || receipt.timestamp > receipt.expires_at + receipt.max_clock_skew
        || receipt.verified_at > receipt.expires_at + receipt.max_clock_skew) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_time_bounds_invalid' };
    }
    const nowSeconds = Date.parse(now) / 1000;
    if (!Number.isFinite(nowSeconds)) {
        return { ok: false, verified: true, acceptance: 'INDETERMINATE', reason: 'ccs:v13_current_time_invalid' };
    }
    if (nowSeconds > receipt.expires_at + receipt.max_clock_skew) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_receipt_expired' };
    }
    if (nowSeconds < receipt.issued_at - receipt.max_clock_skew) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_receipt_not_yet_valid' };
    }
    if (nowSeconds - receipt.issued_at > pins.config.max_receipt_age_seconds) {
        return { ok: false, verified: true, acceptance: 'REJECTED', reason: 'ccs:v13_receipt_too_old' };
    }
    return {
        ok: true,
        value: {
            receipt,
            replayUnit: digestAeb({ source: CCS_V13_SOURCE_LOCK, issuer: receipt.issuer, nonce: receipt.nonce }),
        },
    };
}
function canonicalV13Action(value, actionType) {
    if (!isRecord(value) || !exactKeys(value, CCS_V13_ACTION_KEYS)
        || value.action_type !== actionType || !isRecord(value.parameters)
        || !exactKeys(value.parameters, CCS_V13_ACTION_PARAMETER_KEYS)
        || !validCcsToken(value.parameters.tool))
        return null;
    const argumentsValue = normalizeCcsInteropJson(value.parameters.arguments);
    if (!isRecord(argumentsValue))
        return null;
    return strictJsonClone({
        action_type: actionType,
        parameters: { tool: value.parameters.tool, arguments: argumentsValue },
    });
}
export function createCcsV13AebActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': CCS_V13_CAID_MAPPING_VERSION,
        source: CCS_V13_SOURCE_LOCK,
        source_media_type: 'application/x-ccs-receipt+json',
        projection: 'ccs-v13-signed-tool-and-full-params-digest-v1',
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
function validV13MappingProfile(profile, actionType) {
    const expectedResolverDigest = digestAeb({ implementation: CCS_V13_CAID_MAPPER_ID, version: '1' });
    if (!isRecord(profile) || !exactKeys(profile, CCS_V13_PROFILE_KEYS)
        || profile.version !== CCS_V13_CAID_MAPPING_VERSION
        || profile.registry_entry_ref !== CCS_V13_MAPPING_REGISTRY_REF
        || profile.mapper_id !== CCS_V13_CAID_MAPPER_ID
        || !isRecord(profile.resolver) || !exactKeys(profile.resolver, CCS_V13_RESOLVER_KEYS)
        || profile.resolver.id !== CCS_V13_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || profile.resolver.implementation_digest !== expectedResolverDigest
        || !isRecord(profile.semantic_equivalence)
        || !exactKeys(profile.semantic_equivalence, CCS_V13_EQUIVALENCE_KEYS)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !sameDigest(profile.semantic_equivalence.omitted_nonmaterial_fields, CCS_V13_OMITTED_NONMATERIAL_FIELDS)
        || !isRecord(profile.definition) || !Array.isArray(profile.definition.definitions)
        || !sameDigest(profile.definition, createCcsV13AebActionDefinition(actionType))
        || profile.profile_digest !== mappingProfileDigest(CCS_V13_MAPPING_PROFILE_ID, profile))
        return null;
    return profile.definition.definitions;
}
function fallbackV13(input, pins) {
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
/** Build the source-locked CCS-05 v1.3 Ed25519 enforcement adapter. */
export function createCcsV13AebAdapter(constructorPins) {
    const pins = parseV13Pins(constructorPins);
    return Object.freeze({
        id: CCS_V13_AEB_ADAPTER_ID,
        version: CCS_V13_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            const result = fallbackV13(input, pins);
            try {
                if (safeDigest(input.adapter_config) !== pins.configDigest
                    || safeDigest(input.trust_roots) !== pins.rootsDigest) {
                    result.reasons = ['ccs:v13_constructor_pin_mismatch'];
                    return result;
                }
                const verified = verifyV13Artifact(input.artifact, pins, input.now);
                if (!verified.ok) {
                    result.native_verification = verified.verified ? 'VERIFIED' : 'FAILED';
                    result.acceptance = verified.acceptance;
                    result.reasons = [verified.reason];
                    return result;
                }
                result.native_verification = 'VERIFIED';
                result.replay_unit = verified.value.replayUnit;
                const status = statusDisposition(input.status, input.now);
                const decisionAcceptance = verified.value.receipt.verdict === 'allow'
                    ? 'ACCEPTED'
                    : verified.value.receipt.verdict === 'deny' ? 'REJECTED' : 'INDETERMINATE';
                result.acceptance = combineAcceptance(decisionAcceptance, status.acceptance);
                result.reasons = [
                    ...(verified.value.receipt.verdict === 'allow' ? [] : [`ccs:${verified.value.receipt.verdict}`]),
                    ...status.reasons,
                ];
                return result;
            }
            catch {
                result.reasons = ['ccs:v13_unexpected_adapter_error'];
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
                const definitions = validV13MappingProfile(input.profile, pins.config.action_type);
                if (!definitions) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
                }
                const verified = verifyV13Artifact(input.artifact, pins, input.now);
                if (!verified.ok || verified.value.receipt.verdict !== 'allow') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
                }
                const expected = canonicalV13Action(input.expected_action, pins.config.action_type);
                if (!expected || !isRecord(expected.parameters) || !isRecord(expected.parameters.arguments)) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
                }
                const fullParamsHash = l1ArgsDigest(expected.parameters.arguments);
                const receipt = verified.value.receipt;
                const expectedAction = fullParamsHash
                    ? `ccs:tool-invoke:${String(expected.parameters.tool)}:${fullParamsHash}`
                    : null;
                const semanticMatch = expected.parameters.tool === receipt.tool
                    && fullParamsHash?.slice(0, 16) === receipt.params_hash
                    && expectedAction === receipt.action;
                const actionDigest = digestAeb(expected);
                if (!semanticMatch) {
                    return {
                        mapping: 'MISMATCH',
                        caid: null,
                        action_digest: actionDigest,
                        reasons: ['ccs:v13_exact_action_projection_mismatch'],
                    };
                }
                let computed;
                try {
                    computed = computeCaid(expected, { suite: 'jcs-sha256', definitions });
                }
                catch {
                    computed = null;
                }
                if (!isRecord(computed) || typeof computed.caid !== 'string'
                    || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)
                    || computed.digest !== actionDigest) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
                }
                return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
            }
            catch {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ccs:v13_unexpected_mapping_error'] };
            }
        },
    });
}
//# sourceMappingURL=aeb-ccs-adapter.js.map