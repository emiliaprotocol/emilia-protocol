// SPDX-License-Identifier: Apache-2.0
/**
 * Experimental CCS PyPI 1.1.0 (runtime 0.4.1) adapter for AEB-ADAPTER-v1.
 *
 * The published wheel currently emits the older HMAC result shape. This
 * adapter therefore verifies exactly those shipped bytes and deliberately
 * does not claim support for the Ed25519/extended receipt described by the
 * CCS Internet-Drafts. The HMAC key must be scoped to one relying party and
 * one audience; this is a local composition profile, not a portable receipt.
 *
 * A CCS ALLOW is exposed only as machine-policy-decision evidence. It is not
 * human authorization, execution authority, provider entry, or effect proof.
 */
import crypto from 'node:crypto';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- narrowed and cross-checked below.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
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
//# sourceMappingURL=aeb-ccs-adapter.js.map