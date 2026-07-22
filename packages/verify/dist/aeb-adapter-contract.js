// SPDX-License-Identifier: Apache-2.0
/**
 * AEB-ADAPTER-v1 — relying-party-pinned evidence adapter contract.
 *
 * This module is intentionally a composition boundary, not another receipt
 * format. An adapter verifies a native artifact and projects it into a named
 * CAID mapping profile. The relying party, not the presenter, pins the
 * adapter version, trust roots, mapping profile, and evidence requirement.
 *
 * The evaluator keeps four decisions separate:
 *   VERIFIED    native artifact verification succeeded
 *   ACCEPTED    the relying party accepts that native result under its pins
 *   SATISFIED   the complete pinned requirement is met for one CAID
 *   AUTHORIZED  a local execution policy has allowed the effect
 *
 * A signed evaluation record is useful for evidence transport, but it is not
 * blindly trusted: verifyAebEvaluation re-derives the result from the pinned
 * configuration, adapter registry, and artifacts supplied by the relying party.
 */
import crypto from 'node:crypto';
import { AEC_VERSION, actionDigest as aecActionDigest, verifyAuthorizationChain } from './evidence-chain.js';
export const AEB_ADAPTER_VERSION = 'AEB-ADAPTER-v1';
export const AEB_EVALUATION_VERSION = 'AEB-EVALUATION-v1';
export const AEB_EVALUATION_DOMAIN = `${AEB_EVALUATION_VERSION}\0`;
export const AEB_REQUIREMENT_VERSION = 'AEB-REQUIREMENT-v1';
export const AEB_REGISTRY_VERSION = 'EP-EVIDENCE-REGISTRY-v1';
export const AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION = 'EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1';
export const AEB_NATIVE_VERIFICATION_ATTESTATION_DOMAIN = `${AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION}\0`;
/** Small synchronous reference store. Production stores must provide an atomic equivalent. */
export class InMemoryAebConsumptionStore {
    entries = new Map();
    reserve(key) {
        if (this.entries.has(key))
            return false;
        this.entries.set(key, 'RESERVED');
        return true;
    }
    commit(key) {
        if (this.entries.get(key) !== 'RESERVED')
            return false;
        this.entries.set(key, 'CONSUMED');
        return true;
    }
    release(key) {
        if (this.entries.get(key) !== 'RESERVED')
            return false;
        this.entries.delete(key);
        return true;
    }
    state(key) {
        return this.entries.get(key) ?? 'AVAILABLE';
    }
}
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENT_RE = /^[A-Za-z0-9_.:-]{1,256}$/;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            deepFreeze(child);
        Object.freeze(value);
    }
    return value;
}
function canonicalize(value, seen = new WeakSet()) {
    if (value === null)
        return 'null';
    if (typeof value === 'string' || typeof value === 'boolean')
        return JSON.stringify(value);
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value))
            throw new Error('non-integer number is not canonicalizable');
        return JSON.stringify(value);
    }
    if (typeof value !== 'object' || value === undefined)
        throw new Error('value is not canonicalizable');
    if (seen.has(value))
        throw new Error('cyclic value is not canonicalizable');
    seen.add(value);
    let output;
    if (Array.isArray(value)) {
        output = `[${value.map((item) => canonicalize(item, seen)).join(',')}]`;
    }
    else {
        output = `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`).join(',')}}`;
    }
    seen.delete(value);
    return output;
}
function sha256(value) {
    return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}
function digest(value) {
    return sha256(Buffer.from(canonicalize(value), 'utf8'));
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function parseInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_RE);
    if (!match)
        return NaN;
    const [, y, mo, d, h, mi, s] = match;
    const date = new Date(0);
    date.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
    date.setUTCHours(Number(h), Number(mi), Number(s), 0);
    if (date.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`)
        return NaN;
    return date.getTime();
}
function sortedUnique(values) {
    return [...new Set(values)].sort();
}
function exactString(value) {
    return typeof value === 'string' && value.length > 0 && IDENT_RE.test(value);
}
function safeClone(value) {
    return JSON.parse(canonicalize(value));
}
function unsignedRecord(record) {
    const { signature: _signature, ...body } = record;
    return body;
}
function signingBytes(record) {
    return Buffer.from(`${AEB_EVALUATION_DOMAIN}${canonicalize(unsignedRecord(record))}`, 'utf8');
}
function nativeAttestationBody(attestation) {
    const { signature: _signature, ...body } = attestation;
    return body;
}
function nativeAttestationSigningBytes(body) {
    return Buffer.from(`${AEB_NATIVE_VERIFICATION_ATTESTATION_DOMAIN}${canonicalize(body)}`, 'utf8');
}
/** Sign the exact result emitted by a native verifier or protocol gateway. */
export function signAebNativeVerificationAttestation(body, signer) {
    const detached = safeClone(body);
    const value = crypto.sign(null, nativeAttestationSigningBytes(detached), signer.private_key).toString('base64url');
    return { ...detached, signature: { alg: 'Ed25519', key_id: signer.key_id, value } };
}
const NATIVE_ATTESTATION_KEYS = new Set([
    '@version', 'protocol_id', 'audience', 'native_artifact_ref', 'native_artifact_digest',
    'evidence_role', 'subject', 'verified_at', 'expires_at', 'mapping', 'signature',
]);
const NATIVE_MAPPING_KEYS = new Set([
    'profile_digest', 'mapper_id', 'resolver_digest', 'caid', 'normalized_action_digest',
]);
const NATIVE_SUBJECT_KEYS = new Set(['id', 'kind']);
const NATIVE_SIGNATURE_KEYS = new Set(['alg', 'key_id', 'value']);
const NATIVE_ADAPTER_CONFIG_KEYS = new Set(['audience', 'accepted_protocols']);
function exactKeys(value, keys) {
    return Object.keys(value).length === keys.size && Object.keys(value).every((key) => keys.has(key));
}
function onlyKeys(value, keys) {
    return Object.keys(value).every((key) => keys.has(key));
}
function nativeAttestationShape(value) {
    if (!isObject(value) || !exactKeys(value, NATIVE_ATTESTATION_KEYS)
        || value['@version'] !== AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION
        || !exactString(value.protocol_id) || !exactString(value.audience)
        || !exactString(value.native_artifact_ref) || !validDigest(value.native_artifact_digest)
        || !validRole(value.evidence_role) || !isObject(value.subject)
        || !exactKeys(value.subject, NATIVE_SUBJECT_KEYS) || !exactString(value.subject.id)
        || !['human', 'workload', 'organization', 'system'].includes(String(value.subject.kind))
        || !Number.isFinite(parseInstant(value.verified_at)) || !Number.isFinite(parseInstant(value.expires_at))
        || parseInstant(value.verified_at) >= parseInstant(value.expires_at)
        || !isObject(value.mapping) || !exactKeys(value.mapping, NATIVE_MAPPING_KEYS)
        || !validDigest(value.mapping.profile_digest) || !exactString(value.mapping.mapper_id)
        || !validDigest(value.mapping.resolver_digest) || typeof value.mapping.caid !== 'string'
        || !CAID_RE.test(value.mapping.caid) || !validDigest(value.mapping.normalized_action_digest)
        || !isObject(value.signature) || !exactKeys(value.signature, NATIVE_SIGNATURE_KEYS)
        || value.signature.alg !== 'Ed25519' || !exactString(value.signature.key_id)
        || typeof value.signature.value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value.signature.value))
        return false;
    try {
        const bytes = Buffer.from(value.signature.value, 'base64url');
        return bytes.length === 64 && bytes.toString('base64url') === value.signature.value;
    }
    catch {
        return false;
    }
}
function nativeAttestationConfig(value) {
    if (!isObject(value) || !exactKeys(value, NATIVE_ADAPTER_CONFIG_KEYS)
        || !exactString(value.audience) || !Array.isArray(value.accepted_protocols)
        || value.accepted_protocols.length === 0
        || value.accepted_protocols.some((item) => !exactString(item))
        || new Set(value.accepted_protocols).size !== value.accepted_protocols.length)
        return null;
    return { audience: value.audience, accepted_protocols: value.accepted_protocols };
}
function verifyNativeAttestationSignature(attestation, trustRoots) {
    const root = trustRoots.find((candidate) => isObject(candidate)
        && candidate.key_id === attestation.signature.key_id && typeof candidate.public_key === 'string');
    if (!isObject(root) || typeof root.public_key !== 'string')
        return false;
    try {
        const bytes = Buffer.from(root.public_key, 'base64url');
        if (bytes.length === 0 || bytes.toString('base64url') !== root.public_key)
            return false;
        const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
        return key.asymmetricKeyType === 'ed25519'
            && crypto.verify(null, nativeAttestationSigningBytes(nativeAttestationBody(attestation)), key, Buffer.from(attestation.signature.value, 'base64url'));
    }
    catch {
        return false;
    }
}
/**
 * Concrete bridge for WIMSE, RATS, permit, receipt, and other native verifiers.
 * The bridge verifies a pinned verifier's signed result; presenter assertions
 * and unsigned gateway headers never become evidence.
 */
export function createAebNativeVerificationAttestationAdapter(options) {
    if (!exactString(options?.id) || !exactString(options?.version))
        throw new TypeError('valid adapter id and version required');
    return Object.freeze({
        id: options.id,
        version: options.version,
        verifyNative(input) {
            const evidenceDigest = digest(input.artifact);
            const inputStatusDigest = statusDigest(input.status);
            const fallback = {
                native_verification: 'FAILED', acceptance: 'REJECTED', evidence_digest: evidenceDigest,
                status_digest: inputStatusDigest, evidence_role: 'invalid-evidence',
                subject: { id: 'invalid-evidence', kind: 'system' }, reasons: [],
            };
            if (!nativeAttestationShape(input.artifact)) {
                fallback.reasons = ['native_attestation_malformed'];
                return fallback;
            }
            fallback.evidence_role = input.artifact.evidence_role;
            fallback.subject = safeClone(input.artifact.subject);
            const config = nativeAttestationConfig(input.adapter_config);
            if (!config || input.artifact.audience !== config.audience
                || !config.accepted_protocols.includes(input.artifact.protocol_id)) {
                fallback.reasons = ['native_attestation_scope_refused'];
                return fallback;
            }
            if (!verifyNativeAttestationSignature(input.artifact, input.trust_roots)) {
                fallback.reasons = ['native_attestation_signature_invalid'];
                return fallback;
            }
            const now = parseInstant(input.now);
            if (!Number.isFinite(now) || now < parseInstant(input.artifact.verified_at)
                || now > parseInstant(input.artifact.expires_at)) {
                fallback.acceptance = 'INDETERMINATE';
                fallback.reasons = ['native_attestation_outside_validity'];
                return fallback;
            }
            return { ...fallback, native_verification: 'VERIFIED', acceptance: 'ACCEPTED', reasons: [] };
        },
        mapAction(input) {
            if (input.native.native_verification !== 'VERIFIED' || !nativeAttestationShape(input.artifact)) {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_verification_required'] };
            }
            const mapping = input.artifact.mapping;
            const reasons = [];
            if (mapping.profile_digest !== input.profile.profile_digest)
                reasons.push('native_mapping_profile_mismatch');
            if (mapping.mapper_id !== input.profile.mapper_id)
                reasons.push('native_mapper_mismatch');
            if (mapping.resolver_digest !== input.profile.resolver.implementation_digest)
                reasons.push('native_resolver_mismatch');
            if (reasons.length)
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons };
            return { mapping: 'MATCH', caid: mapping.caid, action_digest: mapping.normalized_action_digest, reasons: [] };
        },
    });
}
function adapterConfigDigest(id, pin) {
    return digest({ adapter_id: id, version: pin.version, trust_roots: pin.trust_roots, config: pin.config ?? null, max_status_age_sec: pin.max_status_age_sec });
}
function profileDigest(id, pin) {
    return digest({
        profile_id: id,
        version: pin.version,
        definition: pin.definition ?? null,
        registry_entry_ref: pin.registry_entry_ref,
        mapper_id: pin.mapper_id,
        resolver: pin.resolver,
        semantic_equivalence: pin.semantic_equivalence,
    });
}
function registryEntryDigestInternal(id, entry) {
    return digest({
        entry_id: id,
        kind: entry.kind,
        version: entry.version,
        status: entry.status,
        definition: entry.definition,
    });
}
function registryDigestInternal(registry) {
    return digest({
        '@version': registry['@version'],
        registry_id: registry.registry_id,
        epoch: registry.epoch,
        entries: registry.entries,
    });
}
export function pinnedConfigDigest(config) {
    return digest(config);
}
export function adapterPinDigest(id, pin) {
    return adapterConfigDigest(id, pin);
}
export function mappingProfileDigest(id, pin) {
    return profileDigest(id, pin);
}
export function registryEntryDigest(id, entry) {
    return registryEntryDigestInternal(id, entry);
}
export function unifiedRegistryDigest(registry) {
    return registryDigestInternal(registry);
}
function statusDigest(status) {
    return digest({
        checked_at: status.checked_at,
        expires_at: status.expires_at,
        revocation_checked: status.revocation_checked,
        revoked: status.revoked,
        consumed: status.consumed,
        unavailable: status.unavailable === true,
    });
}
function emptyFreshness(status, now, maxAgeSec) {
    const nowMs = parseInstant(now);
    const checkedMs = parseInstant(status.checked_at);
    const expiresMs = parseInstant(status.expires_at);
    const ageSeconds = Number.isFinite(nowMs) && Number.isFinite(checkedMs) ? Math.floor((nowMs - checkedMs) / 1000) : null;
    const fresh = status.unavailable !== true
        && status.revocation_checked === true
        && status.revoked === false
        && status.consumed === false
        && Number.isFinite(nowMs) && Number.isFinite(checkedMs) && Number.isFinite(expiresMs)
        && checkedMs <= nowMs && nowMs < expiresMs
        && ageSeconds !== null && ageSeconds >= 0 && ageSeconds <= maxAgeSec;
    return {
        checked_at: status.checked_at,
        expires_at: status.expires_at,
        revocation_checked: status.revocation_checked === true,
        revoked: status.revoked === true,
        consumed: status.consumed === true,
        unavailable: status.unavailable === true,
        age_seconds: ageSeconds,
        fresh,
    };
}
function freshnessReasons(freshness, status, maxAgeSec, now) {
    const reasons = [];
    const nowMs = parseInstant(now);
    const checkedMs = parseInstant(status.checked_at);
    const expiresMs = parseInstant(status.expires_at);
    if (status.unavailable === true)
        reasons.push('status_unavailable');
    if (status.revoked === true)
        reasons.push('evidence_revoked');
    if (status.consumed === true)
        reasons.push('evidence_consumed');
    if (status.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs))
        reasons.push('invalid_status_time');
    else {
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (nowMs >= expiresMs)
            reasons.push('evidence_expired');
        if (freshness.age_seconds !== null && freshness.age_seconds > maxAgeSec)
            reasons.push('status_stale');
    }
    return reasons;
}
function validRole(value) {
    return typeof value === 'string' && ROLE_RE.test(value);
}
function validTextList(value) {
    return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 512)
        && new Set(value).size === value.length;
}
function activeRegistryEntry(config, id, kind) {
    const entry = config?.registry?.entries?.[id];
    return entry && entry.kind === kind && entry.status === 'active' ? entry : null;
}
function roleRegistryEntry(config, role) {
    const entry = activeRegistryEntry(config, `role:${role}`, 'evidence-role');
    if (!entry || !isObject(entry.definition) || entry.definition.role !== role
        || !Array.isArray(entry.definition.subject_kinds)
        || entry.definition.subject_kinds.length === 0
        || new Set(entry.definition.subject_kinds).size !== entry.definition.subject_kinds.length
        || !entry.definition.subject_kinds.every((kind) => ['human', 'workload', 'organization', 'system'].includes(String(kind))))
        return null;
    return entry;
}
const CONFIG_KEYS = new Set(['@version', 'relying_party_id', 'evaluator_keys', 'registry', 'accepted_mappers', 'adapters', 'profiles', 'requirements']);
const REGISTRY_KEYS = new Set(['@version', 'registry_id', 'epoch', 'entries', 'registry_digest']);
const REGISTRY_ENTRY_KEYS = new Set(['kind', 'version', 'status', 'definition', 'definition_digest']);
const ADAPTER_PIN_KEYS = new Set(['version', 'trust_roots', 'config', 'config_digest', 'max_status_age_sec']);
const PROFILE_KEYS = new Set(['version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver', 'semantic_equivalence', 'profile_digest']);
const RESOLVER_KEYS = new Set(['id', 'version', 'implementation_digest']);
const EQUIVALENCE_KEYS = new Set(['assertion', 'loss_policy', 'omitted_material_fields', 'omitted_nonmaterial_fields']);
const REQUIREMENT_KEYS = new Set(['@version', 'all_of', 'any_of', 'terms']);
const QUORUM_TERM_KEYS = new Set(['type', 'role', 'threshold']);
const EXCLUSION_TERM_KEYS = new Set(['type', 'roles']);
const ONE_TIME_TERM_KEYS = new Set(['type']);
const EVALUATOR_KEY_KEYS = new Set(['public_key']);
function validConfig(config) {
    const reasons = [];
    if (!isObject(config) || !exactKeys(config, CONFIG_KEYS) || config['@version'] !== AEB_ADAPTER_VERSION)
        reasons.push('invalid_config_version');
    if (!exactString(config?.relying_party_id))
        reasons.push('invalid_relying_party_id');
    if (!isObject(config?.adapters) || !isObject(config?.profiles) || !isObject(config?.requirements)
        || !isObject(config?.evaluator_keys) || !isObject(config?.registry))
        reasons.push('invalid_config_maps');
    const registry = config?.registry;
    if (!isObject(registry) || !exactKeys(registry, REGISTRY_KEYS)
        || registry['@version'] !== AEB_REGISTRY_VERSION || !exactString(registry.registry_id)
        || !Number.isSafeInteger(registry.epoch) || registry.epoch < 1 || !isObject(registry.entries)
        || !validDigest(registry.registry_digest)) {
        reasons.push('invalid_registry');
    }
    else {
        let expectedRegistryDigest = null;
        try {
            expectedRegistryDigest = registryDigestInternal(registry);
        }
        catch {
            expectedRegistryDigest = null;
        }
        if (expectedRegistryDigest !== registry.registry_digest)
            reasons.push('registry_digest_mismatch');
        for (const [id, rawEntry] of Object.entries(registry.entries)) {
            const entry = rawEntry;
            let expectedEntryDigest = null;
            try {
                expectedEntryDigest = isObject(rawEntry) ? registryEntryDigestInternal(id, entry) : null;
            }
            catch {
                expectedEntryDigest = null;
            }
            if (!exactString(id) || !isObject(rawEntry) || !exactKeys(rawEntry, REGISTRY_ENTRY_KEYS)
                || !['mapping-profile', 'evidence-role', 'receipt-extension'].includes(String(entry.kind))
                || !exactString(entry.version) || !['active', 'deprecated'].includes(String(entry.status))
                || !validDigest(entry.definition_digest) || expectedEntryDigest !== entry.definition_digest) {
                reasons.push(`invalid_registry_entry:${id}`);
            }
        }
    }
    if (!Array.isArray(config?.accepted_mappers) || config.accepted_mappers.length === 0
        || !config.accepted_mappers.every(exactString)
        || new Set(config.accepted_mappers).size !== config.accepted_mappers.length)
        reasons.push('invalid_accepted_mappers');
    for (const [id, pin] of Object.entries(config?.adapters ?? {})) {
        let pinDigest = null;
        try {
            pinDigest = isObject(pin) ? adapterConfigDigest(id, pin) : null;
        }
        catch {
            pinDigest = null;
        }
        if (!exactString(id) || !isObject(pin) || !onlyKeys(pin, ADAPTER_PIN_KEYS)
            || !exactString(pin.version) || !Array.isArray(pin.trust_roots)
            || !Number.isInteger(pin.max_status_age_sec) || pin.max_status_age_sec < 0
            || !validDigest(pin.config_digest) || pinDigest !== pin.config_digest)
            reasons.push(`invalid_adapter_pin:${id}`);
    }
    for (const [id, rawPin] of Object.entries(config?.profiles ?? {})) {
        const pin = rawPin;
        let pinDigest = null;
        try {
            pinDigest = isObject(rawPin) ? profileDigest(id, pin) : null;
        }
        catch {
            pinDigest = null;
        }
        if (!exactString(id) || !isObject(rawPin) || !onlyKeys(rawPin, PROFILE_KEYS)
            || !exactString(pin.version) || !validDigest(pin.profile_digest)
            || pinDigest !== pin.profile_digest || !exactString(pin.registry_entry_ref) || !exactString(pin.mapper_id)
            || !isObject(pin.resolver) || !exactKeys(pin.resolver, RESOLVER_KEYS)
            || !exactString(pin.resolver.id) || !exactString(pin.resolver.version)
            || !validDigest(pin.resolver.implementation_digest) || !isObject(pin.semantic_equivalence)
            || !exactKeys(pin.semantic_equivalence, EQUIVALENCE_KEYS)
            || pin.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
            || pin.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
            || !validTextList(pin.semantic_equivalence.omitted_material_fields)
            || !validTextList(pin.semantic_equivalence.omitted_nonmaterial_fields))
            reasons.push(`invalid_profile_pin:${id}`);
        if (!config.accepted_mappers?.includes(pin.mapper_id))
            reasons.push(`mapper_not_accepted:${id}`);
        if (Array.isArray(pin.semantic_equivalence?.omitted_material_fields)
            && pin.semantic_equivalence.omitted_material_fields.length > 0)
            reasons.push(`material_information_loss:${id}`);
        const profileEntry = activeRegistryEntry(config, pin.registry_entry_ref, 'mapping-profile');
        if (!profileEntry || !isObject(profileEntry.definition) || profileEntry.definition.profile_digest !== pin.profile_digest) {
            reasons.push(`mapping_profile_not_registered:${id}`);
        }
    }
    for (const [id, rawRequirement] of Object.entries(config?.requirements ?? {})) {
        const requirement = rawRequirement;
        const allOfValid = Array.isArray(requirement.all_of) && requirement.all_of.every(validRole)
            && new Set(requirement.all_of).size === requirement.all_of.length;
        const anyOfValid = requirement.any_of === undefined || (Array.isArray(requirement.any_of)
            && requirement.any_of.every((group) => Array.isArray(group) && group.length > 0 && group.every(validRole)
                && new Set(group).size === group.length));
        const rawTerms = Array.isArray(requirement.terms) ? requirement.terms : [];
        const quorumRules = rawTerms.filter((term) => isObject(term) && term.type === 'distinct-human-quorum');
        const exclusionRules = rawTerms.filter((term) => isObject(term) && term.type === 'initiator-exclusion');
        const oneTimeRules = rawTerms.filter((term) => isObject(term) && term.type === 'one-time-consumption');
        const termsValid = Array.isArray(requirement.terms) && requirement.terms.length > 0
            && requirement.terms.every((term) => {
                if (!isObject(term) || !exactString(term.type))
                    return false;
                if (term.type === 'distinct-human-quorum') {
                    return exactKeys(term, QUORUM_TERM_KEYS) && validRole(term.role)
                        && typeof term.threshold === 'number' && Number.isSafeInteger(term.threshold) && term.threshold >= 2;
                }
                if (term.type === 'initiator-exclusion') {
                    return exactKeys(term, EXCLUSION_TERM_KEYS) && Array.isArray(term.roles) && term.roles.length > 0
                        && term.roles.every(validRole) && new Set(term.roles).size === term.roles.length;
                }
                return term.type === 'one-time-consumption' && exactKeys(term, ONE_TIME_TERM_KEYS);
            })
            && new Set(quorumRules.map((term) => term.role)).size === quorumRules.length
            && exclusionRules.length <= 1
            && oneTimeRules.length === 1;
        const hasRequirement = (allOfValid && requirement.all_of.length > 0)
            || (Array.isArray(requirement.any_of) && requirement.any_of.length > 0)
            || quorumRules.length > 0;
        if (!exactString(id) || !isObject(rawRequirement) || !onlyKeys(rawRequirement, REQUIREMENT_KEYS)
            || requirement['@version'] !== AEB_REQUIREMENT_VERSION
            || !allOfValid || !anyOfValid || !termsValid || !hasRequirement)
            reasons.push(`invalid_requirement:${id}`);
        const roles = new Set([
            ...(Array.isArray(requirement.all_of) ? requirement.all_of : []),
            ...(Array.isArray(requirement.any_of) ? requirement.any_of.flat() : []),
            ...quorumRules.map((rule) => String(rule.role)),
            ...exclusionRules.flatMap((rule) => Array.isArray(rule.roles) ? rule.roles.map(String) : []),
        ]);
        for (const role of roles)
            if (!roleRegistryEntry(config, role))
                reasons.push(`role_not_registered:${role}`);
    }
    for (const [id, key] of Object.entries(config?.evaluator_keys ?? {})) {
        if (!exactString(id) || !isObject(key) || !exactKeys(key, EVALUATOR_KEY_KEYS)
            || typeof key.public_key !== 'string' || key.public_key.length === 0)
            reasons.push(`invalid_evaluator_key:${id}`);
    }
    return sortedUnique(reasons);
}
function distinctHumanQuorumTerms(requirement) {
    return requirement.terms.filter((term) => term.type === 'distinct-human-quorum');
}
function initiatorExclusionTerm(requirement) {
    return requirement.terms.find((term) => term.type === 'initiator-exclusion');
}
function requiresOneTimeConsumption(requirement) {
    return requirement.terms.some((term) => term.type === 'one-time-consumption');
}
function requiredRoles(requirement) {
    return new Set([
        ...requirement.all_of,
        ...(requirement.any_of ?? []).flat(),
        ...distinctHumanQuorumTerms(requirement).map((rule) => rule.role),
    ]);
}
function aecRequirementExpression(requirement) {
    const terms = [
        ...sortedUnique(requirement.all_of),
        ...(requirement.any_of ?? []).map((group) => `(${sortedUnique(group).join(' OR ')})`),
        ...sortedUnique(distinctHumanQuorumTerms(requirement).map((rule) => rule.role)),
    ];
    return sortedUnique(terms).join(' AND ');
}
function composeWithAec(requirement, legs, caid) {
    const expression = aecRequirementExpression(requirement);
    const roles = requiredRoles(requirement);
    const relevant = legs.filter((leg) => roles.has(leg.evidence_role));
    const normalizedDigests = new Set(relevant.filter((leg) => leg.verdict === 'SATISFIED' && leg.action_digest !== null)
        .map((leg) => leg.action_digest));
    const normalizedActionDigest = normalizedDigests.size === 1 ? [...normalizedDigests][0] : null;
    const action = { caid, normalized_action_digest: normalizedActionDigest };
    const rawActionDigest = aecActionDigest(action);
    const actionDigest = (rawActionDigest.startsWith('sha256:') ? rawActionDigest : `sha256:${rawActionDigest}`);
    if (normalizedDigests.size > 1) {
        return {
            engine: AEC_VERSION,
            requirement_expression: expression,
            action_digest: actionDigest,
            satisfied: false,
            indeterminate: false,
            reasons: ['normalized_action_digest_mismatch'],
        };
    }
    if (relevant.some((leg) => leg.verdict === 'SATISFIED' && leg.action_digest === null)) {
        return {
            engine: AEC_VERSION,
            requirement_expression: expression,
            action_digest: actionDigest,
            satisfied: false,
            indeterminate: true,
            reasons: ['normalized_action_digest_missing'],
        };
    }
    const verifiers = {};
    for (const role of roles) {
        verifiers[role] = (evidence) => {
            const index = isObject(evidence) && Number.isSafeInteger(evidence.leg_index) ? Number(evidence.leg_index) : -1;
            const leg = relevant[index];
            return { valid: Boolean(leg && leg.evidence_role === role && leg.verdict === 'SATISFIED'), action_digest: leg ? actionDigest : null };
        };
    }
    const result = verifyAuthorizationChain({
        '@version': AEC_VERSION,
        action,
        action_digest: actionDigest,
        components: relevant.map((leg, index) => ({ type: leg.evidence_role, evidence: { leg_index: index } })),
        requirement: expression,
    }, {
        verifiers,
        requirement: expression,
        expectedAction: action,
    });
    return {
        engine: AEC_VERSION,
        requirement_expression: expression,
        action_digest: actionDigest,
        satisfied: result.satisfied === true,
        indeterminate: result.satisfied !== true && relevant.some((leg) => leg.verdict === 'INDETERMINATE'),
        reasons: Array.isArray(result.reasons) ? result.reasons.map(String) : ['aec_composition_failed'],
    };
}
function evaluateAuthorityConstraints(requirement, legs, initiatorId) {
    const reasons = [];
    let indeterminate = false;
    let quorumSatisfied = true;
    for (const rule of distinctHumanQuorumTerms(requirement)) {
        const candidates = legs.filter((leg) => leg.evidence_role === rule.role);
        const satisfiedHumans = candidates.filter((leg) => leg.verdict === 'SATISFIED' && leg.subject?.kind === 'human');
        const distinct = new Set(satisfiedHumans.map((leg) => leg.subject.id));
        if (distinct.size < rule.threshold) {
            quorumSatisfied = false;
            reasons.push(`quorum_not_met:${rule.role}`);
            if (candidates.some((leg) => leg.verdict === 'INDETERMINATE'))
                indeterminate = true;
        }
    }
    const excludedRoles = new Set(initiatorExclusionTerm(requirement)?.roles ?? []);
    const selfApprovedRoles = new Set(legs
        .filter((leg) => leg.verdict === 'SATISFIED'
        && excludedRoles.has(leg.evidence_role) && leg.subject?.id === initiatorId)
        .map((leg) => leg.evidence_role));
    const selfApproval = selfApprovedRoles.size > 0;
    if (selfApproval)
        reasons.push(...[...selfApprovedRoles].map((role) => `initiator_excluded:${role}`));
    const oneTime = requiresOneTimeConsumption(requirement);
    if (!oneTime)
        reasons.push('one_time_consumption_not_required');
    const verdict = indeterminate ? 'INDETERMINATE'
        : quorumSatisfied && !selfApproval && oneTime ? 'SATISFIED' : 'UNSATISFIED';
    return {
        verdict,
        distinct_human_quorum: quorumSatisfied,
        initiator_exclusion: !selfApproval,
        one_time_consumption: oneTime,
        reasons: sortedUnique(reasons),
    };
}
function deriveEvaluation(options) {
    const reasons = [];
    let configReasons = [];
    try {
        configReasons = validConfig(options.config);
        reasons.push(...configReasons);
    }
    catch {
        configReasons = ['invalid_config'];
        reasons.push('invalid_config');
    }
    if (!exactString(options.operation_id) || !exactString(options.consumption_nonce))
        reasons.push('invalid_operation_binding');
    if (!exactString(options.initiator_id))
        reasons.push('invalid_initiator_binding');
    if (!exactString(options.requirement_ref) || !exactString(options.caid) || !CAID_RE.test(options.caid))
        reasons.push('invalid_action_binding');
    if (!Number.isFinite(parseInstant(options.evaluated_at)))
        reasons.push('invalid_evaluated_at');
    const requirement = options.config?.requirements?.[options.requirement_ref];
    if (!requirement)
        reasons.push('requirement_not_pinned');
    let requirementDigest = 'sha256:' + '0'.repeat(64);
    try {
        requirementDigest = digest(requirement);
    }
    catch {
        reasons.push('requirement_not_canonicalizable');
    }
    const legs = [];
    for (const input of options.legs ?? []) {
        const adapterPin = options.config?.adapters?.[input.adapter_id];
        const profile = options.config?.profiles?.[input.profile_id];
        const adapter = options.adapters?.[input.adapter_id];
        const base = {
            adapter_id: input.adapter_id,
            adapter_version: adapterPin?.version ?? '',
            profile_id: input.profile_id,
            profile_version: profile?.version ?? '',
            profile_digest: profile?.profile_digest ?? ('sha256:' + '0'.repeat(64)),
            artifact_ref: input.artifact_ref,
            evidence_digest: ('sha256:' + '0'.repeat(64)),
            status_digest: ('sha256:' + '0'.repeat(64)),
            evidence_role: '',
            subject: null,
            mapper_id: profile?.mapper_id ?? '',
            resolver_digest: profile?.resolver?.implementation_digest ?? ('sha256:' + '0'.repeat(64)),
            native_verification: 'FAILED',
            acceptance: 'INDETERMINATE',
            mapping: 'INDETERMINATE',
            action_digest: null,
            caid: null,
            freshness: emptyFreshness(input.status, options.evaluated_at, adapterPin?.max_status_age_sec ?? 0),
            verdict: 'INDETERMINATE',
            reasons: [],
        };
        if (!adapterPin || !profile || !adapter) {
            base.reasons = ['adapter_or_profile_not_pinned'];
            legs.push(base);
            continue;
        }
        if (adapter.id !== input.adapter_id || adapter.version !== adapterPin.version) {
            base.reasons = ['adapter_version_not_registered'];
            legs.push(base);
            continue;
        }
        if (profile.profile_digest !== profileDigest(input.profile_id, profile)) {
            base.reasons = ['mapping_profile_digest_mismatch'];
            legs.push(base);
            continue;
        }
        try {
            // Adapters receive only a detached copy of relying-party-pinned data.
            // A presenter cannot supply it and adapter code cannot mutate the config
            // object used to re-derive the evaluation.
            const artifact = deepFreeze(safeClone(input.artifact));
            const status = deepFreeze(safeClone(input.status));
            const trustRoots = deepFreeze(safeClone(adapterPin.trust_roots));
            const profileInput = deepFreeze(safeClone(profile));
            const adapterConfig = deepFreeze(JSON.parse(canonicalize(adapterPin.config ?? null)));
            base.evidence_digest = digest(artifact);
            base.status_digest = statusDigest(status);
            const native = adapter.verifyNative({
                artifact,
                artifact_ref: input.artifact_ref,
                status,
                trust_roots: trustRoots,
                adapter_config: adapterConfig,
                now: options.evaluated_at,
            });
            if (!isObject(native) || !validDigest(native.evidence_digest) || native.evidence_digest !== base.evidence_digest
                || !validDigest(native.status_digest) || native.status_digest !== base.status_digest
                || (native.native_verification !== 'VERIFIED' && native.native_verification !== 'FAILED')
                || !['ACCEPTED', 'REJECTED', 'INDETERMINATE'].includes(native.acceptance)
                || !validRole(native.evidence_role) || !isObject(native.subject) || !exactString(native.subject.id)
                || !['human', 'workload', 'organization', 'system'].includes(String(native.subject.kind))
                || !Array.isArray(native.reasons)) {
                base.reasons = ['malformed_native_result'];
                legs.push(base);
                continue;
            }
            base.native_verification = native.native_verification;
            base.acceptance = native.acceptance;
            base.evidence_role = native.evidence_role;
            base.subject = { id: native.subject.id, kind: native.subject.kind };
            base.reasons.push(...native.reasons);
            const roleEntry = roleRegistryEntry(options.config, native.evidence_role);
            const allowedSubjectKinds = roleEntry && isObject(roleEntry.definition) && Array.isArray(roleEntry.definition.subject_kinds)
                ? roleEntry.definition.subject_kinds.map(String) : [];
            const roleAccepted = Boolean(roleEntry && allowedSubjectKinds.includes(native.subject.kind));
            if (!roleAccepted)
                base.reasons.push('evidence_role_not_registered_or_subject_kind_refused');
            const freshnessIssues = freshnessReasons(base.freshness, status, adapterPin.max_status_age_sec, options.evaluated_at);
            base.reasons.push(...freshnessIssues);
            const mapping = adapter.mapAction({
                artifact,
                artifact_ref: input.artifact_ref,
                status,
                trust_roots: trustRoots,
                adapter_config: adapterConfig,
                profile: profileInput,
                now: options.evaluated_at,
                native,
            });
            if (!isObject(mapping) || !['MATCH', 'MISMATCH', 'INDETERMINATE'].includes(mapping.mapping)
                || (mapping.caid !== null && typeof mapping.caid !== 'string')
                || (mapping.action_digest !== null && !validDigest(mapping.action_digest))
                || !Array.isArray(mapping.reasons)) {
                base.reasons.push('malformed_mapping_result');
            }
            else {
                base.mapping = mapping.mapping;
                base.caid = mapping.caid;
                base.action_digest = mapping.action_digest;
                base.reasons.push(...mapping.reasons);
                if (mapping.mapping === 'MATCH' && mapping.action_digest === null)
                    base.reasons.push('normalized_action_digest_missing');
            }
            const hardFailure = base.native_verification === 'FAILED' || base.acceptance === 'REJECTED'
                || base.mapping === 'MISMATCH' || base.freshness.revoked || base.freshness.consumed
                || !roleAccepted
                || (Number.isFinite(parseInstant(options.evaluated_at)) && Number.isFinite(parseInstant(base.freshness.expires_at))
                    && parseInstant(options.evaluated_at) >= parseInstant(base.freshness.expires_at));
            const unknown = base.acceptance === 'INDETERMINATE' || base.mapping === 'INDETERMINATE'
                || (base.mapping === 'MATCH' && base.action_digest === null)
                || !base.freshness.fresh || freshnessIssues.some((reason) => !['evidence_revoked', 'evidence_consumed', 'evidence_expired'].includes(reason));
            if (hardFailure)
                base.verdict = 'UNSATISFIED';
            else if (unknown || base.native_verification !== 'VERIFIED' || base.mapping !== 'MATCH' || base.caid !== options.caid)
                base.verdict = 'INDETERMINATE';
            else
                base.verdict = 'SATISFIED';
            if (base.caid !== null && base.caid !== options.caid && base.mapping === 'MATCH') {
                base.verdict = 'UNSATISFIED';
                base.reasons.push('caid_mismatch');
            }
        }
        catch {
            base.reasons.push('adapter_evaluation_error');
        }
        base.reasons = sortedUnique(base.reasons);
        legs.push(base);
    }
    const zero = ('sha256:' + '0'.repeat(64));
    let composition = {
        engine: AEC_VERSION,
        requirement_expression: requirement ? aecRequirementExpression(requirement) : '',
        action_digest: zero,
        satisfied: false,
    };
    let authorityConstraints = {
        distinct_human_quorum: false,
        initiator_exclusion: false,
        one_time_consumption: false,
    };
    let aggregate = {
        verdict: 'INDETERMINATE', reasons: ['cannot_evaluate_unpinned_requirement'],
    };
    if (requirement && configReasons.length === 0) {
        const composed = composeWithAec(requirement, legs, options.caid);
        const constrained = evaluateAuthorityConstraints(requirement, legs, options.initiator_id);
        composition = {
            engine: composed.engine,
            requirement_expression: composed.requirement_expression,
            action_digest: composed.action_digest,
            satisfied: composed.satisfied,
        };
        authorityConstraints = {
            distinct_human_quorum: constrained.distinct_human_quorum,
            initiator_exclusion: constrained.initiator_exclusion,
            one_time_consumption: constrained.one_time_consumption,
        };
        const verdict = composed.satisfied && constrained.verdict === 'SATISFIED' ? 'SATISFIED'
            : composed.indeterminate || constrained.verdict === 'INDETERMINATE' ? 'INDETERMINATE' : 'UNSATISFIED';
        aggregate = {
            verdict,
            reasons: sortedUnique([
                ...(!composed.satisfied && !composed.indeterminate ? composed.reasons : []),
                ...constrained.reasons,
            ]),
        };
    }
    let configDigest = ('sha256:' + '0'.repeat(64));
    try {
        configDigest = pinnedConfigDigest(options.config);
    }
    catch {
        reasons.push('config_not_canonicalizable');
    }
    let evidenceDigest = ('sha256:' + '0'.repeat(64));
    try {
        evidenceDigest = digest(legs);
    }
    catch {
        reasons.push('evaluation_not_canonicalizable');
    }
    const body = {
        '@type': AEB_EVALUATION_VERSION,
        operation_id: options.operation_id,
        consumption_nonce: options.consumption_nonce,
        initiator_id: options.initiator_id,
        evaluator: { id: options.config?.relying_party_id ?? '', key_id: options.signer?.key_id ?? options.evaluator_key_id ?? '', pinned_config_digest: configDigest },
        requirement_ref: options.requirement_ref,
        requirement_digest: requirementDigest,
        registry_digest: validDigest(options.config?.registry?.registry_digest) ? options.config.registry.registry_digest : zero,
        caid: options.caid,
        legs,
        composition,
        authority_constraints: authorityConstraints,
        verdict: aggregate.verdict,
        evaluated_at: options.evaluated_at,
        evidence_digest: evidenceDigest,
        reasons: sortedUnique([...reasons, ...aggregate.reasons, ...legs.flatMap((leg) => leg.reasons)]),
    };
    return { body, reasons: body.reasons };
}
export function evaluateAebEvidence(options) {
    try {
        const { body } = deriveEvaluation(options);
        const record = safeClone(body);
        if (options.signer) {
            if (!options.config.evaluator_keys?.[options.signer.key_id]) {
                record.reasons = sortedUnique([...record.reasons, 'evaluator_key_not_pinned']);
            }
            else {
                const signature = crypto.sign(null, signingBytes(body), options.signer.private_key).toString('base64url');
                record.signature = { alg: 'Ed25519', key_id: options.signer.key_id, value: signature };
            }
        }
        else {
            record.reasons = sortedUnique([...record.reasons, 'evaluation_signature_required']);
        }
        return { record, valid: record.verdict === 'SATISFIED' && Boolean(record.signature) && record.reasons.length === 0, reasons: record.reasons };
    }
    catch {
        const zero = ('sha256:' + '0'.repeat(64));
        const record = {
            '@type': AEB_EVALUATION_VERSION,
            operation_id: typeof options?.operation_id === 'string' ? options.operation_id : '',
            consumption_nonce: typeof options?.consumption_nonce === 'string' ? options.consumption_nonce : '',
            initiator_id: typeof options?.initiator_id === 'string' ? options.initiator_id : '',
            evaluator: { id: '', key_id: '', pinned_config_digest: zero },
            requirement_ref: typeof options?.requirement_ref === 'string' ? options.requirement_ref : '',
            requirement_digest: zero,
            registry_digest: zero,
            caid: typeof options?.caid === 'string' ? options.caid : '',
            legs: [],
            composition: { engine: AEC_VERSION, requirement_expression: '', action_digest: zero, satisfied: false },
            authority_constraints: { distinct_human_quorum: false, initiator_exclusion: false, one_time_consumption: false },
            verdict: 'INDETERMINATE', evaluated_at: typeof options?.evaluated_at === 'string' ? options.evaluated_at : '',
            evidence_digest: zero, reasons: ['evaluation_error'],
        };
        return { record, valid: false, reasons: record.reasons };
    }
}
function shapeValid(record) {
    if (!isObject(record) || record['@type'] !== AEB_EVALUATION_VERSION || !exactString(record.operation_id)
        || !exactString(record.consumption_nonce) || !exactString(record.initiator_id) || !isObject(record.evaluator)
        || !exactString(record.evaluator.id) || !exactString(record.evaluator.key_id) || !validDigest(record.evaluator.pinned_config_digest)
        || !exactString(record.requirement_ref) || !validDigest(record.requirement_digest) || !validDigest(record.registry_digest) || !exactString(record.caid)
        || typeof record.caid !== 'string' || !CAID_RE.test(record.caid) || !Array.isArray(record.legs) || typeof record.verdict !== 'string' || !['SATISFIED', 'UNSATISFIED', 'INDETERMINATE'].includes(record.verdict)
        || !isObject(record.composition) || record.composition.engine !== AEC_VERSION || typeof record.composition.requirement_expression !== 'string'
        || !validDigest(record.composition.action_digest) || typeof record.composition.satisfied !== 'boolean'
        || !isObject(record.authority_constraints) || typeof record.authority_constraints.distinct_human_quorum !== 'boolean'
        || typeof record.authority_constraints.initiator_exclusion !== 'boolean' || typeof record.authority_constraints.one_time_consumption !== 'boolean'
        || !Number.isFinite(parseInstant(record.evaluated_at)) || !validDigest(record.evidence_digest) || !Array.isArray(record.reasons)
        || !isObject(record.signature) || record.signature.alg !== 'Ed25519' || record.signature.key_id !== record.evaluator.key_id
        || typeof record.signature.value !== 'string' || record.signature.value.length === 0)
        return false;
    return true;
}
function verifyAebEvaluationInner(record, options) {
    const checks = { schema: shapeValid(record), signature: false, pinned_config: false, rederived: false, verdict: false };
    const reasons = [];
    if (!checks.schema)
        return { valid: false, checks, reasons: ['malformed_evaluation_record'] };
    const typed = record;
    if (options.now !== undefined) {
        const nowMs = parseInstant(options.now);
        const evaluatedMs = parseInstant(typed.evaluated_at);
        if (!Number.isFinite(nowMs) || !Number.isFinite(evaluatedMs) || evaluatedMs > nowMs) {
            reasons.push('evaluation_time_in_future');
        }
    }
    const configErrors = validConfig(options.config);
    checks.pinned_config = configErrors.length === 0
        && typed.evaluator.pinned_config_digest === pinnedConfigDigest(options.config)
        && typed.registry_digest === options.config.registry.registry_digest;
    if (!checks.pinned_config)
        reasons.push('pinned_config_mismatch');
    const key = options.config.evaluator_keys?.[typed.signature.key_id]?.public_key;
    if (typeof key === 'string') {
        try {
            const keyObject = crypto.createPublicKey({ key: Buffer.from(key, 'base64url'), type: 'spki', format: 'der' });
            checks.signature = crypto.verify(null, signingBytes(typed), keyObject, Buffer.from(typed.signature.value, 'base64url'));
        }
        catch {
            checks.signature = false;
        }
    }
    if (!checks.signature)
        reasons.push('evaluation_signature_invalid');
    const legs = [];
    for (const leg of typed.legs) {
        const artifact = options.artifacts?.[leg.artifact_ref];
        if (artifact === undefined) {
            reasons.push(`artifact_missing:${leg.artifact_ref}`);
            continue;
        }
        const pin = options.config.adapters?.[leg.adapter_id];
        const profile = options.config.profiles?.[leg.profile_id];
        const status = {
            checked_at: leg.freshness.checked_at,
            expires_at: leg.freshness.expires_at,
            revocation_checked: leg.freshness.revocation_checked,
            revoked: leg.freshness.revoked,
            consumed: leg.freshness.consumed,
            ...(leg.freshness.unavailable ? { unavailable: true } : {}),
        };
        if (!pin || !profile || !validDigest(leg.profile_digest) || leg.profile_digest !== profile.profile_digest) {
            reasons.push(`leg_pin_mismatch:${leg.artifact_ref}`);
            continue;
        }
        legs.push({ adapter_id: leg.adapter_id, profile_id: leg.profile_id, artifact_ref: leg.artifact_ref, artifact, status });
    }
    const derived = deriveEvaluation({
        config: options.config,
        adapters: options.adapters,
        operation_id: typed.operation_id,
        consumption_nonce: typed.consumption_nonce,
        initiator_id: typed.initiator_id,
        requirement_ref: typed.requirement_ref,
        caid: typed.caid,
        legs,
        evaluated_at: typed.evaluated_at,
        evaluator_key_id: typed.evaluator.key_id,
    });
    const derivedRecord = derived.body;
    checks.rederived = reasons.every((reason) => !reason.startsWith('artifact_missing:') && !reason.startsWith('leg_pin_mismatch:'))
        && canonicalize(unsignedRecord(typed)) === canonicalize(derivedRecord);
    checks.verdict = typed.verdict === derivedRecord.verdict;
    if (!checks.rederived)
        reasons.push('evaluation_not_rederivable');
    if (!checks.verdict)
        reasons.push('verdict_mismatch');
    return { valid: Object.values(checks).every(Boolean) && !reasons.includes('evaluation_time_in_future'), checks, reasons: sortedUnique(reasons) };
}
export function verifyAebEvaluation(record, options) {
    try {
        return verifyAebEvaluationInner(record, options);
    }
    catch {
        return {
            valid: false,
            checks: { schema: false, signature: false, pinned_config: false, rederived: false, verdict: false },
            reasons: ['evaluation_verification_error'],
        };
    }
}
export function authorizeAebExecution(record, options) {
    const reservationKey = aebReservationKey(record);
    if (!options.verified)
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evaluation_not_verified' };
    if (record.verdict === 'INDETERMINATE')
        return { allowed: false, invoke_allowed: false, state: 'RECONCILIATION_REQUIRED', reason: 'evidence_indeterminate' };
    if (record.verdict !== 'SATISFIED')
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evidence_requirement_not_satisfied' };
    if (record.authority_constraints?.one_time_consumption !== true)
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'one_time_consumption_not_required' };
    if (!options.local_authorization)
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'local_authorization_denied' };
    if (!options.store.reserve(reservationKey))
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'consumption_conflict' };
    return { allowed: true, invoke_allowed: true, state: 'AUTHORIZED', reason: 'reserved_for_execution', reservation_key: reservationKey };
}
/** Collision-resistant, tenant-scoped key used by both reference and durable stores. */
export function aebReservationKey(record) {
    return `aeb:${digest({
        relying_party_id: record.evaluator.id,
        config_digest: record.evaluator.pinned_config_digest,
        caid: record.caid,
        normalized_action_digest: record.composition.action_digest,
        operation_id: record.operation_id,
        consumption_nonce: record.consumption_nonce,
    })}`;
}
export function reconcileAebExecution(store, reservationKey, outcome) {
    if (outcome === 'COMMITTED') {
        return store.commit(reservationKey)
            ? { state: 'CONSUMED', retry_allowed: false, reason: 'execution_committed' }
            : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
    }
    if (outcome === 'NOT_COMMITTED') {
        return store.release(reservationKey)
            ? { state: 'AVAILABLE', retry_allowed: true, reason: 'execution_not_committed' }
            : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
    }
    return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'execution_outcome_indeterminate' };
}
function secureDurableStore(store) {
    return isObject(store) && store.durable === true && store.ownershipFenced === true
        && store.permanentConsumption === true && typeof store.reserve === 'function'
        && typeof store.commit === 'function' && typeof store.release === 'function';
}
/** Production authorization path for shared Postgres/Redis/DynamoDB-backed custody. */
export async function authorizeAebExecutionDurable(record, options) {
    const reservationKey = aebReservationKey(record);
    if (!options.verified)
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evaluation_not_verified' };
    if (record.verdict === 'INDETERMINATE')
        return { allowed: false, invoke_allowed: false, state: 'RECONCILIATION_REQUIRED', reason: 'evidence_indeterminate' };
    if (record.verdict !== 'SATISFIED')
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evidence_requirement_not_satisfied' };
    if (record.authority_constraints?.one_time_consumption !== true)
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'one_time_consumption_not_required' };
    if (!options.local_authorization)
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'local_authorization_denied' };
    if (!secureDurableStore(options.store))
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'secure_consumption_store_required' };
    try {
        if (await options.store.reserve(reservationKey) !== true) {
            return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'consumption_conflict' };
        }
    }
    catch {
        return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'consumption_store_unavailable' };
    }
    return { allowed: true, invoke_allowed: true, state: 'AUTHORIZED', reason: 'reserved_for_execution', reservation_key: reservationKey };
}
export async function reconcileAebExecutionDurable(store, reservationKey, outcome) {
    if (!secureDurableStore(store))
        return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'secure_consumption_store_required' };
    if (outcome === 'INDETERMINATE')
        return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'execution_outcome_indeterminate' };
    try {
        if (outcome === 'COMMITTED') {
            return await store.commit(reservationKey) === true
                ? { state: 'CONSUMED', retry_allowed: false, reason: 'execution_committed' }
                : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
        }
        return await store.release(reservationKey) === true
            ? { state: 'AVAILABLE', retry_allowed: true, reason: 'execution_not_committed' }
            : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
    }
    catch {
        return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'consumption_store_unavailable' };
    }
}
export { canonicalize as canonicalizeAeb, digest as digestAeb };
//# sourceMappingURL=aeb-adapter-contract.js.map