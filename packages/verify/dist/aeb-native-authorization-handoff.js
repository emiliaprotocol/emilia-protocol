// SPDX-License-Identifier: Apache-2.0
/**
 * Direct native-authorization handoff for the Action Evidence Boundary.
 *
 * A native system makes the authorization decision. A relying-party-pinned
 * gateway signs the exact action and execution bindings it observed. This
 * module verifies that statement; it does not run policy, reinterpret the
 * native decision, or require CAID or AEC.
 */
import crypto from 'node:crypto';
import { types as nodeTypes } from 'node:util';
import { canonicalizeStrictJson } from './strict-json.js';
export const AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION = 'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1';
export const AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN = 'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1\0';
/**
 * v2 replay derivations hash only the authority namespace, issuer, and native
 * authorization identifier. The v1 derivations also hashed the wire labels
 * `system` and `profile`, so one grant relabelled under a second pinned
 * profile derived a second replay key and could be spent twice.
 */
export const AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN = 'AEB-NATIVE-AUTHORIZATION-REPLAY-v2';
export const AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN = 'AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2';
export const AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN = 'AEB-NATIVE-AUTHORIZATION-ACTION-v1';
export const AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION = 'AEB-NATIVE-AUTHORIZATION-GATEWAY-KEY-v1';
export const AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION = 'AEB-NATIVE-AUTHORIZATION-SOURCE-PIN-v1';
export const AEB_NATIVE_AUTHORIZATION_PINS_VERSION = 'AEB-NATIVE-AUTHORIZATION-PINS-v1';
export const AEB_NATIVE_AUTHORIZATION_STATUS_VERSION = 'AEB-NATIVE-AUTHORIZATION-STATUS-v1';
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/#-]{0,511}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const BODY_KEYS = new Set([
    '@version', 'gateway_id', 'decision', 'native_authorization',
    'relying_party_id', 'audience', 'executor_id', 'provider', 'action_digest',
    'issued_at', 'not_before', 'expires_at', 'revocation_id',
]);
const HANDOFF_KEYS = new Set([...BODY_KEYS, 'signature']);
const NATIVE_KEYS = new Set([
    'system', 'profile', 'issuer', 'authorization_id', 'replay_unit',
]);
const NATIVE_IDENTITY_KEYS = new Set([
    'system', 'profile', 'issuer', 'authorization_id',
]);
const PROVIDER_KEYS = new Set([
    'tenant_id', 'provider_id', 'provider_account_id', 'environment',
]);
const SIGNATURE_KEYS = new Set(['alg', 'key_id', 'value']);
const GATEWAY_KEY_KEYS = new Set([
    '@version', 'gateway_id', 'key_id', 'algorithm', 'public_key',
]);
const SOURCE_PIN_KEYS = new Set([
    '@version', 'gateway_id', 'system', 'profile', 'issuer',
]);
const SOURCE_PIN_OPTIONAL_KEYS = new Set(['authority_namespace']);
const PINS_KEYS = new Set([
    '@version', 'relying_party_id', 'audience', 'executor_id', 'provider',
    'max_handoff_age_seconds', 'max_status_age_seconds', 'clock_skew_seconds',
    'gateway_keys', 'accepted_sources',
]);
const STATUS_KEYS = new Set([
    '@version', 'gateway_id', 'native_authorization', 'revocation_id',
    'checked_at', 'valid_until', 'revoked',
]);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    try {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null)
            return false;
        const descriptors = Object.getOwnPropertyDescriptors(value);
        return Reflect.ownKeys(descriptors).every((key) => typeof key === 'string'
            && descriptors[key].enumerable === true
            && Object.hasOwn(descriptors[key], 'value'));
    }
    catch {
        return false;
    }
}
function exactKeys(value, expected) {
    try {
        const keys = Reflect.ownKeys(value);
        return keys.length === expected.size
            && keys.every((key) => typeof key === 'string' && expected.has(key));
    }
    catch {
        return false;
    }
}
function closedKeys(value, required, optional) {
    try {
        const keys = Reflect.ownKeys(value);
        return [...required].every((key) => Object.hasOwn(value, key))
            && keys.every((key) => typeof key === 'string'
                && (required.has(key) || optional.has(key)));
    }
    catch {
        return false;
    }
}
function identifier(value) {
    return typeof value === 'string'
        && Buffer.byteLength(value, 'utf8') <= 512
        && IDENTIFIER_RE.test(value)
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function digest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function nonNegativeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function instant(value) {
    if (typeof value !== 'string')
        return NaN;
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
        ? milliseconds
        : NaN;
}
function canonicalClone(value) {
    return JSON.parse(canonicalizeStrictJson(value));
}
const UNREADABLE = Symbol('unreadable');
// canonicalizeStrictJson refuses more than 100000 nodes by default.
const PROXY_SCAN_NODE_BUDGET = 100_001;
/**
 * True when a Proxy appears anywhere in a value. Detection runs no traps; the
 * walk reads descriptors of ordinary objects only. A Proxy can answer
 * descriptor reads faithfully while its other traps misbehave, so it is
 * refused rather than trusted.
 */
function containsProxy(value) {
    const seen = new Set();
    const stack = [value];
    let nodes = 0;
    while (stack.length > 0) {
        const current = stack.pop();
        if (current === null || (typeof current !== 'object' && typeof current !== 'function'))
            continue;
        if (nodeTypes.isProxy(current))
            return true;
        if (seen.has(current))
            continue;
        seen.add(current);
        nodes += 1;
        if (nodes > PROXY_SCAN_NODE_BUDGET)
            return true;
        try {
            const descriptors = Object.getOwnPropertyDescriptors(current);
            for (const key of Reflect.ownKeys(descriptors)) {
                const descriptor = descriptors[key];
                if (Object.hasOwn(descriptor, 'value'))
                    stack.push(descriptor.value);
            }
        }
        catch {
            return true;
        }
    }
    return false;
}
/**
 * One read of a caller value into plain JSON data. Proxies are refused first.
 * canonicalizeStrictJson then reads members through property descriptors and
 * refuses accessors, sparse arrays, symbols, non-plain prototypes, and cycles,
 * so no caller code runs and no value can change between validation and use.
 * An unreadable value is reported by the callers as a refusal, never thrown.
 */
function snapshotOrUnreadable(value) {
    try {
        if (containsProxy(value))
            return UNREADABLE;
        return canonicalClone(value);
    }
    catch {
        return UNREADABLE;
    }
}
function snapshot(value) {
    const copy = snapshotOrUnreadable(value);
    return copy === UNREADABLE ? null : copy;
}
function readOption(options, key) {
    if (options === undefined || options === null)
        return { ok: true, value: undefined };
    if (typeof options !== 'object' || nodeTypes.isProxy(options))
        return { ok: false };
    try {
        const descriptor = Object.getOwnPropertyDescriptor(options, key);
        if (descriptor === undefined)
            return { ok: true, value: undefined };
        if (!Object.hasOwn(descriptor, 'value'))
            return { ok: false };
        return { ok: true, value: descriptor.value };
    }
    catch {
        return { ok: false };
    }
}
function freezeDeep(value) {
    if (value === null || typeof value !== 'object')
        return value;
    const stack = [value];
    while (stack.length > 0) {
        const current = stack.pop();
        for (const child of Object.values(current)) {
            if (child !== null && typeof child === 'object')
                stack.push(child);
        }
        Object.freeze(current);
    }
    return value;
}
function sha256Domain(domain, value) {
    const bytes = Buffer.from(`${domain}\0${canonicalizeStrictJson(value)}`, 'utf8');
    return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}
export function digestAebNativeAuthorizationAction(action) {
    return sha256Domain(AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN, action);
}
/**
 * Derive the replay unit for one native authority: (authority namespace,
 * issuer, native authorization identifier). The `system` and `profile` labels
 * are validated but are never inputs, so relabelling one grant cannot make it
 * spendable again. Without an explicit namespace the issuer is the namespace;
 * that default is what a gateway signs on the wire.
 */
export function deriveAebNativeAuthorizationReplayUnit(source, options = {}) {
    const identity = parseNativeIdentity(source);
    if (!identity) {
        throw new TypeError('valid closed native authorization source required');
    }
    const namespace = readOption(options, 'authority_namespace');
    if (!namespace.ok || (namespace.value !== undefined && !identifier(namespace.value))) {
        throw new TypeError('valid native authority namespace required');
    }
    return deriveReplayUnitUnchecked(identity, namespace.value);
}
/**
 * Relying-party-scoped durable replay key. `authority_namespace` is the value
 * pinned by the relying party for the accepted source; omit it for the default
 * (issuer) namespace.
 */
export function aebNativeAuthorizationReplayKey(input) {
    const relyingParty = readOption(input, 'relying_party_id');
    const nativeAuthorization = readOption(input, 'native_authorization');
    const namespace = readOption(input, 'authority_namespace');
    const source = nativeAuthorization.ok ? parseNativeSource(nativeAuthorization.value) : null;
    if (!relyingParty.ok || !identifier(relyingParty.value) || !source || !namespace.ok
        || (namespace.value !== undefined && !identifier(namespace.value))) {
        throw new TypeError('valid native authorization replay binding required');
    }
    const { replay_unit: _wireUnit, ...identity } = source;
    return replayKeyUnchecked(relyingParty.value, deriveReplayUnitUnchecked(identity, namespace.value));
}
function replayKeyUnchecked(relyingPartyId, replayUnit) {
    return `aeb-native:${sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN, {
        relying_party_id: relyingPartyId,
        replay_unit: replayUnit,
    })}`;
}
function parseProvider(value) {
    if (!isRecord(value) || !exactKeys(value, PROVIDER_KEYS)
        || !identifier(value.tenant_id) || !identifier(value.provider_id)
        || !identifier(value.provider_account_id) || !identifier(value.environment))
        return null;
    return canonicalClone(value);
}
function nativeSystem(value) {
    return value === 'aims' || value === 'authzen' || value === 'coaz'
        || value === 'ap2' || value === 'oauth' || value === 'local';
}
function parseNativeIdentity(input) {
    const value = snapshot(input);
    if (!isRecord(value) || !exactKeys(value, NATIVE_IDENTITY_KEYS)
        || !nativeSystem(value.system) || !identifier(value.profile)
        || !identifier(value.issuer) || !identifier(value.authorization_id))
        return null;
    return canonicalClone(value);
}
function parseNativeSource(input) {
    const value = snapshot(input);
    if (!isRecord(value) || !exactKeys(value, NATIVE_KEYS)
        || !nativeSystem(value.system) || !identifier(value.profile)
        || !identifier(value.issuer) || !identifier(value.authorization_id)
        || !digest(value.replay_unit))
        return null;
    const source = canonicalClone(value);
    const { replay_unit: _replayUnit, ...identity } = source;
    return deriveReplayUnitUnchecked(identity) === source.replay_unit ? source : null;
}
function deriveReplayUnitUnchecked(source, authorityNamespace) {
    return sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN, {
        authority_namespace: authorityNamespace ?? source.issuer,
        issuer: source.issuer,
        authorization_id: source.authorization_id,
    });
}
function parseBody(value) {
    if (!isRecord(value) || !exactKeys(value, BODY_KEYS)
        || value['@version'] !== AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION
        || !identifier(value.gateway_id) || value.decision !== 'PERMIT'
        || !parseNativeSource(value.native_authorization)
        || !identifier(value.relying_party_id) || !identifier(value.audience)
        || !identifier(value.executor_id) || !parseProvider(value.provider)
        || !digest(value.action_digest) || !identifier(value.revocation_id)
        || !Number.isFinite(instant(value.issued_at))
        || !Number.isFinite(instant(value.not_before))
        || !Number.isFinite(instant(value.expires_at)))
        return null;
    const issuedAt = instant(value.issued_at);
    const notBefore = instant(value.not_before);
    const expiresAt = instant(value.expires_at);
    if (issuedAt > expiresAt || notBefore >= expiresAt)
        return null;
    return canonicalClone(value);
}
function parseHandoff(input) {
    const value = snapshot(input);
    if (!isRecord(value) || !exactKeys(value, HANDOFF_KEYS) || !isRecord(value.signature)
        || !exactKeys(value.signature, SIGNATURE_KEYS)
        || value.signature.alg !== 'Ed25519' || !identifier(value.signature.key_id)
        || typeof value.signature.value !== 'string'
        || !SIGNATURE_RE.test(value.signature.value))
        return null;
    let signatureBytes;
    try {
        signatureBytes = Buffer.from(value.signature.value, 'base64url');
    }
    catch {
        return null;
    }
    if (signatureBytes.length !== 64
        || signatureBytes.toString('base64url') !== value.signature.value)
        return null;
    const { signature: _signature, ...bodyValue } = value;
    const body = parseBody(bodyValue);
    if (!body)
        return null;
    return canonicalClone({ ...body, signature: value.signature });
}
function parseGatewayKey(value) {
    if (!isRecord(value) || !exactKeys(value, GATEWAY_KEY_KEYS)
        || value['@version'] !== AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION
        || !identifier(value.gateway_id) || !identifier(value.key_id)
        || value.algorithm !== 'Ed25519' || typeof value.public_key !== 'string'
        || !B64URL_RE.test(value.public_key) || value.public_key.length % 4 === 1)
        return null;
    try {
        const bytes = Buffer.from(value.public_key, 'base64url');
        if (bytes.length === 0 || bytes.toString('base64url') !== value.public_key)
            return null;
        const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
        const exported = key.export({ type: 'spki', format: 'der' });
        if (key.asymmetricKeyType !== 'ed25519' || !Buffer.isBuffer(exported)
            || !exported.equals(bytes))
            return null;
        return {
            ...canonicalClone(value),
            key,
        };
    }
    catch {
        return null;
    }
}
function parseSourcePin(value) {
    if (!isRecord(value) || !closedKeys(value, SOURCE_PIN_KEYS, SOURCE_PIN_OPTIONAL_KEYS)
        || value['@version'] !== AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION
        || !identifier(value.gateway_id) || !nativeSystem(value.system)
        || !identifier(value.profile) || !identifier(value.issuer)
        || (Object.hasOwn(value, 'authority_namespace')
            && !identifier(value.authority_namespace)))
        return null;
    return canonicalClone(value);
}
function parsePins(input) {
    // Arrays are validated on a dense JSON snapshot: a sparse or accessor-backed
    // pin list is refused here instead of throwing later.
    const value = snapshot(input);
    if (!isRecord(value) || !exactKeys(value, PINS_KEYS)
        || value['@version'] !== AEB_NATIVE_AUTHORIZATION_PINS_VERSION
        || !identifier(value.relying_party_id) || !identifier(value.audience)
        || !identifier(value.executor_id) || !parseProvider(value.provider)
        || !nonNegativeInteger(value.max_handoff_age_seconds)
        || Number(value.max_handoff_age_seconds) === 0
        || !nonNegativeInteger(value.max_status_age_seconds)
        || Number(value.max_status_age_seconds) === 0
        || !nonNegativeInteger(value.clock_skew_seconds)
        || Number(value.clock_skew_seconds) > 300
        || !Array.isArray(value.gateway_keys) || value.gateway_keys.length === 0
        || !Array.isArray(value.accepted_sources) || value.accepted_sources.length === 0)
        return null;
    const keys = value.gateway_keys.map(parseGatewayKey);
    const sources = value.accepted_sources.map(parseSourcePin);
    if (keys.some((key) => key === null) || sources.some((source) => source === null))
        return null;
    const parsedKeys = keys;
    const parsedSources = sources;
    if (new Set(parsedKeys.map((key) => `${key.gateway_id}\0${key.key_id}`)).size !== parsedKeys.length
        || new Set(parsedSources.map((source) => canonicalizeStrictJson([
            source.gateway_id, source.system, source.profile, source.issuer,
        ]))).size !== parsedSources.length
        || parsedSources.some((source) => !parsedKeys.some((key) => key.gateway_id === source.gateway_id))) {
        return null;
    }
    // One issuer accepted under several pins shares one authority namespace
    // unless every one of those pins declares its namespace explicitly. A mix
    // would let a relabelled grant land in a second, default namespace.
    const namespaceDeclarations = new Map();
    for (const source of parsedSources) {
        const declared = namespaceDeclarations.get(source.issuer) ?? new Set();
        declared.add(Object.hasOwn(source, 'authority_namespace'));
        namespaceDeclarations.set(source.issuer, declared);
    }
    if ([...namespaceDeclarations.values()].some((declared) => declared.size > 1))
        return null;
    return {
        pins: canonicalClone(value),
        keys: parsedKeys,
        sources: parsedSources,
    };
}
function parseStatus(input) {
    const value = snapshot(input);
    if (!isRecord(value) || !exactKeys(value, STATUS_KEYS)
        || value['@version'] !== AEB_NATIVE_AUTHORIZATION_STATUS_VERSION
        || !identifier(value.gateway_id)
        || !parseNativeSource(value.native_authorization)
        || !identifier(value.revocation_id)
        || !Number.isFinite(instant(value.checked_at))
        || !Number.isFinite(instant(value.valid_until))
        || typeof value.revoked !== 'boolean'
        || instant(value.checked_at) >= instant(value.valid_until))
        return null;
    return canonicalClone(value);
}
function unsigned(handoff) {
    const { signature: _signature, ...body } = handoff;
    return body;
}
function signingBytes(body) {
    return Buffer.from(`${AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN}${canonicalizeStrictJson(body)}`, 'utf8');
}
function validPrivateKey(value) {
    return value instanceof crypto.KeyObject
        && value.type === 'private'
        && value.asymmetricKeyType === 'ed25519';
}
/**
 * Issue a gateway statement for one native PERMIT. The caller supplies the
 * native system's stable authorization identifier. Operation and wrapper IDs
 * are deliberately absent from the replay-unit derivation.
 */
export function issueAebNativeAuthorizationHandoff(input, signer) {
    if (!validPrivateKey(signer?.private_key) || !identifier(signer?.key_id)) {
        throw new TypeError('valid Ed25519 native authorization gateway signer required');
    }
    const identity = parseNativeIdentity(input?.native_authorization);
    if (!identity)
        throw new TypeError('valid closed native authorization source required');
    const source = {
        ...identity,
        replay_unit: deriveReplayUnitUnchecked(identity),
    };
    const body = parseBody({
        '@version': AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION,
        gateway_id: input?.gateway_id,
        decision: 'PERMIT',
        native_authorization: source,
        relying_party_id: input?.relying_party_id,
        audience: input?.audience,
        executor_id: input?.executor_id,
        provider: input?.provider,
        action_digest: digestAebNativeAuthorizationAction(input?.action),
        issued_at: input?.issued_at,
        not_before: input?.not_before,
        expires_at: input?.expires_at,
        revocation_id: input?.revocation_id,
    });
    if (!body)
        throw new TypeError('valid closed native authorization handoff input required');
    const value = crypto.sign(null, signingBytes(body), signer.private_key).toString('base64url');
    return freezeDeep(canonicalClone({
        ...body,
        signature: { alg: 'Ed25519', key_id: signer.key_id, value },
    }));
}
function emptyChecks() {
    return {
        schema: false,
        key_pinned: false,
        signature: false,
        source_pinned: false,
        decision: false,
        exact_action: false,
        relying_party: false,
        audience: false,
        executor: false,
        provider: false,
        freshness: false,
        revocation: false,
    };
}
function safeRecordDigest(value) {
    try {
        return sha256Domain(AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION, value);
    }
    catch {
        return sha256Domain(AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION, { invalid_record: true });
    }
}
/**
 * Verify a gateway-signed native-authorization handoff under relying-party
 * pins. This verifies the gateway statement, not the native permit or artifact.
 * `execution_authorizing` reports only whether the statement is usable at this
 * boundary. It is not a fresh policy decision.
 */
export function verifyAebNativeAuthorizationHandoff(handoffValue, options) {
    const modeOption = readOption(options, 'mode');
    const pinsOption = readOption(options, 'pins');
    const actionOption = readOption(options, 'expected_action');
    const statusOption = readOption(options, 'status');
    const nowOption = readOption(options, 'now');
    const optionsReadable = modeOption.ok && pinsOption.ok && actionOption.ok
        && statusOption.ok && nowOption.ok;
    const requestedMode = modeOption.ok ? modeOption.value : undefined;
    const modeValid = requestedMode === undefined
        || requestedMode === 'execution'
        || requestedMode === 'historical';
    // TypeScript callers cannot name another mode, but this is a public
    // JavaScript verifier and hostile runtime input must still fail closed. Use
    // execution semantics as the safe internal fallback while retaining the
    // explicit invalid-mode reason below.
    const mode = requestedMode === 'historical'
        ? 'historical'
        : 'execution';
    const reasons = [];
    if (!optionsReadable)
        reasons.push('native_handoff_options_invalid');
    if (!modeValid)
        reasons.push('native_handoff_mode_invalid');
    const checks = emptyChecks();
    // Every caller value is read exactly once into plain data before any check.
    const handoffSnapshot = snapshotOrUnreadable(handoffValue);
    const recordDigest = safeRecordDigest(handoffSnapshot);
    const handoff = optionsReadable && handoffSnapshot !== UNREADABLE
        ? parseHandoff(handoffSnapshot)
        : null;
    const parsedPins = optionsReadable && pinsOption.ok ? parsePins(pinsOption.value) : null;
    const status = optionsReadable && statusOption.ok ? parseStatus(statusOption.value) : null;
    const nowMs = optionsReadable && nowOption.ok ? instant(nowOption.value) : NaN;
    checks.schema = handoff !== null && parsedPins !== null && Number.isFinite(nowMs);
    if (!checks.schema)
        reasons.push('native_handoff_schema_invalid');
    let expectedActionDigest = null;
    try {
        if (!optionsReadable || !actionOption.ok || containsProxy(actionOption.value)) {
            throw new TypeError('expected action unreadable');
        }
        expectedActionDigest = digestAebNativeAuthorizationAction(actionOption.value);
    }
    catch {
        reasons.push('native_handoff_expected_action_invalid');
    }
    let key = null;
    if (handoff && parsedPins) {
        key = parsedPins.keys.find((candidate) => candidate.gateway_id === handoff.gateway_id
            && candidate.key_id === handoff.signature.key_id) ?? null;
    }
    checks.key_pinned = key !== null;
    if (handoff && !checks.key_pinned)
        reasons.push('native_handoff_gateway_key_not_pinned');
    if (handoff && key) {
        try {
            checks.signature = crypto.verify(null, signingBytes(unsigned(handoff)), key.key, Buffer.from(handoff.signature.value, 'base64url'));
        }
        catch {
            checks.signature = false;
        }
    }
    if (handoff && !checks.signature)
        reasons.push('native_handoff_signature_invalid');
    let matchedSource = null;
    if (handoff && parsedPins) {
        // Pin identities are unique (see parsePins), so at most one pin matches.
        matchedSource = parsedPins.sources.find((source) => source.gateway_id === handoff.gateway_id
            && source.system === handoff.native_authorization.system
            && source.profile === handoff.native_authorization.profile
            && source.issuer === handoff.native_authorization.issuer) ?? null;
        checks.source_pinned = matchedSource !== null;
        checks.decision = handoff.decision === 'PERMIT';
        checks.exact_action = expectedActionDigest !== null
            && handoff.action_digest === expectedActionDigest;
        checks.relying_party = handoff.relying_party_id === parsedPins.pins.relying_party_id;
        checks.audience = handoff.audience === parsedPins.pins.audience;
        checks.executor = handoff.executor_id === parsedPins.pins.executor_id;
        checks.provider = canonicalizeStrictJson(handoff.provider)
            === canonicalizeStrictJson(parsedPins.pins.provider);
        if (!checks.source_pinned)
            reasons.push('native_handoff_source_not_pinned');
        if (!checks.decision)
            reasons.push('native_handoff_not_permit');
        if (!checks.exact_action)
            reasons.push('native_handoff_exact_action_mismatch');
        if (!checks.relying_party)
            reasons.push('native_handoff_relying_party_mismatch');
        if (!checks.audience)
            reasons.push('native_handoff_audience_mismatch');
        if (!checks.executor)
            reasons.push('native_handoff_executor_mismatch');
        if (!checks.provider)
            reasons.push('native_handoff_provider_mismatch');
        const skewMs = parsedPins.pins.clock_skew_seconds * 1000;
        if (mode === 'historical') {
            // Historical verification proves the signed binding only. The Gate's
            // owner-fenced attempt record is what proves that execution-mode checks
            // passed before provider entry.
            checks.freshness = false;
            checks.revocation = false;
        }
        else {
            const issuedAt = instant(handoff.issued_at);
            const notBefore = instant(handoff.not_before);
            const expiresAt = instant(handoff.expires_at);
            const maxAgeMs = parsedPins.pins.max_handoff_age_seconds * 1000;
            checks.freshness = Number.isFinite(nowMs)
                && nowMs + skewMs >= notBefore
                && nowMs - skewMs < expiresAt
                && issuedAt <= nowMs + skewMs
                && nowMs - issuedAt <= maxAgeMs + skewMs;
            if (!checks.freshness)
                reasons.push('native_handoff_stale_or_not_current');
        }
        if (mode === 'execution' && status) {
            const checkedAt = instant(status.checked_at);
            const validUntil = instant(status.valid_until);
            const maxStatusAgeMs = parsedPins.pins.max_status_age_seconds * 1000;
            checks.revocation = status.gateway_id === handoff.gateway_id
                && canonicalizeStrictJson(status.native_authorization)
                    === canonicalizeStrictJson(handoff.native_authorization)
                && status.revocation_id === handoff.revocation_id
                && status.revoked === false
                && checkedAt <= nowMs + skewMs
                && nowMs - checkedAt <= maxStatusAgeMs + skewMs
                && nowMs - skewMs < validUntil;
        }
        if (mode === 'execution') {
            if (!status)
                reasons.push('native_handoff_revocation_status_invalid');
            else if (status.revoked)
                reasons.push('native_handoff_revoked');
            else if (!checks.revocation)
                reasons.push('native_handoff_revocation_status_not_current');
        }
    }
    const bindingChecks = Object.entries(checks)
        .filter(([name]) => mode === 'execution' || (name !== 'freshness' && name !== 'revocation'))
        .every(([, passed]) => passed);
    const valid = bindingChecks && reasons.length === 0;
    const frozenHandoff = handoff ? freezeDeep(canonicalClone(handoff)) : null;
    // The replay identity is established only under a pin: the relying party's
    // namespace (default: the issuer), the issuer, and the authorization ID.
    const nativeReplayUnit = handoff && matchedSource
        ? deriveReplayUnitUnchecked(handoff.native_authorization, matchedSource.authority_namespace)
        : null;
    return freezeDeep({
        mode,
        valid,
        execution_authorizing: valid && mode === 'execution',
        reasons: [...new Set(reasons)],
        checks,
        record_digest: recordDigest,
        action_digest: expectedActionDigest,
        native_replay_unit: nativeReplayUnit,
        replay_key: handoff && nativeReplayUnit
            ? replayKeyUnchecked(handoff.relying_party_id, nativeReplayUnit)
            : null,
        handoff: frozenHandoff,
    });
}
export default Object.freeze({
    AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION,
    AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN,
    AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN,
    AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN,
    AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN,
    AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
    AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
    AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
    AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
    digestAebNativeAuthorizationAction,
    deriveAebNativeAuthorizationReplayUnit,
    aebNativeAuthorizationReplayKey,
    issueAebNativeAuthorizationHandoff,
    verifyAebNativeAuthorizationHandoff,
});
//# sourceMappingURL=aeb-native-authorization-handoff.js.map