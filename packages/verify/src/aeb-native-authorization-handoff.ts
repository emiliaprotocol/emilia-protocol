// SPDX-License-Identifier: Apache-2.0
/**
 * Direct native-authorization handoff for the Action Evidence Boundary.
 *
 * A native system makes the authorization decision. A relying-party-pinned
 * gateway signs the exact action and execution bindings it observed. This
 * module verifies that statement; it does not run policy, reinterpret the
 * native decision, or require CAID or AEC.
 */
import crypto, { type KeyObject } from 'node:crypto';
import { types as nodeTypes } from 'node:util';
import { canonicalizeStrictJson } from './strict-json.js';

type JsonObject = Record<string, unknown>;

export const AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION =
  'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1';
export const AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1\0';
/**
 * Domain of the wire `native_authorization.replay_unit` that a gateway signs.
 * It is unchanged from verify 4.1.0 and still hashes the `system` and
 * `profile` labels, so handoffs stay byte-compatible in both directions. The
 * verifier checks the wire value but never uses it for replay enforcement.
 */
export const AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-REPLAY-v1';
/**
 * Domain of the label-free native replay identity the verifier derives
 * locally: (authority namespace, native authorization identifier). The
 * default namespace is the issuer. A declared namespace replaces the issuer,
 * so pins that spell one issuer two ways can share one identity.
 */
export const AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-REPLAY-IDENTITY-v1';
/**
 * Domain of the verify 4.1.0 relying-party-scoped replay key over the
 * label-bearing wire `replay_unit` (aebNativeAuthorizationReplayKey() and the
 * verification result's `replay_key`). Unchanged from 4.1.0. That key changes
 * when one grant is relabelled under a second pinned profile or system, so it
 * is not sufficient as the only replay fence.
 */
export const AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1';
/**
 * Domain of the relying-party-scoped durable replay key over the label-free
 * native replay identity (aebNativeAuthorizationReplayIdentityKey() and the
 * verification result's `replay_identity_key`).
 */
export const AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2';
export const AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-ACTION-v1';
export const AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION =
  'AEB-NATIVE-AUTHORIZATION-GATEWAY-KEY-v1';
export const AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION =
  'AEB-NATIVE-AUTHORIZATION-SOURCE-PIN-v1';
export const AEB_NATIVE_AUTHORIZATION_PINS_VERSION =
  'AEB-NATIVE-AUTHORIZATION-PINS-v1';
export const AEB_NATIVE_AUTHORIZATION_STATUS_VERSION =
  'AEB-NATIVE-AUTHORIZATION-STATUS-v1';

export type AebNativeAuthorizationSystem =
  | 'aims'
  | 'authzen'
  | 'coaz'
  | 'ap2'
  | 'oauth'
  | 'local';
export type AebNativeAuthorizationDigest = `sha256:${string}`;

export interface AebNativeAuthorizationProviderBinding {
  tenant_id: string;
  provider_id: string;
  provider_account_id: string;
  environment: string;
}

export interface AebNativeAuthorizationSource {
  system: AebNativeAuthorizationSystem;
  profile: string;
  issuer: string;
  authorization_id: string;
  /**
   * Gateway-computed wire digest of (system, profile, issuer, authorization
   * ID) under `AEB-NATIVE-AUTHORIZATION-REPLAY-v1`, exactly as verify 4.1.0
   * signs it. The verifier checks it for wire compatibility and never uses it
   * as a replay identity: it changes when a grant is relabelled. The
   * enforcement identity is AebNativeAuthorizationHandoffVerification
   * `.native_replay_unit`.
   */
  replay_unit: AebNativeAuthorizationDigest;
}

export interface AebNativeAuthorizationHandoffBody {
  '@version': typeof AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION;
  gateway_id: string;
  decision: 'PERMIT';
  native_authorization: AebNativeAuthorizationSource;
  relying_party_id: string;
  audience: string;
  executor_id: string;
  provider: AebNativeAuthorizationProviderBinding;
  action_digest: AebNativeAuthorizationDigest;
  issued_at: string;
  not_before: string;
  expires_at: string;
  revocation_id: string;
}

export interface AebNativeAuthorizationHandoff
  extends AebNativeAuthorizationHandoffBody {
  signature: {
    alg: 'Ed25519';
    key_id: string;
    value: string;
  };
}

export interface AebNativeAuthorizationGatewayKey {
  '@version': typeof AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION;
  gateway_id: string;
  key_id: string;
  algorithm: 'Ed25519';
  /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
  public_key: string;
}

export interface AebNativeAuthorizationSourcePin {
  '@version': typeof AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION;
  gateway_id: string;
  system: AebNativeAuthorizationSystem;
  profile: string;
  issuer: string;
  /**
   * Relying-party-pinned namespace for this issuer's authorization
   * identifiers. When omitted the namespace is the issuer string. A declared
   * namespace replaces the issuer in the replay identity, so two pins that
   * declare one namespace share one replay identity per authorization ID.
   * Every pin that accepts one issuer shares one namespace unless each of
   * those pins declares one explicitly; a pin set that mixes declared and
   * default namespaces for one issuer is refused. Pins whose issuers differ
   * only by URL spelling (scheme or host case, a default port, a trailing
   * slash) are refused unless all of them declare the same namespace.
   * Changing a declared namespace changes every replay key derived under it,
   * so it is a key rotation: drain in-flight and burned grants first.
   */
  authority_namespace?: string;
}

export interface AebNativeAuthorizationPins {
  '@version': typeof AEB_NATIVE_AUTHORIZATION_PINS_VERSION;
  relying_party_id: string;
  audience: string;
  executor_id: string;
  provider: AebNativeAuthorizationProviderBinding;
  max_handoff_age_seconds: number;
  max_status_age_seconds: number;
  clock_skew_seconds: number;
  gateway_keys: readonly AebNativeAuthorizationGatewayKey[];
  accepted_sources: readonly AebNativeAuthorizationSourcePin[];
}

export interface AebNativeAuthorizationStatus {
  '@version': typeof AEB_NATIVE_AUTHORIZATION_STATUS_VERSION;
  /** The pinned gateway whose statement this status result covers. */
  gateway_id: string;
  /** Exact native-source identity, including the derived replay unit. */
  native_authorization: AebNativeAuthorizationSource;
  revocation_id: string;
  checked_at: string;
  valid_until: string;
  revoked: boolean;
}

export interface IssueAebNativeAuthorizationHandoffInput {
  gateway_id: string;
  native_authorization: Omit<AebNativeAuthorizationSource, 'replay_unit'>;
  relying_party_id: string;
  audience: string;
  executor_id: string;
  provider: AebNativeAuthorizationProviderBinding;
  action: unknown;
  issued_at: string;
  not_before: string;
  expires_at: string;
  revocation_id: string;
}

export interface AebNativeAuthorizationHandoffSigner {
  key_id: string;
  private_key: KeyObject;
}

export interface AebNativeAuthorizationHandoffChecks {
  schema: boolean;
  key_pinned: boolean;
  signature: boolean;
  source_pinned: boolean;
  decision: boolean;
  exact_action: boolean;
  relying_party: boolean;
  audience: boolean;
  executor: boolean;
  provider: boolean;
  freshness: boolean;
  revocation: boolean;
}

export interface AebNativeAuthorizationHandoffVerification {
  mode: 'execution' | 'historical';
  valid: boolean;
  execution_authorizing: boolean;
  reasons: readonly string[];
  checks: Readonly<AebNativeAuthorizationHandoffChecks>;
  record_digest: AebNativeAuthorizationDigest;
  action_digest: AebNativeAuthorizationDigest | null;
  /**
   * The wire `handoff.native_authorization.replay_unit`, exactly as verify
   * 4.1.0 reported it: a label-bearing digest of (system, profile, issuer,
   * authorization ID). Kept for compatibility. It changes when one grant is
   * relabelled, so enforcement should use `native_replay_identity`.
   */
  native_replay_unit: AebNativeAuthorizationDigest | null;
  /**
   * The verify 4.1.0 replay key over `native_replay_unit`
   * (`AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1`), unchanged. Fence it together
   * with `replay_identity_key`, never alone.
   */
  replay_key: string | null;
  /**
   * Label-free native replay identity under the matched pin's authority
   * namespace: (namespace, authorization ID), with the issuer as the default
   * namespace. Null unless the native source is pinned and the pin set passes
   * verifyAebNativeAuthorizationPins().
   */
  native_replay_identity: AebNativeAuthorizationDigest | null;
  /**
   * Relying-party-scoped durable replay key for `native_replay_identity`
   * (`AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2`). Null exactly when
   * `native_replay_identity` is null.
   */
  replay_identity_key: string | null;
  /**
   * The verify 4.1.0 `replay_key` this grant has under every pinned
   * (system, profile, issuer) label that shares the matched pin's authority
   * namespace (the issuer, unless the pin declares `authority_namespace`),
   * sorted and without duplicates. It includes `replay_key`. Code built on
   * 4.1.0 fenced only the key of the label a grant was presented under, so a
   * replay fence that holds all of these refuses a grant consumed there under
   * one label and presented here under another pinned label. Null exactly
   * when `native_replay_identity` is null.
   */
  legacy_replay_keys: readonly string[] | null;
  handoff: Readonly<AebNativeAuthorizationHandoff> | null;
}

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

function isRecord(value: unknown): value is JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Reflect.ownKeys(descriptors).every((key) => typeof key === 'string'
      && descriptors[key].enumerable === true
      && Object.hasOwn(descriptors[key], 'value'));
  } catch {
    return false;
  }
}

function exactKeys(value: JsonObject, expected: ReadonlySet<string>): boolean {
  try {
    const keys = Reflect.ownKeys(value);
    return keys.length === expected.size
      && keys.every((key) => typeof key === 'string' && expected.has(key));
  } catch {
    return false;
  }
}

function closedKeys(
  value: JsonObject,
  required: ReadonlySet<string>,
  optional: ReadonlySet<string>,
): boolean {
  try {
    const keys = Reflect.ownKeys(value);
    return [...required].every((key) => Object.hasOwn(value, key))
      && keys.every((key) => typeof key === 'string'
        && (required.has(key) || optional.has(key)));
  } catch {
    return false;
  }
}

function identifier(value: unknown): value is string {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') <= 512
    && IDENTIFIER_RE.test(value)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function digest(value: unknown): value is AebNativeAuthorizationDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function instant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
    ? milliseconds
    : NaN;
}

function canonicalClone<T>(value: T): T {
  return JSON.parse(canonicalizeStrictJson(value)) as T;
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
function containsProxy(value: unknown): boolean {
  const seen = new Set<object>();
  const stack: unknown[] = [value];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || (typeof current !== 'object' && typeof current !== 'function')) continue;
    if (nodeTypes.isProxy(current)) return true;
    if (seen.has(current as object)) continue;
    seen.add(current as object);
    nodes += 1;
    if (nodes > PROXY_SCAN_NODE_BUDGET) return true;
    try {
      const descriptors = Object.getOwnPropertyDescriptors(current);
      for (const key of Reflect.ownKeys(descriptors)) {
        const descriptor = descriptors[key as string];
        if (Object.hasOwn(descriptor, 'value')) stack.push(descriptor.value);
      }
    } catch {
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
function snapshotOrUnreadable(value: unknown): unknown {
  try {
    if (containsProxy(value)) return UNREADABLE;
    return canonicalClone(value);
  } catch {
    return UNREADABLE;
  }
}

function snapshot(value: unknown): unknown {
  const copy = snapshotOrUnreadable(value);
  return copy === UNREADABLE ? null : copy;
}

type OptionRead = { ok: true; value: unknown } | { ok: false };

function readOption(options: unknown, key: string): OptionRead {
  if (options === undefined || options === null) return { ok: true, value: undefined };
  if (typeof options !== 'object' || nodeTypes.isProxy(options)) return { ok: false };
  try {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (descriptor === undefined) return { ok: true, value: undefined };
    if (!Object.hasOwn(descriptor, 'value')) return { ok: false };
    return { ok: true, value: descriptor.value };
  } catch {
    return { ok: false };
  }
}

function freezeDeep<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value;
  const stack: object[] = [value as object];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === 'object') stack.push(child);
    }
    Object.freeze(current);
  }
  return value;
}

function sha256Domain(
  domain: string,
  value: unknown,
): AebNativeAuthorizationDigest {
  const bytes = Buffer.from(`${domain}\0${canonicalizeStrictJson(value)}`, 'utf8');
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function digestAebNativeAuthorizationAction(
  action: unknown,
): AebNativeAuthorizationDigest {
  return sha256Domain(AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN, action);
}

/**
 * Derive the wire `replay_unit` a gateway signs, byte-identical to verify
 * 4.1.0: a domain-separated digest of (system, profile, issuer,
 * authorization ID). It is a wire-compatibility value, not a replay identity;
 * use deriveAebNativeAuthorizationReplayIdentity() for enforcement.
 */
export function deriveAebNativeAuthorizationReplayUnit(
  source: Omit<AebNativeAuthorizationSource, 'replay_unit'>,
): AebNativeAuthorizationDigest {
  const identity = parseNativeIdentity(source);
  if (!identity) {
    throw new TypeError('valid closed native authorization source required');
  }
  return deriveWireReplayUnitUnchecked(identity);
}

/**
 * Derive the label-free native replay identity used for enforcement:
 * (authority namespace, native authorization identifier). The namespace is
 * the relying-party-pinned `authority_namespace`, or the issuer when the pin
 * declares none. The `system` and `profile` labels are validated but are never
 * inputs, so relabelling one grant cannot make it spendable again, and a
 * declared namespace replaces the issuer string entirely.
 */
export function deriveAebNativeAuthorizationReplayIdentity(
  source: Omit<AebNativeAuthorizationSource, 'replay_unit'>,
  options: { authority_namespace?: string } = {},
): AebNativeAuthorizationDigest {
  const identity = parseNativeIdentity(source);
  if (!identity) {
    throw new TypeError('valid closed native authorization source required');
  }
  const namespace = readOption(options, 'authority_namespace');
  if (!namespace.ok || (namespace.value !== undefined && !identifier(namespace.value))) {
    throw new TypeError('valid native authority namespace required');
  }
  return deriveReplayIdentityUnchecked(identity, namespace.value as string | undefined);
}

/**
 * The verify 4.1.0 relying-party-scoped replay key over the label-bearing wire
 * `replay_unit`, byte-identical to 4.1.0. One grant relabelled under a second
 * pinned profile or system derives a second value, so a replay fence should
 * hold this key together with aebNativeAuthorizationReplayIdentityKey(), not
 * alone.
 */
export function aebNativeAuthorizationReplayKey(
  input: Pick<AebNativeAuthorizationHandoffBody, 'relying_party_id' | 'native_authorization'>,
): string {
  const relyingParty = readOption(input, 'relying_party_id');
  const nativeAuthorization = readOption(input, 'native_authorization');
  const source = nativeAuthorization.ok ? parseNativeSource(nativeAuthorization.value) : null;
  if (!relyingParty.ok || !identifier(relyingParty.value) || !source) {
    throw new TypeError('valid native authorization replay binding required');
  }
  return legacyReplayKeyUnchecked(relyingParty.value, source.replay_unit);
}

/**
 * Relying-party-scoped durable replay key over the label-free native replay
 * identity (deriveAebNativeAuthorizationReplayIdentity()).
 * `authority_namespace` is the value pinned by the relying party for the
 * accepted source; omit it for the default (issuer) namespace. The input's
 * wire `replay_unit` must be the 4.1.0-compatible value for its labels.
 */
export function aebNativeAuthorizationReplayIdentityKey(
  input: Pick<AebNativeAuthorizationHandoffBody, 'relying_party_id' | 'native_authorization'>
    & { authority_namespace?: string },
): string {
  const relyingParty = readOption(input, 'relying_party_id');
  const nativeAuthorization = readOption(input, 'native_authorization');
  const namespace = readOption(input, 'authority_namespace');
  const source = nativeAuthorization.ok ? parseNativeSource(nativeAuthorization.value) : null;
  if (!relyingParty.ok || !identifier(relyingParty.value) || !source || !namespace.ok
      || (namespace.value !== undefined && !identifier(namespace.value))) {
    throw new TypeError('valid native authorization replay binding required');
  }
  const { replay_unit: _wireUnit, ...identity } = source;
  return identityReplayKeyUnchecked(
    relyingParty.value,
    deriveReplayIdentityUnchecked(identity, namespace.value as string | undefined),
  );
}

function legacyReplayKeyUnchecked(
  relyingPartyId: string,
  wireReplayUnit: AebNativeAuthorizationDigest,
): string {
  return `aeb-native:${sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN, {
    relying_party_id: relyingPartyId,
    replay_unit: wireReplayUnit,
  })}`;
}

function identityReplayKeyUnchecked(
  relyingPartyId: string,
  replayIdentity: AebNativeAuthorizationDigest,
): string {
  return `aeb-native:${sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN, {
    relying_party_id: relyingPartyId,
    replay_unit: replayIdentity,
  })}`;
}

function parseProvider(value: unknown): AebNativeAuthorizationProviderBinding | null {
  if (!isRecord(value) || !exactKeys(value, PROVIDER_KEYS)
      || !identifier(value.tenant_id) || !identifier(value.provider_id)
      || !identifier(value.provider_account_id) || !identifier(value.environment)) return null;
  return canonicalClone(value) as unknown as AebNativeAuthorizationProviderBinding;
}

function nativeSystem(value: unknown): value is AebNativeAuthorizationSystem {
  return value === 'aims' || value === 'authzen' || value === 'coaz'
    || value === 'ap2' || value === 'oauth' || value === 'local';
}

function parseNativeIdentity(
  input: unknown,
): Omit<AebNativeAuthorizationSource, 'replay_unit'> | null {
  const value = snapshot(input);
  if (!isRecord(value) || !exactKeys(value, NATIVE_IDENTITY_KEYS)
      || !nativeSystem(value.system) || !identifier(value.profile)
      || !identifier(value.issuer) || !identifier(value.authorization_id)) return null;
  return canonicalClone(value) as Omit<AebNativeAuthorizationSource, 'replay_unit'>;
}

function parseNativeSource(input: unknown): AebNativeAuthorizationSource | null {
  const value = snapshot(input);
  if (!isRecord(value) || !exactKeys(value, NATIVE_KEYS)
      || !nativeSystem(value.system) || !identifier(value.profile)
      || !identifier(value.issuer) || !identifier(value.authorization_id)
      || !digest(value.replay_unit)) return null;
  const source = canonicalClone(value) as unknown as AebNativeAuthorizationSource;
  const { replay_unit: _replayUnit, ...identity } = source;
  return deriveWireReplayUnitUnchecked(identity) === source.replay_unit ? source : null;
}

/** The 4.1.0 wire digest over the closed four-member native identity. */
function deriveWireReplayUnitUnchecked(
  source: Omit<AebNativeAuthorizationSource, 'replay_unit'>,
): AebNativeAuthorizationDigest {
  return sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN, {
    system: source.system,
    profile: source.profile,
    issuer: source.issuer,
    authorization_id: source.authorization_id,
  });
}

function deriveReplayIdentityUnchecked(
  source: Pick<AebNativeAuthorizationSource, 'issuer' | 'authorization_id'>,
  authorityNamespace?: string,
): AebNativeAuthorizationDigest {
  return sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_DOMAIN, {
    authority_namespace: authorityNamespace ?? source.issuer,
    authorization_id: source.authorization_id,
  });
}

const DEFAULT_PORTS: Readonly<Record<string, string>> = Object.freeze({
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
  'ftp:': '21',
});

/**
 * Comparison form of an issuer, used only to detect aliased pins; the replay
 * identity never hashes this form. The scheme compares case-insensitively.
 * For the special URL schemes (http, https, ws, wss, ftp) the issuer is parsed
 * as a WHATWG URL, which also accepts a missing `//` and resolves dot
 * segments; the host compares lower-case without trailing dots, a default
 * port is dropped, and trailing slashes on the path are dropped. For `urn:`
 * the namespace identifier compares case-insensitively (RFC 8141). For `did:`
 * the method name compares lower-case, and for `did:web` the host compares
 * lower-case without trailing dots. For `spiffe://` the trust
 * domain compares lower-case without trailing dots and trailing slashes on
 * the path are dropped. Any other identifier, and every path, compares as
 * written. This finds common aliases, not every alias.
 */
function issuerComparisonForm(issuer: string): string {
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(issuer);
  if (!scheme) return issuer;
  const protocol = `${scheme[1].toLowerCase()}:`;
  const rest = issuer.slice(scheme[0].length);
  if (protocol === 'urn:') {
    const nid = /^([A-Za-z0-9][A-Za-z0-9-]{0,31}):/.exec(rest);
    return nid ? `urn:${nid[1].toLowerCase()}:${rest.slice(nid[0].length)}` : `urn:${rest}`;
  }
  if (protocol === 'did:') {
    const method = /^([A-Za-z0-9]+):/.exec(rest);
    if (!method) return `did:${rest}`;
    const methodName = method[1].toLowerCase();
    const id = rest.slice(method[0].length);
    if (methodName !== 'web') return `did:${methodName}:${id}`;
    // The pin identifier grammar has no `%`, so a did:web issuer here never
    // carries an encoded port: the host is the first colon-separated part.
    const [host, ...path] = id.split(':');
    const normalizedHost = host.toLowerCase().replace(/\.+$/, '');
    return `did:web:${normalizedHost}${path.length > 0 ? `:${path.join(':')}` : ''}`;
  }
  if (protocol === 'spiffe:') {
    const authority = /^\/\/([^/?#]*)(.*)$/.exec(rest);
    if (!authority) return `spiffe:${rest}`;
    const trustDomain = authority[1].toLowerCase().replace(/\.+$/, '');
    return `spiffe://${trustDomain}${authority[2].replace(/\/+$/, '')}`;
  }
  if (!Object.hasOwn(DEFAULT_PORTS, protocol)) return `${protocol}${rest}`;
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    return `${protocol}${rest}`;
  }
  const port = url.port !== '' && url.port !== DEFAULT_PORTS[url.protocol] ? `:${url.port}` : '';
  const userinfo = url.username !== '' || url.password !== ''
    ? `${url.username}${url.password !== '' ? `:${url.password}` : ''}@`
    : '';
  const host = url.hostname.toLowerCase().replace(/\.+$/, '');
  const path = url.pathname.replace(/\/+$/, '');
  return `${url.protocol}//${userinfo}${host}${port}${path}${url.search}${url.hash}`;
}

/** The namespace a pin's replay identity is derived under. */
function effectiveNamespace(source: AebNativeAuthorizationSourcePin): string {
  return source.authority_namespace ?? source.issuer;
}

/**
 * The verify 4.1.0 replay key of one grant under every pinned label whose
 * replay identity shares the matched pin's namespace.
 */
function namespaceGroupReplayKeys(
  handoff: AebNativeAuthorizationHandoff,
  matched: AebNativeAuthorizationSourcePin,
  sources: readonly AebNativeAuthorizationSourcePin[],
): string[] {
  const namespace = effectiveNamespace(matched);
  const keys = new Set<string>();
  for (const source of sources) {
    if (effectiveNamespace(source) !== namespace) continue;
    keys.add(legacyReplayKeyUnchecked(handoff.relying_party_id, deriveWireReplayUnitUnchecked({
      system: source.system,
      profile: source.profile,
      issuer: source.issuer,
      authorization_id: handoff.native_authorization.authorization_id,
    })));
  }
  return [...keys].sort();
}

function parseBody(value: unknown): AebNativeAuthorizationHandoffBody | null {
  if (!isRecord(value) || !exactKeys(value, BODY_KEYS)
      || value['@version'] !== AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION
      || !identifier(value.gateway_id) || value.decision !== 'PERMIT'
      || !parseNativeSource(value.native_authorization)
      || !identifier(value.relying_party_id) || !identifier(value.audience)
      || !identifier(value.executor_id) || !parseProvider(value.provider)
      || !digest(value.action_digest) || !identifier(value.revocation_id)
      || !Number.isFinite(instant(value.issued_at))
      || !Number.isFinite(instant(value.not_before))
      || !Number.isFinite(instant(value.expires_at))) return null;
  const issuedAt = instant(value.issued_at);
  const notBefore = instant(value.not_before);
  const expiresAt = instant(value.expires_at);
  if (issuedAt > expiresAt || notBefore >= expiresAt) return null;
  return canonicalClone(value) as unknown as AebNativeAuthorizationHandoffBody;
}

function parseHandoff(input: unknown): AebNativeAuthorizationHandoff | null {
  const value = snapshot(input);
  if (!isRecord(value) || !exactKeys(value, HANDOFF_KEYS) || !isRecord(value.signature)
      || !exactKeys(value.signature, SIGNATURE_KEYS)
      || value.signature.alg !== 'Ed25519' || !identifier(value.signature.key_id)
      || typeof value.signature.value !== 'string'
      || !SIGNATURE_RE.test(value.signature.value)) return null;
  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(value.signature.value, 'base64url');
  } catch {
    return null;
  }
  if (signatureBytes.length !== 64
      || signatureBytes.toString('base64url') !== value.signature.value) return null;
  const { signature: _signature, ...bodyValue } = value;
  const body = parseBody(bodyValue);
  if (!body) return null;
  return canonicalClone({ ...body, signature: value.signature }) as AebNativeAuthorizationHandoff;
}

function parseGatewayKey(value: unknown): (AebNativeAuthorizationGatewayKey & { key: KeyObject }) | null {
  if (!isRecord(value) || !exactKeys(value, GATEWAY_KEY_KEYS)
      || value['@version'] !== AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION
      || !identifier(value.gateway_id) || !identifier(value.key_id)
      || value.algorithm !== 'Ed25519' || typeof value.public_key !== 'string'
      || !B64URL_RE.test(value.public_key) || value.public_key.length % 4 === 1) return null;
  try {
    const bytes = Buffer.from(value.public_key, 'base64url');
    if (bytes.length === 0 || bytes.toString('base64url') !== value.public_key) return null;
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    const exported = key.export({ type: 'spki', format: 'der' });
    if (key.asymmetricKeyType !== 'ed25519' || !Buffer.isBuffer(exported)
        || !exported.equals(bytes)) return null;
    return {
      ...(canonicalClone(value) as unknown as AebNativeAuthorizationGatewayKey),
      key,
    };
  } catch {
    return null;
  }
}

function parseSourcePin(value: unknown): AebNativeAuthorizationSourcePin | null {
  if (!isRecord(value) || !closedKeys(value, SOURCE_PIN_KEYS, SOURCE_PIN_OPTIONAL_KEYS)
      || value['@version'] !== AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION
      || !identifier(value.gateway_id) || !nativeSystem(value.system)
      || !identifier(value.profile) || !identifier(value.issuer)
      || (Object.hasOwn(value, 'authority_namespace')
        && !identifier(value.authority_namespace))) return null;
  return canonicalClone(value) as unknown as AebNativeAuthorizationSourcePin;
}

/**
 * Pins whose issuers are two spellings of one issuer (for example
 * `https://a.example` and `https://a.example/`) would give one grant one
 * replay identity per spelling. Such a set is accepted only when every pin in
 * the alias group declares the same `authority_namespace`, which replaces the
 * issuer in the replay identity.
 */
function issuerAliasRefusal(sources: readonly AebNativeAuthorizationSourcePin[]): boolean {
  const groups = new Map<string, AebNativeAuthorizationSourcePin[]>();
  for (const source of sources) {
    const form = issuerComparisonForm(source.issuer);
    groups.set(form, [...(groups.get(form) ?? []), source]);
  }
  for (const group of groups.values()) {
    if (new Set(group.map((source) => source.issuer)).size < 2) continue;
    const namespaces = new Set(group.map((source) => source.authority_namespace));
    if (namespaces.size !== 1 || namespaces.has(undefined)) return true;
  }
  return false;
}

/**
 * One exact issuer string declared under two different authority namespaces
 * would give one grant two replay identities, so it is refused the same way
 * as aliased spellings without a shared namespace.
 */
function issuerNamespaceConflict(sources: readonly AebNativeAuthorizationSourcePin[]): boolean {
  const namespaces = new Map<string, Set<string | undefined>>();
  for (const source of sources) {
    const declared = namespaces.get(source.issuer) ?? new Set<string | undefined>();
    declared.add(source.authority_namespace);
    namespaces.set(source.issuer, declared);
  }
  return [...namespaces.values()].some((declared) => declared.size > 1);
}

interface ParsedPins {
  pins: AebNativeAuthorizationPins;
  keys: Array<AebNativeAuthorizationGatewayKey & { key: KeyObject }>;
  sources: AebNativeAuthorizationSourcePin[];
  /**
   * Null when the pin set is safe for the label-free replay identity. A pin
   * set that verify 4.1.0 accepted (no declared namespace) but that aliases
   * one issuer is still accepted for handoff verification, with this reason
   * set and no replay identity derived from it.
   */
  identityRefusal: string | null;
}

type PinsParse = { ok: true; parsed: ParsedPins } | { ok: false; reason: string };

function parsePinsDetailed(input: unknown): PinsParse {
  // Arrays are validated on a dense JSON snapshot: a sparse or accessor-backed
  // pin list is refused here instead of throwing later.
  const value = snapshot(input);
  const refuse = (reason: string): PinsParse => ({ ok: false, reason });
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
      || !Array.isArray(value.accepted_sources) || value.accepted_sources.length === 0) {
    return refuse('native_pins_schema_invalid');
  }
  const keys = value.gateway_keys.map(parseGatewayKey);
  const sources = value.accepted_sources.map(parseSourcePin);
  if (keys.some((key) => key === null) || sources.some((source) => source === null)) {
    return refuse('native_pins_schema_invalid');
  }
  const parsedKeys = keys as Array<AebNativeAuthorizationGatewayKey & { key: KeyObject }>;
  const parsedSources = sources as AebNativeAuthorizationSourcePin[];
  if (new Set(parsedKeys.map((key) => `${key.gateway_id}\0${key.key_id}`)).size !== parsedKeys.length) {
    return refuse('native_pins_duplicate_gateway_key');
  }
  if (new Set(parsedSources.map((source) => canonicalizeStrictJson([
    source.gateway_id, source.system, source.profile, source.issuer,
  ]))).size !== parsedSources.length) {
    return refuse('native_pins_duplicate_source');
  }
  if (parsedSources.some((source) => !parsedKeys.some((key) => key.gateway_id === source.gateway_id))) {
    return refuse('native_pins_source_gateway_unpinned');
  }
  // A pin set that declares any authority namespace uses a feature verify
  // 4.1.0 refused, so every namespace rule below refuses it outright. A pin
  // set without one is still accepted for handoff verification exactly as
  // 4.1.0 accepted it, but an aliased issuer then withholds the label-free
  // replay identity (identityRefusal) instead of deriving one per spelling.
  const declaresNamespace = parsedSources.some((source) =>
    Object.hasOwn(source, 'authority_namespace'));
  // One issuer accepted under several pins shares one authority namespace
  // unless every one of those pins declares its namespace explicitly. A mix
  // would let a relabelled grant land in a second, default namespace.
  const namespaceDeclarations = new Map<string, Set<boolean>>();
  for (const source of parsedSources) {
    const declared = namespaceDeclarations.get(source.issuer) ?? new Set<boolean>();
    declared.add(Object.hasOwn(source, 'authority_namespace'));
    namespaceDeclarations.set(source.issuer, declared);
  }
  if ([...namespaceDeclarations.values()].some((declared) => declared.size > 1)) {
    return refuse('native_pins_namespace_declaration_mixed');
  }
  if (issuerNamespaceConflict(parsedSources)) {
    return refuse('native_pins_issuer_namespace_conflict');
  }
  let identityRefusal: string | null = null;
  if (issuerAliasRefusal(parsedSources)) {
    if (declaresNamespace) return refuse('native_pins_issuer_alias_without_shared_namespace');
    identityRefusal = 'native_pins_issuer_alias_without_shared_namespace';
  }
  return {
    ok: true,
    parsed: {
      pins: canonicalClone(value) as unknown as AebNativeAuthorizationPins,
      keys: parsedKeys,
      sources: parsedSources,
      identityRefusal,
    },
  };
}

function parsePins(input: unknown): ParsedPins | null {
  const result = parsePinsDetailed(input);
  return result.ok ? result.parsed : null;
}

export interface AebNativeAuthorizationPinsVerification {
  valid: boolean;
  /** Empty when valid; otherwise one `native_pins_*` refusal reason. */
  reasons: readonly string[];
}

/**
 * Validate a relying-party pin set before it is used, so a consequence
 * boundary can refuse an unsafe configuration at construction instead of at
 * run time. Never throws: an unreadable value is `native_pins_schema_invalid`.
 */
export function verifyAebNativeAuthorizationPins(
  pins: unknown,
): AebNativeAuthorizationPinsVerification {
  let result: PinsParse;
  try {
    result = parsePinsDetailed(pins);
    if (result.ok && result.parsed.identityRefusal !== null) {
      result = { ok: false, reason: result.parsed.identityRefusal };
    }
  } catch {
    result = { ok: false, reason: 'native_pins_schema_invalid' };
  }
  return freezeDeep({
    valid: result.ok,
    reasons: result.ok ? [] : [result.reason],
  });
}

function parseStatus(input: unknown): AebNativeAuthorizationStatus | null {
  const value = snapshot(input);
  if (!isRecord(value) || !exactKeys(value, STATUS_KEYS)
      || value['@version'] !== AEB_NATIVE_AUTHORIZATION_STATUS_VERSION
      || !identifier(value.gateway_id)
      || !parseNativeSource(value.native_authorization)
      || !identifier(value.revocation_id)
      || !Number.isFinite(instant(value.checked_at))
      || !Number.isFinite(instant(value.valid_until))
      || typeof value.revoked !== 'boolean'
      || instant(value.checked_at) >= instant(value.valid_until)) return null;
  return canonicalClone(value) as unknown as AebNativeAuthorizationStatus;
}

function unsigned(
  handoff: AebNativeAuthorizationHandoff,
): AebNativeAuthorizationHandoffBody {
  const { signature: _signature, ...body } = handoff;
  return body;
}

function signingBytes(body: AebNativeAuthorizationHandoffBody): Buffer {
  return Buffer.from(
    `${AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN}${canonicalizeStrictJson(body)}`,
    'utf8',
  );
}

function validPrivateKey(value: unknown): value is KeyObject {
  return value instanceof crypto.KeyObject
    && value.type === 'private'
    && value.asymmetricKeyType === 'ed25519';
}

/**
 * Issue a gateway statement for one native PERMIT. The caller supplies the
 * native system's stable authorization identifier. Operation and wrapper IDs
 * are deliberately absent from the replay-unit derivation.
 */
export function issueAebNativeAuthorizationHandoff(
  input: IssueAebNativeAuthorizationHandoffInput,
  signer: AebNativeAuthorizationHandoffSigner,
): AebNativeAuthorizationHandoff {
  if (!validPrivateKey(signer?.private_key) || !identifier(signer?.key_id)) {
    throw new TypeError('valid Ed25519 native authorization gateway signer required');
  }
  const identity = parseNativeIdentity(input?.native_authorization);
  if (!identity) throw new TypeError('valid closed native authorization source required');
  const source = {
    ...identity,
    replay_unit: deriveWireReplayUnitUnchecked(identity),
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
  if (!body) throw new TypeError('valid closed native authorization handoff input required');
  const value = crypto.sign(null, signingBytes(body), signer.private_key).toString('base64url');
  return freezeDeep(canonicalClone({
    ...body,
    signature: { alg: 'Ed25519', key_id: signer.key_id, value },
  }));
}

function emptyChecks(): AebNativeAuthorizationHandoffChecks {
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

function safeRecordDigest(value: unknown): AebNativeAuthorizationDigest {
  try {
    return sha256Domain(AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION, value);
  } catch {
    return sha256Domain(AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION, { invalid_record: true });
  }
}

/**
 * Verify a gateway-signed native-authorization handoff under relying-party
 * pins. This verifies the gateway statement, not the native permit or artifact.
 * `execution_authorizing` reports only whether the statement is usable at this
 * boundary. It is not a fresh policy decision.
 */
export function verifyAebNativeAuthorizationHandoff(
  handoffValue: unknown,
  options: {
    pins: AebNativeAuthorizationPins;
    expected_action: unknown;
    status?: AebNativeAuthorizationStatus;
    now: string;
    mode?: 'execution' | 'historical';
  },
): AebNativeAuthorizationHandoffVerification {
  const modeOption = readOption(options, 'mode');
  const pinsOption = readOption(options, 'pins');
  const actionOption = readOption(options, 'expected_action');
  const statusOption = readOption(options, 'status');
  const nowOption = readOption(options, 'now');
  const optionsReadable = modeOption.ok && pinsOption.ok && actionOption.ok
    && statusOption.ok && nowOption.ok;
  const requestedMode: unknown = modeOption.ok ? modeOption.value : undefined;
  const modeValid = requestedMode === undefined
    || requestedMode === 'execution'
    || requestedMode === 'historical';
  // TypeScript callers cannot name another mode, but this is a public
  // JavaScript verifier and hostile runtime input must still fail closed. Use
  // execution semantics as the safe internal fallback while retaining the
  // explicit invalid-mode reason below.
  const mode: 'execution' | 'historical' = requestedMode === 'historical'
    ? 'historical'
    : 'execution';
  const reasons: string[] = [];
  if (!optionsReadable) reasons.push('native_handoff_options_invalid');
  if (!modeValid) reasons.push('native_handoff_mode_invalid');
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
  if (!checks.schema) reasons.push('native_handoff_schema_invalid');

  let expectedActionDigest: AebNativeAuthorizationDigest | null = null;
  try {
    if (!optionsReadable || !actionOption.ok || containsProxy(actionOption.value)) {
      throw new TypeError('expected action unreadable');
    }
    expectedActionDigest = digestAebNativeAuthorizationAction(actionOption.value);
  } catch {
    reasons.push('native_handoff_expected_action_invalid');
  }

  let key: (AebNativeAuthorizationGatewayKey & { key: KeyObject }) | null = null;
  if (handoff && parsedPins) {
    key = parsedPins.keys.find((candidate) => candidate.gateway_id === handoff.gateway_id
      && candidate.key_id === handoff.signature.key_id) ?? null;
  }
  checks.key_pinned = key !== null;
  if (handoff && !checks.key_pinned) reasons.push('native_handoff_gateway_key_not_pinned');

  if (handoff && key) {
    try {
      checks.signature = crypto.verify(
        null,
        signingBytes(unsigned(handoff)),
        key.key,
        Buffer.from(handoff.signature.value, 'base64url'),
      );
    } catch {
      checks.signature = false;
    }
  }
  if (handoff && !checks.signature) reasons.push('native_handoff_signature_invalid');

  let matchedSource: AebNativeAuthorizationSourcePin | null = null;
  if (handoff && parsedPins) {
    // Pin identities are unique (see parsePins), so at most one pin matches.
    matchedSource = parsedPins.sources.find((source) =>
      source.gateway_id === handoff.gateway_id
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

    if (!checks.source_pinned) reasons.push('native_handoff_source_not_pinned');
    if (!checks.decision) reasons.push('native_handoff_not_permit');
    if (!checks.exact_action) reasons.push('native_handoff_exact_action_mismatch');
    if (!checks.relying_party) reasons.push('native_handoff_relying_party_mismatch');
    if (!checks.audience) reasons.push('native_handoff_audience_mismatch');
    if (!checks.executor) reasons.push('native_handoff_executor_mismatch');
    if (!checks.provider) reasons.push('native_handoff_provider_mismatch');

    const skewMs = parsedPins.pins.clock_skew_seconds * 1000;
    if (mode === 'historical') {
      // Historical verification proves the signed binding only. The Gate's
      // owner-fenced attempt record is what proves that execution-mode checks
      // passed before provider entry.
      checks.freshness = false;
      checks.revocation = false;
    } else {
      const issuedAt = instant(handoff.issued_at);
      const notBefore = instant(handoff.not_before);
      const expiresAt = instant(handoff.expires_at);
      const maxAgeMs = parsedPins.pins.max_handoff_age_seconds * 1000;
      checks.freshness = Number.isFinite(nowMs)
        && nowMs + skewMs >= notBefore
        && nowMs - skewMs < expiresAt
        && issuedAt <= nowMs + skewMs
        && nowMs - issuedAt <= maxAgeMs + skewMs;
      if (!checks.freshness) reasons.push('native_handoff_stale_or_not_current');
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
      if (!status) reasons.push('native_handoff_revocation_status_invalid');
      else if (status.revoked) reasons.push('native_handoff_revoked');
      else if (!checks.revocation) reasons.push('native_handoff_revocation_status_not_current');
    }
  }

  const bindingChecks = Object.entries(checks)
    .filter(([name]) => mode === 'execution' || (name !== 'freshness' && name !== 'revocation'))
    .every(([, passed]) => passed);
  const valid = bindingChecks && reasons.length === 0;
  const frozenHandoff = handoff ? freezeDeep(canonicalClone(handoff)) : null;
  // The label-free replay identity is established only under a pin, and only
  // when the pin set is safe for it: the relying party's namespace (default:
  // the issuer) and the authorization ID. The signed wire replay_unit was
  // checked in parseNativeSource; it and the 4.1.0 replay_key are reported
  // unchanged for compatibility.
  const nativeReplayIdentity = handoff && matchedSource && parsedPins
      && parsedPins.identityRefusal === null
    ? deriveReplayIdentityUnchecked(handoff.native_authorization, matchedSource.authority_namespace)
    : null;
  // Every pinned label in the grant's namespace group, as 4.1.0 keyed it.
  const legacyReplayKeys = handoff && matchedSource && parsedPins && nativeReplayIdentity
    ? namespaceGroupReplayKeys(handoff, matchedSource, parsedPins.sources)
    : null;
  return freezeDeep({
    mode,
    valid,
    execution_authorizing: valid && mode === 'execution',
    reasons: [...new Set(reasons)],
    checks,
    record_digest: recordDigest,
    action_digest: expectedActionDigest,
    native_replay_unit: handoff?.native_authorization.replay_unit ?? null,
    replay_key: handoff
      ? legacyReplayKeyUnchecked(handoff.relying_party_id, handoff.native_authorization.replay_unit)
      : null,
    native_replay_identity: nativeReplayIdentity,
    replay_identity_key: handoff && nativeReplayIdentity
      ? identityReplayKeyUnchecked(handoff.relying_party_id, nativeReplayIdentity)
      : null,
    legacy_replay_keys: legacyReplayKeys,
    handoff: frozenHandoff,
  });
}

export default Object.freeze({
  AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION,
  AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
  AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
  AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
  AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
  digestAebNativeAuthorizationAction,
  deriveAebNativeAuthorizationReplayUnit,
  deriveAebNativeAuthorizationReplayIdentity,
  aebNativeAuthorizationReplayKey,
  aebNativeAuthorizationReplayIdentityKey,
  issueAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationPins,
  verifyAebNativeAuthorizationHandoff,
});
