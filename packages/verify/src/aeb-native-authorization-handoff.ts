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
import { canonicalizeStrictJson } from './strict-json.js';

type JsonObject = Record<string, unknown>;

export const AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION =
  'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1';
export const AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1\0';
export const AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-REPLAY-v1';
export const AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN =
  'AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1';
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
  /** Stable across wrapper and operation identifiers for this native grant. */
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
  native_replay_unit: AebNativeAuthorizationDigest | null;
  replay_key: string | null;
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

export function deriveAebNativeAuthorizationReplayUnit(
  source: Omit<AebNativeAuthorizationSource, 'replay_unit'>,
): AebNativeAuthorizationDigest {
  if (!parseNativeIdentity(source)) {
    throw new TypeError('valid closed native authorization source required');
  }
  return sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN, source);
}

export function aebNativeAuthorizationReplayKey(
  input: Pick<AebNativeAuthorizationHandoffBody, 'relying_party_id' | 'native_authorization'>,
): string {
  if (!identifier(input?.relying_party_id)
      || !parseNativeSource(input?.native_authorization)) {
    throw new TypeError('valid native authorization replay binding required');
  }
  return `aeb-native:${sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN, {
    relying_party_id: input.relying_party_id,
    replay_unit: input.native_authorization.replay_unit,
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
  value: unknown,
): Omit<AebNativeAuthorizationSource, 'replay_unit'> | null {
  if (!isRecord(value) || !exactKeys(value, NATIVE_IDENTITY_KEYS)
      || !nativeSystem(value.system) || !identifier(value.profile)
      || !identifier(value.issuer) || !identifier(value.authorization_id)) return null;
  return canonicalClone(value) as Omit<AebNativeAuthorizationSource, 'replay_unit'>;
}

function parseNativeSource(value: unknown): AebNativeAuthorizationSource | null {
  if (!isRecord(value) || !exactKeys(value, NATIVE_KEYS)
      || !nativeSystem(value.system) || !identifier(value.profile)
      || !identifier(value.issuer) || !identifier(value.authorization_id)
      || !digest(value.replay_unit)) return null;
  const source = canonicalClone(value) as unknown as AebNativeAuthorizationSource;
  const { replay_unit: _replayUnit, ...identity } = source;
  return deriveReplayUnitUnchecked(identity) === source.replay_unit ? source : null;
}

function deriveReplayUnitUnchecked(
  source: Omit<AebNativeAuthorizationSource, 'replay_unit'>,
): AebNativeAuthorizationDigest {
  return sha256Domain(AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN, source);
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

function parseHandoff(value: unknown): AebNativeAuthorizationHandoff | null {
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
  if (!isRecord(value) || !exactKeys(value, SOURCE_PIN_KEYS)
      || value['@version'] !== AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION
      || !identifier(value.gateway_id) || !nativeSystem(value.system)
      || !identifier(value.profile) || !identifier(value.issuer)) return null;
  return canonicalClone(value) as unknown as AebNativeAuthorizationSourcePin;
}

interface ParsedPins {
  pins: AebNativeAuthorizationPins;
  keys: Array<AebNativeAuthorizationGatewayKey & { key: KeyObject }>;
  sources: AebNativeAuthorizationSourcePin[];
}

function parsePins(value: unknown): ParsedPins | null {
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
      || !Array.isArray(value.accepted_sources) || value.accepted_sources.length === 0) return null;
  const keys = value.gateway_keys.map(parseGatewayKey);
  const sources = value.accepted_sources.map(parseSourcePin);
  if (keys.some((key) => key === null) || sources.some((source) => source === null)) return null;
  const parsedKeys = keys as Array<AebNativeAuthorizationGatewayKey & { key: KeyObject }>;
  const parsedSources = sources as AebNativeAuthorizationSourcePin[];
  if (new Set(parsedKeys.map((key) => `${key.gateway_id}\0${key.key_id}`)).size !== parsedKeys.length
      || new Set(parsedSources.map((source) => canonicalizeStrictJson(source))).size !== parsedSources.length
      || parsedSources.some((source) => !parsedKeys.some((key) => key.gateway_id === source.gateway_id))) {
    return null;
  }
  return {
    pins: canonicalClone(value) as unknown as AebNativeAuthorizationPins,
    keys: parsedKeys,
    sources: parsedSources,
  };
}

function parseStatus(value: unknown): AebNativeAuthorizationStatus | null {
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
  const source = {
    ...input?.native_authorization,
    replay_unit: deriveAebNativeAuthorizationReplayUnit(input?.native_authorization),
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
  const requestedMode: unknown = options?.mode;
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
  if (!modeValid) reasons.push('native_handoff_mode_invalid');
  const checks = emptyChecks();
  const recordDigest = safeRecordDigest(handoffValue);
  const handoff = parseHandoff(handoffValue);
  const parsedPins = parsePins(options?.pins);
  const status = parseStatus(options?.status);
  const nowMs = instant(options?.now);
  checks.schema = handoff !== null && parsedPins !== null && Number.isFinite(nowMs);
  if (!checks.schema) reasons.push('native_handoff_schema_invalid');

  let expectedActionDigest: AebNativeAuthorizationDigest | null = null;
  try {
    expectedActionDigest = digestAebNativeAuthorizationAction(options?.expected_action);
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

  if (handoff && parsedPins) {
    checks.source_pinned = parsedPins.sources.some((source) =>
      source.gateway_id === handoff.gateway_id
      && source.system === handoff.native_authorization.system
      && source.profile === handoff.native_authorization.profile
      && source.issuer === handoff.native_authorization.issuer);
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
  return freezeDeep({
    mode,
    valid,
    execution_authorizing: valid && mode === 'execution',
    reasons: [...new Set(reasons)],
    checks,
    record_digest: recordDigest,
    action_digest: expectedActionDigest,
    native_replay_unit: handoff?.native_authorization.replay_unit ?? null,
    replay_key: handoff ? aebNativeAuthorizationReplayKey(handoff) : null,
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
