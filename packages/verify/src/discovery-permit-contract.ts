// SPDX-License-Identifier: Apache-2.0
/**
 * EP Discovery-to-Permit Continuity contract.
 *
 * Discovery establishes bounded, content-addressed evidence about a configured
 * source. It never authorizes an action. Trust inputs are pinned outside this
 * pure contract by the resolver and are repeated here so adapters can recheck
 * the complete source/action/mapping join.
 */

import crypto, { type KeyObject } from 'node:crypto';

import {
  canonicalizeAeb,
  digestAeb,
  type AebDigest,
  type AebJson,
} from './aeb-adapter-contract.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileSignature,
  type AgilityOptions,
} from './pq-signature-agility.js';

export const DISCOVERY_PERMIT_DISCOVERY_VERSION = 'EP-DISCOVERY-PERMIT-DISCOVERY-v1';
export const DISCOVERY_PERMIT_BINDING_VERSION = 'EP-DISCOVERY-PERMIT-BINDING-v1';
export const DISCOVERY_PERMIT_RESOLUTION_VERSION = 'EP-DISCOVERY-PERMIT-RESOLUTION-v1';
export const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION =
  'EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v1';
export const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_DOMAIN =
  `${DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION}\0`;

export type DiscoveryPermitDigest = AebDigest;
export type DiscoveryPermitJson = AebJson;
export type DiscoveryPermitSourceStatus = 'active' | 'unknown' | 'deprecated';
export type DiscoveryPermitDisposition = 'current' | 'stale' | 'unknown' | 'deprecated';
export type DiscoveryPermitDocumentRole = 'discovery' | 'permit';

export interface DiscoveryPermitSource {
  origin: string;
  discovery_url: string;
  permit_url: string;
}

export interface DiscoveryPermitSchemaDigests {
  discovery: DiscoveryPermitDigest;
  permit_binding: DiscoveryPermitDigest;
}

export interface DiscoveryPermitTrustPinsInput {
  origin: string;
  discovery_url: string;
  permit_url: string;
  discovery_schema_digest: DiscoveryPermitDigest | string;
  permit_schema_digest: DiscoveryPermitDigest | string;
  mapping_digest: DiscoveryPermitDigest | string;
  max_age_seconds: number;
  redirect_map: Record<string, string>;
}

export interface DiscoveryPermitTrustPins {
  readonly origin: string;
  readonly discovery_url: string;
  readonly permit_url: string;
  readonly discovery_schema_digest: DiscoveryPermitDigest;
  readonly permit_schema_digest: DiscoveryPermitDigest;
  readonly mapping_digest: DiscoveryPermitDigest;
  readonly max_age_seconds: number;
  readonly redirect_map: Readonly<Record<string, string>>;
}

export interface DiscoveryPermitDiscoveryDocument {
  '@type': typeof DISCOVERY_PERMIT_DISCOVERY_VERSION;
  source: DiscoveryPermitSource;
  schema_digests: DiscoveryPermitSchemaDigests;
  mapping_digest: DiscoveryPermitDigest;
  status: DiscoveryPermitSourceStatus;
  issued_at: string;
}

export interface DiscoveryPermitBinding {
  '@type': typeof DISCOVERY_PERMIT_BINDING_VERSION;
  source: DiscoveryPermitSource;
  schema_digests: DiscoveryPermitSchemaDigests;
  mapping_digest: DiscoveryPermitDigest;
  status: DiscoveryPermitSourceStatus;
  issued_at: string;
  caid: string;
  action_digest: DiscoveryPermitDigest;
}

export interface DiscoveryPermitDocumentProvenance {
  role: DiscoveryPermitDocumentRole;
  requested_url: string;
  resolved_url: string;
  connected_address: string;
  media_type: 'application/json';
  byte_length: number;
  raw_digest: DiscoveryPermitDigest;
  canonical_digest: DiscoveryPermitDigest;
  redirect_chain: readonly string[];
}

export interface DiscoveryPermitProvenance {
  discovery: DiscoveryPermitDocumentProvenance;
  permit: DiscoveryPermitDocumentProvenance;
}

export interface DiscoveryPermitResolution {
  '@type': typeof DISCOVERY_PERMIT_RESOLUTION_VERSION;
  disposition: DiscoveryPermitDisposition;
  usable_for_permit: boolean;
  /** Discovery evidence is never itself action authorization. */
  authorizes_action: false;
  source: DiscoveryPermitSource;
  schema_digests: DiscoveryPermitSchemaDigests;
  mapping_digest: DiscoveryPermitDigest;
  max_age_seconds: number;
  discovery: DiscoveryPermitDiscoveryDocument;
  binding: DiscoveryPermitBinding;
  age_seconds: number;
  provenance: DiscoveryPermitProvenance;
}

export interface DiscoveryPermitResolverAttestationBody {
  '@type': typeof DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION;
  resolver_id: string;
  evaluated_at: string;
  expires_at: string;
  configuration_digest: DiscoveryPermitDigest;
  caid: string;
  action_digest: DiscoveryPermitDigest;
  source_digest: DiscoveryPermitDigest;
  provenance_digest: DiscoveryPermitDigest;
  resolution_digest: DiscoveryPermitDigest;
  resolution: DiscoveryPermitResolution;
}

export interface DiscoveryPermitResolverAttestation
  extends DiscoveryPermitResolverAttestationBody {
  signature: {
    alg: 'Ed25519';
    key_id: string;
    value: string;
  };
}

export interface DiscoveryPermitResolverAttestationSigner {
  key_id: string;
  private_key: KeyObject;
}

export interface DiscoveryPermitResolverPin {
  resolver_id: string;
  key_id: string;
  public_key: string;
}

export interface SignDiscoveryPermitResolverAttestationOptions {
  resolver_id: string;
  evaluated_at: string;
  expires_at: string;
  configuration_digest: DiscoveryPermitDigest;
  resolution: DiscoveryPermitResolution;
}

export interface EvaluateDiscoveryPermitContinuityOptions {
  pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
  discovery: unknown;
  binding: unknown;
  caid: string;
  action: unknown;
  now: number | string | Date;
  provenance: DiscoveryPermitProvenance;
}

export interface RederiveDiscoveryPermitResolutionOptions {
  pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
  resolution: unknown;
  now: number | string | Date;
}

export class DiscoveryPermitContractError extends Error {
  readonly code: string;

  constructor(code: string, message = code) {
    super(message);
    this.name = 'DiscoveryPermitContractError';
    this.code = code;
  }
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const PIN_KEYS = new Set([
  'origin',
  'discovery_url',
  'permit_url',
  'discovery_schema_digest',
  'permit_schema_digest',
  'mapping_digest',
  'max_age_seconds',
  'redirect_map',
]);
const SOURCE_KEYS = new Set(['origin', 'discovery_url', 'permit_url']);
const SCHEMA_KEYS = new Set(['discovery', 'permit_binding']);
const DISCOVERY_KEYS = new Set([
  '@type',
  'source',
  'schema_digests',
  'mapping_digest',
  'status',
  'issued_at',
]);
const BINDING_KEYS = new Set([
  ...DISCOVERY_KEYS,
  'caid',
  'action_digest',
]);
const PROVENANCE_KEYS = new Set([
  'role',
  'requested_url',
  'resolved_url',
  'connected_address',
  'media_type',
  'byte_length',
  'raw_digest',
  'canonical_digest',
  'redirect_chain',
]);
const RESOLUTION_KEYS = new Set([
  '@type',
  'disposition',
  'usable_for_permit',
  'authorizes_action',
  'source',
  'schema_digests',
  'mapping_digest',
  'max_age_seconds',
  'discovery',
  'binding',
  'age_seconds',
  'provenance',
]);
const RESOLVER_ATTESTATION_KEYS = new Set([
  '@type',
  'resolver_id',
  'evaluated_at',
  'expires_at',
  'configuration_digest',
  'caid',
  'action_digest',
  'source_digest',
  'provenance_digest',
  'resolution_digest',
  'resolution',
  'signature',
]);
const RESOLVER_SIGNATURE_KEYS = new Set(['alg', 'key_id', 'value']);

function fail(code: string, message = code): never {
  throw new DiscoveryPermitContractError(code, message);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: unknown, keys: ReadonlySet<string>): value is Record<string, unknown> {
  if (!isObject(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function isDigest(value: unknown): value is DiscoveryPermitDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function isStatus(value: unknown): value is DiscoveryPermitSourceStatus {
  return value === 'active' || value === 'unknown' || value === 'deprecated';
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string' || !RFC3339_RE.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function exactUrl(value: unknown, code: string): string {
  if (typeof value !== 'string' || value.length === 0) fail(code);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail(code);
  }
  if (parsed.protocol !== 'https:'
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.hash !== ''
    || parsed.href !== value) {
    fail(code);
  }
  return parsed.href;
}

function exactOrigin(value: unknown): string {
  const url = exactUrl(`${String(value)}/`, 'origin_invalid');
  const parsed = new URL(url);
  if (typeof value !== 'string'
    || parsed.origin !== value
    || parsed.pathname !== '/'
    || parsed.search !== '') {
    fail('origin_invalid');
  }
  return parsed.origin;
}

function sourceShape(value: unknown): value is DiscoveryPermitSource {
  if (!hasExactKeys(value, SOURCE_KEYS)) return false;
  if (typeof value.origin !== 'string'
    || typeof value.discovery_url !== 'string'
    || typeof value.permit_url !== 'string') return false;
  try {
    return exactOrigin(value.origin) === value.origin
      && exactUrl(value.discovery_url, 'source_url_invalid') === value.discovery_url
      && exactUrl(value.permit_url, 'source_url_invalid') === value.permit_url;
  } catch {
    return false;
  }
}

function schemaShape(value: unknown): value is DiscoveryPermitSchemaDigests {
  return hasExactKeys(value, SCHEMA_KEYS)
    && isDigest(value.discovery)
    && isDigest(value.permit_binding);
}

function discoveryShape(value: unknown): value is DiscoveryPermitDiscoveryDocument {
  return hasExactKeys(value, DISCOVERY_KEYS)
    && value['@type'] === DISCOVERY_PERMIT_DISCOVERY_VERSION
    && sourceShape(value.source)
    && schemaShape(value.schema_digests)
    && isDigest(value.mapping_digest)
    && isStatus(value.status)
    && Number.isFinite(parseInstant(value.issued_at));
}

function bindingShape(value: unknown): value is DiscoveryPermitBinding {
  return hasExactKeys(value, BINDING_KEYS)
    && value['@type'] === DISCOVERY_PERMIT_BINDING_VERSION
    && sourceShape(value.source)
    && schemaShape(value.schema_digests)
    && isDigest(value.mapping_digest)
    && isStatus(value.status)
    && Number.isFinite(parseInstant(value.issued_at))
    && typeof value.caid === 'string'
    && CAID_RE.test(value.caid)
    && isDigest(value.action_digest);
}

function sameSource(left: DiscoveryPermitSource, right: DiscoveryPermitSource): boolean {
  return left.origin === right.origin
    && left.discovery_url === right.discovery_url
    && left.permit_url === right.permit_url;
}

function sameSchemas(
  left: DiscoveryPermitSchemaDigests,
  right: DiscoveryPermitSchemaDigests,
): boolean {
  return left.discovery === right.discovery
    && left.permit_binding === right.permit_binding;
}

function expectedSource(pins: DiscoveryPermitTrustPins): DiscoveryPermitSource {
  return {
    origin: pins.origin,
    discovery_url: pins.discovery_url,
    permit_url: pins.permit_url,
  };
}

function expectedSchemas(pins: DiscoveryPermitTrustPins): DiscoveryPermitSchemaDigests {
  return {
    discovery: pins.discovery_schema_digest,
    permit_binding: pins.permit_schema_digest,
  };
}

function validateRedirectChain(
  record: DiscoveryPermitDocumentProvenance,
  pins: DiscoveryPermitTrustPins,
): boolean {
  if (record.redirect_chain.length === 0
    || record.redirect_chain[0] !== record.requested_url
    || record.redirect_chain.at(-1) !== record.resolved_url
    || new Set(record.redirect_chain).size !== record.redirect_chain.length
    || record.redirect_chain.length > Object.keys(pins.redirect_map).length + 1) {
    return false;
  }
  for (let index = 0; index < record.redirect_chain.length - 1; index += 1) {
    const current = record.redirect_chain[index];
    const next = record.redirect_chain[index + 1];
    if (pins.redirect_map[current] !== next) return false;
  }
  return true;
}

function provenanceShape(
  value: unknown,
  role: DiscoveryPermitDocumentRole,
): value is DiscoveryPermitDocumentProvenance {
  return hasExactKeys(value, PROVENANCE_KEYS)
    && value.role === role
    && typeof value.requested_url === 'string'
    && typeof value.resolved_url === 'string'
    && typeof value.connected_address === 'string'
    && value.connected_address.length > 0
    && value.media_type === 'application/json'
    && Number.isSafeInteger(value.byte_length)
    && (value.byte_length as number) >= 0
    && isDigest(value.raw_digest)
    && isDigest(value.canonical_digest)
    && Array.isArray(value.redirect_chain)
    && value.redirect_chain.every((url) => typeof url === 'string');
}

function validateProvenance(
  provenance: DiscoveryPermitProvenance,
  discovery: DiscoveryPermitDiscoveryDocument,
  binding: DiscoveryPermitBinding,
  pins: DiscoveryPermitTrustPins,
): void {
  if (!isObject(provenance)
    || Object.keys(provenance).length !== 2
    || !Object.hasOwn(provenance, 'discovery')
    || !Object.hasOwn(provenance, 'permit')
    || !provenanceShape(provenance.discovery, 'discovery')
    || !provenanceShape(provenance.permit, 'permit')) {
    fail('provenance_shape_invalid');
  }
  if (provenance.discovery.requested_url !== pins.discovery_url
    || provenance.permit.requested_url !== pins.permit_url
    || !validateRedirectChain(provenance.discovery, pins)
    || !validateRedirectChain(provenance.permit, pins)) {
    fail('provenance_source_mismatch');
  }
  if (provenance.discovery.canonical_digest !== digestDiscoveryPermit(discovery)
    || provenance.permit.canonical_digest !== digestDiscoveryPermit(binding)) {
    fail('provenance_digest_mismatch');
  }
}

function dispositionFor(
  status: DiscoveryPermitSourceStatus,
  ageSeconds: number,
  maxAgeSeconds: number,
): DiscoveryPermitDisposition {
  if (status === 'unknown') return 'unknown';
  if (status === 'deprecated') return 'deprecated';
  return ageSeconds > maxAgeSeconds ? 'stale' : 'current';
}

/**
 * Snapshot and validate every relying-party trust pin. The returned object has
 * no references to caller-owned maps.
 */
export function pinDiscoveryPermitTrust(
  input: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput,
): DiscoveryPermitTrustPins {
  if (!hasExactKeys(input, PIN_KEYS)) fail('trust_pins_shape_invalid');
  const origin = exactOrigin(input.origin);
  const discoveryUrl = exactUrl(input.discovery_url, 'discovery_url_invalid');
  const permitUrl = exactUrl(input.permit_url, 'permit_url_invalid');
  if (new URL(discoveryUrl).origin !== origin || new URL(permitUrl).origin !== origin) {
    fail('source_url_origin_mismatch');
  }
  if (!isDigest(input.discovery_schema_digest)
    || !isDigest(input.permit_schema_digest)
    || !isDigest(input.mapping_digest)) {
    fail('trust_digest_invalid');
  }
  if (!Number.isSafeInteger(input.max_age_seconds)
    || input.max_age_seconds <= 0
    || input.max_age_seconds > 31_536_000) {
    fail('max_age_invalid');
  }
  if (!isObject(input.redirect_map)) fail('redirect_map_invalid');

  const redirectMap: Record<string, string> = {};
  for (const [rawSource, rawTarget] of Object.entries(input.redirect_map)) {
    const source = exactUrl(rawSource, 'redirect_source_invalid');
    const target = exactUrl(rawTarget, 'redirect_target_invalid');
    if (source === target || Object.hasOwn(redirectMap, source)) fail('redirect_map_invalid');
    redirectMap[source] = target;
  }

  // A finite exact map must not contain cycles. Cycles would make a pinned
  // configuration non-terminating rather than merely stale.
  for (const source of Object.keys(redirectMap)) {
    const seen = new Set<string>();
    let cursor: string | undefined = source;
    while (cursor !== undefined && Object.hasOwn(redirectMap, cursor)) {
      if (seen.has(cursor)) fail('redirect_cycle');
      seen.add(cursor);
      cursor = redirectMap[cursor];
    }
  }

  return deepFreeze({
    origin,
    discovery_url: discoveryUrl,
    permit_url: permitUrl,
    discovery_schema_digest: input.discovery_schema_digest,
    permit_schema_digest: input.permit_schema_digest,
    mapping_digest: input.mapping_digest,
    max_age_seconds: input.max_age_seconds,
    redirect_map: redirectMap,
  });
}

export function canonicalizeDiscoveryPermit(value: unknown): string {
  return canonicalizeAeb(value);
}

export function digestDiscoveryPermit(value: unknown): DiscoveryPermitDigest {
  return digestAeb(value);
}

export function digestDiscoveryPermitRaw(
  raw: string | Uint8Array,
): DiscoveryPermitDigest {
  const bytes = typeof raw === 'string' ? Buffer.from(raw, 'utf8') : raw;
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function deriveDiscoveryPermitResolution(options: {
  pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
  discovery: unknown;
  binding: unknown;
  now: number | string | Date;
  provenance: DiscoveryPermitProvenance;
}): DiscoveryPermitResolution {
  const pins = pinDiscoveryPermitTrust(options.pins);
  if (!discoveryShape(options.discovery)) fail('discovery_shape_invalid');
  if (!bindingShape(options.binding)) fail('binding_shape_invalid');

  const discovery = options.discovery;
  const binding = options.binding;
  const source = expectedSource(pins);
  const schemas = expectedSchemas(pins);

  if (!sameSource(discovery.source, source)
    || !sameSource(binding.source, source)
    || !sameSource(discovery.source, binding.source)
    || discovery.status !== binding.status
    || discovery.issued_at !== binding.issued_at) {
    fail('source_agreement_failed');
  }
  if (!sameSchemas(discovery.schema_digests, schemas)
    || !sameSchemas(binding.schema_digests, schemas)
    || !sameSchemas(discovery.schema_digests, binding.schema_digests)) {
    fail('schema_digest_mismatch');
  }
  if (discovery.mapping_digest !== pins.mapping_digest
    || binding.mapping_digest !== pins.mapping_digest
    || discovery.mapping_digest !== binding.mapping_digest) {
    fail('mapping_digest_mismatch');
  }

  validateProvenance(options.provenance, discovery, binding, pins);

  const now = options.now instanceof Date
    ? options.now.getTime()
    : typeof options.now === 'number'
      ? options.now
      : Date.parse(options.now);
  if (!Number.isFinite(now)) fail('evaluation_time_invalid');
  const issuedAt = parseInstant(discovery.issued_at);
  if (issuedAt > now) fail('issued_at_in_future');
  const ageSeconds = Math.floor((now - issuedAt) / 1000);
  const disposition = dispositionFor(discovery.status, ageSeconds, pins.max_age_seconds);

  return deepFreeze({
    '@type': DISCOVERY_PERMIT_RESOLUTION_VERSION,
    disposition,
    usable_for_permit: disposition === 'current',
    authorizes_action: false,
    source: clone(source),
    schema_digests: clone(schemas),
    mapping_digest: pins.mapping_digest,
    max_age_seconds: pins.max_age_seconds,
    discovery: clone(discovery),
    binding: clone(binding),
    age_seconds: ageSeconds,
    provenance: clone(options.provenance),
  });
}

/**
 * Join the two source documents to constructor pins and the executor-owned
 * CAID/action. This function never returns action authorization.
 */
export function evaluateDiscoveryPermitContinuity(
  options: EvaluateDiscoveryPermitContinuityOptions,
): DiscoveryPermitResolution {
  const resolution = deriveDiscoveryPermitResolution(options);
  if (typeof options.caid !== 'string' || !CAID_RE.test(options.caid)) fail('caid_invalid');
  if (resolution.binding.caid !== options.caid) fail('caid_mismatch');

  let actionDigest: DiscoveryPermitDigest;
  try {
    actionDigest = digestDiscoveryPermit(options.action);
  } catch {
    fail('action_not_canonicalizable');
  }
  if (resolution.binding.action_digest !== actionDigest) fail('action_digest_mismatch');
  return resolution;
}

/**
 * Strict shape and self-consistency check for serialized resolver output.
 * Pin agreement remains the adapter's responsibility.
 */
export function isDiscoveryPermitResolution(
  value: unknown,
): value is DiscoveryPermitResolution {
  if (!hasExactKeys(value, RESOLUTION_KEYS)
    || value['@type'] !== DISCOVERY_PERMIT_RESOLUTION_VERSION
    || !discoveryShape(value.discovery)
    || !bindingShape(value.binding)
    || !sourceShape(value.source)
    || !schemaShape(value.schema_digests)
    || !isDigest(value.mapping_digest)
    || !Number.isSafeInteger(value.max_age_seconds)
    || (value.max_age_seconds as number) <= 0
    || !Number.isSafeInteger(value.age_seconds)
    || (value.age_seconds as number) < 0
    || value.authorizes_action !== false
    || typeof value.usable_for_permit !== 'boolean') {
    return false;
  }

  const disposition = value.disposition;
  if (disposition !== 'current'
    && disposition !== 'stale'
    && disposition !== 'unknown'
    && disposition !== 'deprecated') return false;
  if (!sameSource(value.source, value.discovery.source)
    || !sameSource(value.source, value.binding.source)
    || !sameSchemas(value.schema_digests, value.discovery.schema_digests)
    || !sameSchemas(value.schema_digests, value.binding.schema_digests)
    || value.mapping_digest !== value.discovery.mapping_digest
    || value.mapping_digest !== value.binding.mapping_digest
    || value.discovery.status !== value.binding.status
    || value.discovery.issued_at !== value.binding.issued_at) {
    return false;
  }
  const expectedDisposition = dispositionFor(
    value.discovery.status,
    value.age_seconds as number,
    value.max_age_seconds as number,
  );
  if (disposition !== expectedDisposition
    || value.usable_for_permit !== (disposition === 'current')) return false;

  const provenance = value.provenance;
  if (!isObject(provenance)
    || Object.keys(provenance).length !== 2
    || !provenanceShape(provenance.discovery, 'discovery')
    || !provenanceShape(provenance.permit, 'permit')) return false;
  return provenance.discovery.canonical_digest === digestDiscoveryPermit(value.discovery)
    && provenance.permit.canonical_digest === digestDiscoveryPermit(value.binding);
}

/**
 * Recompute a serialized resolution from the source documents and provenance
 * under relying-party pins. This authenticates no presenter by itself; callers
 * must first verify the resolver attestation that carries the resolution.
 */
export function rederiveDiscoveryPermitResolutionFromPinnedDocuments(
  options: RederiveDiscoveryPermitResolutionOptions,
): DiscoveryPermitResolution {
  if (!isDiscoveryPermitResolution(options.resolution)) fail('resolution_shape_invalid');
  return deriveDiscoveryPermitResolution({
    pins: options.pins,
    discovery: options.resolution.discovery,
    binding: options.resolution.binding,
    now: options.now,
    provenance: options.resolution.provenance,
  });
}

function resolverAttestationBody(
  attestation: DiscoveryPermitResolverAttestation,
): DiscoveryPermitResolverAttestationBody {
  const { signature: _signature, ...body } = attestation;
  return body;
}

function resolverAttestationSigningBytes(
  body: DiscoveryPermitResolverAttestationBody,
): Buffer {
  return Buffer.from(
    `${DISCOVERY_PERMIT_RESOLVER_ATTESTATION_DOMAIN}${canonicalizeDiscoveryPermit(body)}`,
    'utf8',
  );
}

export function isDiscoveryPermitResolverAttestation(
  value: unknown,
): value is DiscoveryPermitResolverAttestation {
  if (!hasExactKeys(value, RESOLVER_ATTESTATION_KEYS)
    || value['@type'] !== DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION
    || typeof value.resolver_id !== 'string'
    || value.resolver_id.length === 0
    || !Number.isFinite(parseInstant(value.evaluated_at))
    || !Number.isFinite(parseInstant(value.expires_at))
    || parseInstant(value.expires_at) <= parseInstant(value.evaluated_at)
    || !isDigest(value.configuration_digest)
    || typeof value.caid !== 'string'
    || !CAID_RE.test(value.caid)
    || !isDigest(value.action_digest)
    || !isDigest(value.source_digest)
    || !isDigest(value.provenance_digest)
    || !isDigest(value.resolution_digest)
    || !isDiscoveryPermitResolution(value.resolution)
    || !hasExactKeys(value.signature, RESOLVER_SIGNATURE_KEYS)
    || value.signature.alg !== 'Ed25519'
    || typeof value.signature.key_id !== 'string'
    || value.signature.key_id.length === 0
    || typeof value.signature.value !== 'string'
    || !/^[A-Za-z0-9_-]+$/.test(value.signature.value)) {
    return false;
  }
  return true;
}

/**
 * Produce a domain-separated Ed25519 resolver statement over the exact
 * resolution body and every relying-party-relevant join digest.
 */
export function signDiscoveryPermitResolverAttestation(
  options: SignDiscoveryPermitResolverAttestationOptions,
  signer: DiscoveryPermitResolverAttestationSigner,
): DiscoveryPermitResolverAttestation {
  if (typeof options?.resolver_id !== 'string' || options.resolver_id.length === 0) {
    fail('resolver_id_invalid');
  }
  if (!isDigest(options.configuration_digest)) fail('configuration_digest_invalid');
  if (!isDiscoveryPermitResolution(options.resolution)) fail('resolution_shape_invalid');
  if (typeof signer?.key_id !== 'string'
    || signer.key_id.length === 0
    || !(signer.private_key instanceof crypto.KeyObject)
    || signer.private_key.type !== 'private'
    || signer.private_key.asymmetricKeyType !== 'ed25519') {
    fail('resolver_signer_invalid');
  }

  const evaluatedAt = parseInstant(options.evaluated_at);
  const expiresAt = parseInstant(options.expires_at);
  const issuedAt = parseInstant(options.resolution.discovery.issued_at);
  if (!Number.isFinite(evaluatedAt)
    || !Number.isFinite(expiresAt)
    || expiresAt <= evaluatedAt
    || issuedAt > evaluatedAt
    || Math.floor((evaluatedAt - issuedAt) / 1000) !== options.resolution.age_seconds) {
    fail('resolver_attestation_evaluation_mismatch');
  }

  const resolution = clone(options.resolution);
  const body: DiscoveryPermitResolverAttestationBody = {
    '@type': DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION,
    resolver_id: options.resolver_id,
    evaluated_at: options.evaluated_at,
    expires_at: options.expires_at,
    configuration_digest: options.configuration_digest,
    caid: resolution.binding.caid,
    action_digest: resolution.binding.action_digest,
    source_digest: digestDiscoveryPermit(resolution.source),
    provenance_digest: digestDiscoveryPermit(resolution.provenance),
    resolution_digest: digestDiscoveryPermit(resolution),
    resolution,
  };
  const signature = crypto.sign(
    null,
    resolverAttestationSigningBytes(body),
    signer.private_key,
  ).toString('base64url');
  return deepFreeze({
    ...body,
    signature: {
      alg: 'Ed25519',
      key_id: signer.key_id,
      value: signature,
    },
  });
}

export function verifyDiscoveryPermitResolverAttestationSignature(
  attestation: unknown,
  pin: DiscoveryPermitResolverPin,
): attestation is DiscoveryPermitResolverAttestation {
  if (!isDiscoveryPermitResolverAttestation(attestation)
    || typeof pin?.resolver_id !== 'string'
    || pin.resolver_id !== attestation.resolver_id
    || typeof pin.key_id !== 'string'
    || pin.key_id !== attestation.signature.key_id
    || typeof pin.public_key !== 'string'
    || pin.public_key.length === 0) {
    return false;
  }
  try {
    const publicKey = crypto.createPublicKey(pin.public_key);
    if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') return false;
    const signature = Buffer.from(attestation.signature.value, 'base64url');
    if (signature.length !== 64
      || signature.toString('base64url') !== attestation.signature.value) return false;
    return crypto.verify(
      null,
      resolverAttestationSigningBytes(resolverAttestationBody(attestation)),
      publicKey,
      signature,
    );
  } catch {
    return false;
  }
}

// ===========================================================================
// EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v2 -- hybrid (Ed25519 + ML-DSA-65)
// ===========================================================================
/**
 * Reference hybrid migration for this surface. Copies the five moves from
 * EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP. `@type` moves EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v1
 *    -> -v2. isDiscoveryPermitResolverAttestation / verify...Signature above
 *    are UNCHANGED; a v2 attestation fails the v1 shape check on `@type`
 *    before any signature is inspected.
 * 2. SET SHAPE. The single `signature` field is replaced by `signatures`, an
 *    array of exactly the two AgileSignature entries ({alg, sig, key_id}) for
 *    Ed25519 and ML-DSA-65, reusing EP-SIG-AGILITY-v1's shape verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is a BODY field (inside the
 *    signed bytes), independently recomputed by the verifier from the
 *    registered set.
 * 4. V1 COMPATIBILITY. v1 attestations keep verifying, unchanged, through the
 *    sync functions above. v2 verification is a separate ASYNC entry point;
 *    verifyDiscoveryPermitResolverAttestationStatement routes on `@type`.
 * 5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *    is 'pq_backend_unavailable' from the agility module, never a pass on the
 *    Ed25519 leg alone.
 */

export const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION =
  'EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v2';
export const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_DOMAIN =
  `${DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION}\0`;
/** The registered required algorithm set, in canonical order. */
export const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS =
  Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const RESOLVER_ATTESTATION_V2_BODY_KEYS = new Set([
  '@type', 'resolver_id', 'evaluated_at', 'expires_at', 'configuration_digest',
  'caid', 'action_digest', 'source_digest', 'provenance_digest',
  'resolution_digest', 'resolution', 'required_algorithms',
]);
const RESOLVER_ATTESTATION_V2_KEYS = new Set([...RESOLVER_ATTESTATION_V2_BODY_KEYS, 'signatures']);

export interface DiscoveryPermitResolverAttestationV2Body
  extends Omit<DiscoveryPermitResolverAttestationBody, '@type'> {
  '@type': typeof DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION;
  required_algorithms: readonly string[];
}

export interface DiscoveryPermitResolverAttestationV2
  extends Omit<DiscoveryPermitResolverAttestationV2Body, '@type'> {
  '@type': typeof DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION;
  signatures: readonly AgileSignature[];
}

export interface DiscoveryPermitResolverAttestationV2Signer {
  key_id: string;
  private_key: KeyObject;
  pq_key_id: string;
  /** ML-DSA-65 secret key: raw bytes or base64url, 4032 bytes. */
  pq_private_key: Uint8Array | string;
}

export interface DiscoveryPermitResolverV2Pin {
  resolver_id: string;
  key_id: string;
  public_key: string;
  pq_key_id: string;
  /** ML-DSA-65: base64url of the raw 1952-byte public key. */
  pq_public_key: string;
}

function algorithmSetMatchesRegisteredDPR(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS[i]);
}

function resolverAttestationV2SigningBytes(body: DiscoveryPermitResolverAttestationV2Body): Buffer {
  return Buffer.from(
    `${DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_DOMAIN}${canonicalizeDiscoveryPermit(body)}`,
    'utf8',
  );
}

export function isDiscoveryPermitResolverAttestationV2(
  value: unknown,
): value is DiscoveryPermitResolverAttestationV2 {
  if (!hasExactKeys(value, RESOLVER_ATTESTATION_V2_KEYS)
    || value['@type'] !== DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION
    || typeof value.resolver_id !== 'string'
    || value.resolver_id.length === 0
    || !Number.isFinite(parseInstant(value.evaluated_at))
    || !Number.isFinite(parseInstant(value.expires_at))
    || parseInstant(value.expires_at) <= parseInstant(value.evaluated_at)
    || !isDigest(value.configuration_digest)
    || typeof value.caid !== 'string'
    || !CAID_RE.test(value.caid)
    || !isDigest(value.action_digest)
    || !isDigest(value.source_digest)
    || !isDigest(value.provenance_digest)
    || !isDigest(value.resolution_digest)
    || !isDiscoveryPermitResolution(value.resolution)
    || !algorithmSetMatchesRegisteredDPR(value.required_algorithms)
    || !Array.isArray(value.signatures)
    || value.signatures.length !== 2) {
    return false;
  }
  const seen = new Set<string>();
  for (const sig of value.signatures) {
    if (!isObject(sig) || typeof sig.alg !== 'string' || typeof sig.sig !== 'string'
      || typeof sig.key_id !== 'string' || sig.key_id.length === 0
      || seen.has(sig.alg)) return false;
    seen.add(sig.alg);
  }
  return DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS.every((alg) => seen.has(alg));
}

/**
 * Produce a domain-separated hybrid resolver statement (Ed25519 + ML-DSA-65)
 * over the exact resolution body and every relying-party-relevant join digest.
 */
export async function signDiscoveryPermitResolverAttestationV2(
  options: SignDiscoveryPermitResolverAttestationOptions,
  signer: DiscoveryPermitResolverAttestationV2Signer,
): Promise<DiscoveryPermitResolverAttestationV2> {
  if (typeof options?.resolver_id !== 'string' || options.resolver_id.length === 0) {
    fail('resolver_id_invalid');
  }
  if (!isDigest(options.configuration_digest)) fail('configuration_digest_invalid');
  if (!isDiscoveryPermitResolution(options.resolution)) fail('resolution_shape_invalid');
  if (typeof signer?.key_id !== 'string'
    || signer.key_id.length === 0
    || !(signer.private_key instanceof crypto.KeyObject)
    || signer.private_key.type !== 'private'
    || signer.private_key.asymmetricKeyType !== 'ed25519'
    || typeof signer.pq_key_id !== 'string'
    || signer.pq_key_id.length === 0) {
    fail('resolver_signer_invalid');
  }

  const evaluatedAt = parseInstant(options.evaluated_at);
  const expiresAt = parseInstant(options.expires_at);
  const issuedAt = parseInstant(options.resolution.discovery.issued_at);
  if (!Number.isFinite(evaluatedAt)
    || !Number.isFinite(expiresAt)
    || expiresAt <= evaluatedAt
    || issuedAt > evaluatedAt
    || Math.floor((evaluatedAt - issuedAt) / 1000) !== options.resolution.age_seconds) {
    fail('resolver_attestation_evaluation_mismatch');
  }

  const resolution = clone(options.resolution);
  const body: DiscoveryPermitResolverAttestationV2Body = {
    '@type': DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION,
    resolver_id: options.resolver_id,
    evaluated_at: options.evaluated_at,
    expires_at: options.expires_at,
    configuration_digest: options.configuration_digest,
    caid: resolution.binding.caid,
    action_digest: resolution.binding.action_digest,
    source_digest: digestDiscoveryPermit(resolution.source),
    provenance_digest: digestDiscoveryPermit(resolution.provenance),
    resolution_digest: digestDiscoveryPermit(resolution),
    resolution,
    required_algorithms: [...DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS],
  };
  const bytes = resolverAttestationV2SigningBytes(body);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: signer.private_key, key_id: signer.key_id },
    { alg: 'ML-DSA-65', private_key: signer.pq_private_key, key_id: signer.pq_key_id },
  ]);
  return deepFreeze({
    ...body,
    signatures,
  });
}

/**
 * Verify a hybrid resolver attestation. Async because ML-DSA-65 verification
 * is async; a v2 attestation never verifies on one leg alone (FAIL-CLOSED).
 */
export async function verifyDiscoveryPermitResolverAttestationSignatureV2(
  attestation: unknown,
  pin: DiscoveryPermitResolverV2Pin,
  options: AgilityOptions = {},
): Promise<boolean> {
  if (!isDiscoveryPermitResolverAttestationV2(attestation)
    || typeof pin?.resolver_id !== 'string'
    || pin.resolver_id !== attestation.resolver_id
    || typeof pin.key_id !== 'string'
    || typeof pin.pq_key_id !== 'string'
    || typeof pin.public_key !== 'string' || pin.public_key.length === 0
    || typeof pin.pq_public_key !== 'string' || pin.pq_public_key.length === 0) {
    return false;
  }
  const { signatures: _signatures, ...body } = attestation as DiscoveryPermitResolverAttestationV2;
  const bytes = resolverAttestationV2SigningBytes(body as DiscoveryPermitResolverAttestationV2Body);
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(bytes),
      attestation.signatures,
      [
        { alg: 'Ed25519', public_key: pin.public_key, key_id: pin.key_id },
        { alg: 'ML-DSA-65', public_key: pin.pq_public_key, key_id: pin.pq_key_id },
      ],
      {
        ...options,
        policy: 'hybrid_all',
        requiredAlgorithms: [...DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS],
      },
    );
  } catch {
    return false;
  }
  if (setResult.verified !== true) return false;
  // key_id binding: each leg's presented key_id must match the pin exactly,
  // the same discipline verifyAgileSignatureSet leaves to the caller.
  const byAlg = new Map(attestation.signatures.map((s) => [s.alg, s]));
  return byAlg.get('Ed25519')?.key_id === pin.key_id
    && byAlg.get('ML-DSA-65')?.key_id === pin.pq_key_id;
}

/**
 * Route an attestation of EITHER version to its verifier. An `@type` naming
 * neither version refuses through the v1 shape check, which is fail-closed.
 */
export async function verifyDiscoveryPermitResolverAttestationStatement(
  attestation: unknown,
  pin: DiscoveryPermitResolverPin | DiscoveryPermitResolverV2Pin,
  options: AgilityOptions = {},
): Promise<boolean> {
  if (isObject(attestation) && attestation['@type'] === DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION) {
    return verifyDiscoveryPermitResolverAttestationSignatureV2(
      attestation,
      pin as DiscoveryPermitResolverV2Pin,
      options,
    );
  }
  return verifyDiscoveryPermitResolverAttestationSignature(attestation, pin as DiscoveryPermitResolverPin);
}
