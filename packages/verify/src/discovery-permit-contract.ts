// SPDX-License-Identifier: Apache-2.0
/**
 * EP Discovery-to-Permit Continuity contract.
 *
 * Discovery establishes bounded, content-addressed evidence about a configured
 * source. It never authorizes an action. Trust inputs are pinned outside this
 * pure contract by the resolver and are repeated here so adapters can recheck
 * the complete source/action/mapping join.
 */

import crypto from 'node:crypto';

import {
  canonicalizeAeb,
  digestAeb,
  type AebDigest,
  type AebJson,
} from './aeb-adapter-contract.js';

export const DISCOVERY_PERMIT_DISCOVERY_VERSION = 'EP-DISCOVERY-PERMIT-DISCOVERY-v1';
export const DISCOVERY_PERMIT_BINDING_VERSION = 'EP-DISCOVERY-PERMIT-BINDING-v1';
export const DISCOVERY_PERMIT_RESOLUTION_VERSION = 'EP-DISCOVERY-PERMIT-RESOLUTION-v1';

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

export interface EvaluateDiscoveryPermitContinuityOptions {
  pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
  discovery: unknown;
  binding: unknown;
  caid: string;
  action: unknown;
  now: number | string | Date;
  provenance: DiscoveryPermitProvenance;
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

/**
 * Join the two source documents to constructor pins and the executor-owned
 * CAID/action. This function never returns action authorization.
 */
export function evaluateDiscoveryPermitContinuity(
  options: EvaluateDiscoveryPermitContinuityOptions,
): DiscoveryPermitResolution {
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
  if (typeof options.caid !== 'string' || !CAID_RE.test(options.caid)) fail('caid_invalid');
  if (binding.caid !== options.caid) fail('caid_mismatch');

  let actionDigest: DiscoveryPermitDigest;
  try {
    actionDigest = digestDiscoveryPermit(options.action);
  } catch {
    fail('action_not_canonicalizable');
  }
  if (binding.action_digest !== actionDigest) fail('action_digest_mismatch');

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
