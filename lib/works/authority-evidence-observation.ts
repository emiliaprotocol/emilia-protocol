// SPDX-License-Identifier: Apache-2.0
//
// Private, source-agnostic evidence envelope for Authority Record preparation.
// This object never grants a favorable public label. A public Authority Record
// still requires owner consent and exact-byte approval through its own schema.

import crypto from 'node:crypto';

import { canonicalize } from '../canonical-json.js';

export const AUTHORITY_EVIDENCE_OBSERVATION_VERSION =
  'EMILIA-AUTHORITY-EVIDENCE-OBSERVATION-v1' as const;
export const AUTHORITY_EVIDENCE_CLAIM_BOUNDARY =
  'private_source_evidence_not_certification_not_safety_score_not_complete_mediation' as const;

export const AUTHORITY_EVIDENCE_SOURCE_KINDS = Object.freeze([
  'repository_state',
  'signed_release',
  'build_provenance',
  'tool_schema',
  'deployment_manifest',
  'runtime_attestation',
  'observed_action_interface',
] as const);

export const AUTHORITY_EVIDENCE_STATUSES = Object.freeze([
  'OBSERVED',
  'SELLER_ASSERTED',
  'UNVERIFIED',
  'UNVERIFIABLE',
  'INDETERMINATE',
] as const);

const OBSERVATION_ID = /^authority-evidence-[a-z0-9][a-z0-9-]{2,95}$/;
const SUBJECT_ID = /^authority-record-[a-z0-9][a-z0-9-]{2,63}$/;
const SURFACE_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/;
const LOCATOR = /^[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s\u0000-\u001f\u007f]{1,1000}$/;

type PlainObject = Record<string, unknown>;

export interface AuthorityEvidenceObservation {
  '@version': typeof AUTHORITY_EVIDENCE_OBSERVATION_VERSION;
  observation_id: string;
  subject_id: string;
  source: {
    kind: (typeof AUTHORITY_EVIDENCE_SOURCE_KINDS)[number];
    locator: string;
    watched_pointer: string;
    resolved_identifier: string | null;
    artifact_digest: string | null;
    observed_at: string;
    expires_at: string;
  };
  collector: {
    name: string;
    version: string;
    profile_digest: string;
  };
  status: (typeof AUTHORITY_EVIDENCE_STATUSES)[number];
  status_reason: string | null;
  surface_ids: string[];
  claim_boundary: typeof AUTHORITY_EVIDENCE_CLAIM_BOUNDARY;
}

export type AuthorityEvidenceError = Readonly<{ ok: false; code: string; detail: string }>;
export type AuthorityEvidenceResult =
  | Readonly<{ ok: true; observation: AuthorityEvidenceObservation }>
  | AuthorityEvidenceError;

export type AuthorityEvidenceResolution =
  | Readonly<{ kind: 'resolved'; identifier: string }>
  | Readonly<{ kind: 'unavailable'; reason: string }>
  | Readonly<{ kind: 'indeterminate'; reason: string }>;

export type AuthorityEvidenceFreshness =
  | Readonly<{ status: 'CURRENT'; observed_identifier: string; current_identifier: string }>
  | Readonly<{ status: 'STALE'; observed_identifier: string; current_identifier: string }>
  | Readonly<{ status: 'EXPIRED' }>
  | Readonly<{ status: 'UNAVAILABLE'; reason: string }>
  | Readonly<{ status: 'INDETERMINATE'; reason: string }>;

function error(code: string, detail: string): AuthorityEvidenceError {
  return Object.freeze({ ok: false, code, detail });
}

function isPlainObject(value: unknown): value is PlainObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: PlainObject, keys: readonly string[]): boolean {
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function exactObject(value: unknown, keys: readonly string[]): value is PlainObject {
  return isPlainObject(value) && hasExactKeys(value, keys);
}

function boundedString(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > max || /[\u0000-\u001f\u007f]/.test(normalized)) {
    return null;
  }
  return normalized;
}

function canonicalInstant(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 40) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function oneOf<T extends readonly string[]>(value: unknown, allowed: T): value is T[number] {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

function normalizeLocator(value: unknown): string | null {
  const locator = boundedString(value, 1024);
  return locator && LOCATOR.test(locator) ? locator : null;
}

export function validateAuthorityEvidenceObservation(input: unknown): AuthorityEvidenceResult {
  const topKeys = [
    '@version', 'observation_id', 'subject_id', 'source', 'collector',
    'status', 'status_reason', 'surface_ids', 'claim_boundary',
  ];
  if (!isPlainObject(input)) {
    return error('authority_evidence_invalid', 'Authority evidence observation must be an object.');
  }
  if (!hasExactKeys(input, topKeys)) {
    return error('authority_evidence_unknown_field', 'Authority evidence contains a field outside the private envelope.');
  }
  if (input['@version'] !== AUTHORITY_EVIDENCE_OBSERVATION_VERSION
      || typeof input.observation_id !== 'string'
      || !OBSERVATION_ID.test(input.observation_id)
      || typeof input.subject_id !== 'string'
      || !SUBJECT_ID.test(input.subject_id)
      || input.claim_boundary !== AUTHORITY_EVIDENCE_CLAIM_BOUNDARY) {
    return error('authority_evidence_invalid', 'Authority evidence envelope is invalid.');
  }

  const sourceKeys = [
    'kind', 'locator', 'watched_pointer', 'resolved_identifier',
    'artifact_digest', 'observed_at', 'expires_at',
  ];
  if (!exactObject(input.source, sourceKeys)) {
    return error(
      isPlainObject(input.source) ? 'authority_evidence_unknown_field' : 'authority_evidence_source_invalid',
      'Authority evidence source is invalid or contains an unknown field.',
    );
  }
  const locator = normalizeLocator(input.source.locator);
  const watchedPointer = boundedString(input.source.watched_pointer, 300);
  const resolvedIdentifier = input.source.resolved_identifier === null
    ? null : boundedString(input.source.resolved_identifier, 300);
  const artifactDigest = input.source.artifact_digest === null
    ? null : typeof input.source.artifact_digest === 'string' && DIGEST.test(input.source.artifact_digest)
      ? input.source.artifact_digest : null;
  if (!oneOf(input.source.kind, AUTHORITY_EVIDENCE_SOURCE_KINDS)
      || !locator
      || !watchedPointer
      || !canonicalInstant(input.source.observed_at)
      || !canonicalInstant(input.source.expires_at)
      || Date.parse(input.source.expires_at) <= Date.parse(input.source.observed_at)
      || Date.parse(input.source.expires_at) - Date.parse(input.source.observed_at) > 93 * 24 * 60 * 60 * 1000
      || (input.source.resolved_identifier !== null && resolvedIdentifier === null)
      || (input.source.artifact_digest !== null && artifactDigest === null)
      || (resolvedIdentifier === null) !== (artifactDigest === null)) {
    return error('authority_evidence_source_invalid', 'Authority evidence source must carry a bounded pointer and consistent immutable evidence identity.');
  }

  const collectorKeys = ['name', 'version', 'profile_digest'];
  if (!exactObject(input.collector, collectorKeys)) {
    return error(
      isPlainObject(input.collector) ? 'authority_evidence_unknown_field' : 'authority_evidence_collector_invalid',
      'Authority evidence collector is invalid or contains an unknown field.',
    );
  }
  const collectorName = boundedString(input.collector.name, 200);
  if (!collectorName
      || typeof input.collector.version !== 'string'
      || !SEMVER.test(input.collector.version)
      || typeof input.collector.profile_digest !== 'string'
      || !DIGEST.test(input.collector.profile_digest)) {
    return error('authority_evidence_collector_invalid', 'Collector identity, version, or profile digest is invalid.');
  }

  if (!oneOf(input.status, AUTHORITY_EVIDENCE_STATUSES)) {
    return error('authority_evidence_status_invalid', 'Authority evidence status is not recognized.');
  }
  const statusReason = input.status_reason === null ? null : boundedString(input.status_reason, 500);
  if ((input.status === 'OBSERVED' && (resolvedIdentifier === null || artifactDigest === null || statusReason !== null))
      || (input.status !== 'OBSERVED' && statusReason === null)) {
    return error('authority_evidence_status_invalid', 'OBSERVED requires immutable evidence; every other status requires an explicit reason.');
  }

  if (!Array.isArray(input.surface_ids) || input.surface_ids.length < 1 || input.surface_ids.length > 64) {
    return error('authority_evidence_surfaces_invalid', 'Authority evidence requires 1-64 surface identifiers.');
  }
  const surfaceIds: string[] = [];
  const seen = new Set<string>();
  for (const raw of input.surface_ids) {
    if (typeof raw !== 'string' || !SURFACE_ID.test(raw) || seen.has(raw)) {
      return error('authority_evidence_surfaces_invalid', 'Authority evidence surface identifiers must be unique and typed.');
    }
    seen.add(raw);
    surfaceIds.push(raw);
  }

  return Object.freeze({
    ok: true,
    observation: Object.freeze({
      '@version': AUTHORITY_EVIDENCE_OBSERVATION_VERSION,
      observation_id: input.observation_id,
      subject_id: input.subject_id,
      source: Object.freeze({
        kind: input.source.kind,
        locator,
        watched_pointer: watchedPointer,
        resolved_identifier: resolvedIdentifier,
        artifact_digest: artifactDigest,
        observed_at: input.source.observed_at,
        expires_at: input.source.expires_at,
      }),
      collector: Object.freeze({
        name: collectorName,
        version: input.collector.version,
        profile_digest: input.collector.profile_digest,
      }),
      status: input.status,
      status_reason: statusReason,
      surface_ids: Object.freeze(surfaceIds) as unknown as string[],
      claim_boundary: AUTHORITY_EVIDENCE_CLAIM_BOUNDARY,
    }),
  });
}

export function authorityEvidenceObservationDigest(observation: AuthorityEvidenceObservation): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(observation), 'utf8').digest('hex')}`;
}

export function evaluateAuthorityEvidenceFreshness(
  observation: AuthorityEvidenceObservation,
  resolution: AuthorityEvidenceResolution,
  now = Date.now(),
): AuthorityEvidenceFreshness {
  if (!Number.isFinite(now) || Date.parse(observation.source.expires_at) <= now) {
    return Object.freeze({ status: 'EXPIRED' });
  }
  if (resolution.kind === 'unavailable') {
    return Object.freeze({ status: 'UNAVAILABLE', reason: resolution.reason });
  }
  if (resolution.kind === 'indeterminate') {
    return Object.freeze({ status: 'INDETERMINATE', reason: resolution.reason });
  }
  if (observation.status !== 'OBSERVED' || observation.source.resolved_identifier === null) {
    return Object.freeze({ status: 'INDETERMINATE', reason: 'observation_not_immutable_and_observed' });
  }
  const currentIdentifier = boundedString(resolution.identifier, 300);
  if (!currentIdentifier) {
    return Object.freeze({ status: 'INDETERMINATE', reason: 'resolved_identifier_invalid' });
  }
  const observedIdentifier = observation.source.resolved_identifier;
  return currentIdentifier === observedIdentifier
    ? Object.freeze({ status: 'CURRENT', observed_identifier: observedIdentifier, current_identifier: currentIdentifier })
    : Object.freeze({ status: 'STALE', observed_identifier: observedIdentifier, current_identifier: currentIdentifier });
}
