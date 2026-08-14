// SPDX-License-Identifier: Apache-2.0
//
// Closed public projection for an EMILIA Marketplace Authority Record.
// Raw scanner output never crosses this boundary. The public object contains
// only a version-pinned source, typed authority surfaces, and an optional
// statement supplied by the repository owner.

import crypto from 'node:crypto';

import { canonicalize } from '../canonical-json.js';

export const AUTHORITY_RECORD_VERSION = 'EMILIA-AUTHORITY-RECORD-v1' as const;
export const AUTHORITY_RECORD_CLAIM_BOUNDARY =
  'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation' as const;

const RECORD_ID = /^authority-record-[a-z0-9][a-z0-9-]{2,63}$/;
const SURFACE_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const WATCHED_REF = /^refs\/(?:heads|tags)\/[A-Za-z0-9._/-]{1,240}$/;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/;
const CLAIM_CHALLENGE = /^claim_[A-Za-z0-9_-]{32,96}$/;

export const ACTION_CLASSES = Object.freeze([
  'code_change',
  'deployment',
  'financial_transaction',
  'data_mutation',
  'permission_change',
  'infrastructure_change',
  'machine_command',
  'physical_action',
  'communication',
  'other',
] as const);

export const CONSEQUENCE_CLASSES = Object.freeze([
  'money', 'code', 'data', 'permissions', 'infrastructure', 'machines', 'matter', 'other',
] as const);

export const EVIDENCE_STATUSES = Object.freeze([
  'OBSERVED', 'SELLER_ASSERTED', 'UNVERIFIED', 'INDETERMINATE',
] as const);

export const ENFORCEMENT_STATUSES = Object.freeze([
  'NOT_ASSESSED', 'DECLARED', 'OBSERVED', 'OWNER_CONFIRMED', 'INDETERMINATE',
] as const);

export interface AuthoritySurface {
  surface_id: string;
  label: string;
  action_class: (typeof ACTION_CLASSES)[number];
  consequence_class: (typeof CONSEQUENCE_CLASSES)[number];
  evidence_status: (typeof EVIDENCE_STATUSES)[number];
  enforcement_status: (typeof ENFORCEMENT_STATUSES)[number];
}

export interface AuthorityRecordProjection {
  '@version': typeof AUTHORITY_RECORD_VERSION;
  record_id: string;
  subject: {
    name: string;
    builder_name: string;
    repository_url: string;
  };
  provenance: {
    source_locator: string;
    watched_ref: string;
    resolved_revision: string;
    artifact_digest: string;
    observed_at: string;
    expires_at: string;
    scanner: {
      name: '@emilia-protocol/scan';
      version: string;
      profile_digest: string;
    };
  };
  surfaces: AuthoritySurface[];
  owner_statement: null | {
    status: 'SELLER_ASSERTED';
    statement: string;
  };
  claim_boundary: typeof AUTHORITY_RECORD_CLAIM_BOUNDARY;
}

export type AuthorityRecordError = Readonly<{ ok: false; code: string; detail: string }>;
export type AuthorityRecordResult =
  | Readonly<{ ok: true; record: AuthorityRecordProjection }>
  | AuthorityRecordError;

type PlainObject = Record<string, unknown>;

function err(code: string, detail: string): AuthorityRecordError {
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

function requireExactKeys(value: unknown, keys: readonly string[]): value is PlainObject {
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

export function normalizeGitHubRepositoryUrl(value: unknown): string | null {
  const source = boundedString(value, 300);
  if (!source) return null;
  let parsed: URL;
  try {
    parsed = new URL(source);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:'
      || parsed.hostname.toLowerCase() !== 'github.com'
      || parsed.username || parsed.password || parsed.search || parsed.hash) return null;
  const parts = parsed.pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  if (parts.length !== 2) return null;
  const [owner, rawRepo] = parts;
  const repository = rawRepo.replace(/\.git$/i, '');
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)
      || !/^[A-Za-z0-9._-]{1,100}$/.test(repository)) return null;
  return `https://github.com/${owner}/${repository}`;
}

function unknownField(value: unknown, keys: readonly string[]): boolean {
  return isPlainObject(value) && !hasExactKeys(value, keys);
}

export function validateAuthorityRecordProjection(input: unknown): AuthorityRecordResult {
  const topKeys = ['@version', 'record_id', 'subject', 'provenance', 'surfaces', 'owner_statement', 'claim_boundary'];
  if (!isPlainObject(input)) return err('authority_record_invalid', 'Authority Record must be an object.');
  if (unknownField(input, topKeys)) {
    return err('authority_record_unknown_field', 'Authority Record contains a field outside the public projection.');
  }
  if (!requireExactKeys(input, topKeys)
      || input['@version'] !== AUTHORITY_RECORD_VERSION
      || typeof input.record_id !== 'string'
      || !RECORD_ID.test(input.record_id)
      || input.claim_boundary !== AUTHORITY_RECORD_CLAIM_BOUNDARY) {
    return err('authority_record_invalid', 'Authority Record envelope is invalid.');
  }

  const subjectKeys = ['name', 'builder_name', 'repository_url'];
  if (!isPlainObject(input.subject)) return err('authority_record_subject_invalid', 'Subject is invalid.');
  if (unknownField(input.subject, subjectKeys)) {
    return err('authority_record_unknown_field', 'Subject contains a field outside the public projection.');
  }
  if (!requireExactKeys(input.subject, subjectKeys)) {
    return err('authority_record_subject_invalid', 'Subject is incomplete.');
  }
  const name = boundedString(input.subject.name, 200);
  const builderName = boundedString(input.subject.builder_name, 200);
  const repositoryUrl = normalizeGitHubRepositoryUrl(input.subject.repository_url);
  if (!name || !builderName || !repositoryUrl) {
    return err('authority_record_subject_invalid', 'Subject requires names and a canonical GitHub repository URL.');
  }

  const provenanceKeys = [
    'source_locator', 'watched_ref', 'resolved_revision', 'artifact_digest',
    'observed_at', 'expires_at', 'scanner',
  ];
  if (!isPlainObject(input.provenance)) {
    return err('authority_record_provenance_invalid', 'Provenance is invalid.');
  }
  if (unknownField(input.provenance, provenanceKeys)) {
    return err('authority_record_unknown_field', 'Provenance contains a field outside the public projection.');
  }
  if (!requireExactKeys(input.provenance, provenanceKeys)) {
    return err('authority_record_provenance_invalid', 'Provenance is incomplete.');
  }
  const sourceLocator = normalizeGitHubRepositoryUrl(input.provenance.source_locator);
  if (!sourceLocator || sourceLocator !== repositoryUrl
      || typeof input.provenance.watched_ref !== 'string'
      || !WATCHED_REF.test(input.provenance.watched_ref)
      || typeof input.provenance.resolved_revision !== 'string'
      || !REVISION.test(input.provenance.resolved_revision)
      || typeof input.provenance.artifact_digest !== 'string'
      || !DIGEST.test(input.provenance.artifact_digest)
      || !canonicalInstant(input.provenance.observed_at)
      || !canonicalInstant(input.provenance.expires_at)
      || Date.parse(input.provenance.expires_at) <= Date.parse(input.provenance.observed_at)
      || Date.parse(input.provenance.expires_at) - Date.parse(input.provenance.observed_at) > 93 * 24 * 60 * 60 * 1000) {
    return err('authority_record_provenance_invalid', 'Provenance must pin one source, ref, revision, digest, and bounded validity window.');
  }

  const scannerKeys = ['name', 'version', 'profile_digest'];
  if (!isPlainObject(input.provenance.scanner)) {
    return err('authority_record_scanner_invalid', 'Scanner provenance is invalid.');
  }
  if (unknownField(input.provenance.scanner, scannerKeys)) {
    return err('authority_record_unknown_field', 'Scanner provenance contains an unknown field.');
  }
  if (!requireExactKeys(input.provenance.scanner, scannerKeys)
      || input.provenance.scanner.name !== '@emilia-protocol/scan'
      || typeof input.provenance.scanner.version !== 'string'
      || !SEMVER.test(input.provenance.scanner.version)
      || typeof input.provenance.scanner.profile_digest !== 'string'
      || !DIGEST.test(input.provenance.scanner.profile_digest)) {
    return err('authority_record_scanner_invalid', 'Scanner name, version, or profile digest is invalid.');
  }

  if (!Array.isArray(input.surfaces) || input.surfaces.length < 1 || input.surfaces.length > 64) {
    return err('authority_record_surfaces_invalid', 'Authority Record requires 1-64 typed surfaces.');
  }
  const surfaceKeys = [
    'surface_id', 'label', 'action_class', 'consequence_class',
    'evidence_status', 'enforcement_status',
  ];
  const surfaces: AuthoritySurface[] = [];
  const surfaceIds = new Set<string>();
  for (const raw of input.surfaces) {
    if (!isPlainObject(raw)) return err('authority_record_surfaces_invalid', 'Each authority surface must be an object.');
    if (unknownField(raw, surfaceKeys)) {
      return err('authority_record_unknown_field', 'Authority surface contains a field outside the public projection.');
    }
    if (!requireExactKeys(raw, surfaceKeys)) {
      return err('authority_record_surfaces_invalid', 'Authority surface is incomplete.');
    }
    const surfaceId = typeof raw.surface_id === 'string' && SURFACE_ID.test(raw.surface_id)
      ? raw.surface_id : null;
    const label = boundedString(raw.label, 160);
    if (!surfaceId || surfaceIds.has(surfaceId) || !label
        || !oneOf(raw.action_class, ACTION_CLASSES)
        || !oneOf(raw.consequence_class, CONSEQUENCE_CLASSES)
        || !oneOf(raw.evidence_status, EVIDENCE_STATUSES)
        || !oneOf(raw.enforcement_status, ENFORCEMENT_STATUSES)) {
      return err('authority_record_surfaces_invalid', 'Authority surface labels, statuses, or identifiers are invalid.');
    }
    surfaceIds.add(surfaceId);
    surfaces.push({
      surface_id: surfaceId,
      label,
      action_class: raw.action_class,
      consequence_class: raw.consequence_class,
      evidence_status: raw.evidence_status,
      enforcement_status: raw.enforcement_status,
    });
  }

  let ownerStatement: AuthorityRecordProjection['owner_statement'] = null;
  if (input.owner_statement !== null) {
    const ownerKeys = ['status', 'statement'];
    if (!isPlainObject(input.owner_statement)) {
      return err('authority_record_owner_statement_invalid', 'Owner statement is invalid.');
    }
    if (unknownField(input.owner_statement, ownerKeys)) {
      return err('authority_record_unknown_field', 'Owner statement contains an unknown field.');
    }
    const statement = boundedString(input.owner_statement.statement, 1000);
    if (!requireExactKeys(input.owner_statement, ownerKeys)
        || input.owner_statement.status !== 'SELLER_ASSERTED'
        || !statement) {
      return err('authority_record_owner_statement_invalid', 'Owner statement must be explicitly seller-asserted.');
    }
    ownerStatement = { status: 'SELLER_ASSERTED', statement };
  }

  return Object.freeze({
    ok: true,
    record: Object.freeze({
      '@version': AUTHORITY_RECORD_VERSION,
      record_id: input.record_id,
      subject: Object.freeze({ name, builder_name: builderName, repository_url: repositoryUrl }),
      provenance: Object.freeze({
        source_locator: sourceLocator,
        watched_ref: input.provenance.watched_ref,
        resolved_revision: input.provenance.resolved_revision,
        artifact_digest: input.provenance.artifact_digest,
        observed_at: input.provenance.observed_at,
        expires_at: input.provenance.expires_at,
        scanner: Object.freeze({
          name: '@emilia-protocol/scan',
          version: input.provenance.scanner.version,
          profile_digest: input.provenance.scanner.profile_digest,
        }),
      }),
      surfaces: Object.freeze(surfaces.map((surface) => Object.freeze(surface))) as unknown as AuthoritySurface[],
      owner_statement: ownerStatement === null ? null : Object.freeze(ownerStatement),
      claim_boundary: AUTHORITY_RECORD_CLAIM_BOUNDARY,
    }),
  });
}

export function authorityRecordDigest(record: AuthorityRecordProjection): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(record), 'utf8').digest('hex')}`;
}

export type RefResolution =
  | Readonly<{ kind: 'resolved'; revision: string }>
  | Readonly<{ kind: 'unavailable'; reason: string }>
  | Readonly<{ kind: 'indeterminate'; reason: string }>;

export type AuthorityRecordFreshness =
  | Readonly<{ status: 'CURRENT'; observed_revision: string; current_revision: string }>
  | Readonly<{ status: 'STALE'; observed_revision: string; current_revision: string }>
  | Readonly<{ status: 'EXPIRED' }>
  | Readonly<{ status: 'UNAVAILABLE'; reason: string }>
  | Readonly<{ status: 'INDETERMINATE'; reason: string }>;

export function evaluateAuthorityRecordFreshness(
  record: AuthorityRecordProjection,
  resolution: RefResolution,
  now = Date.now(),
): AuthorityRecordFreshness {
  if (!Number.isFinite(now) || Date.parse(record.provenance.expires_at) <= now) {
    return Object.freeze({ status: 'EXPIRED' });
  }
  if (resolution.kind === 'unavailable') {
    return Object.freeze({ status: 'UNAVAILABLE', reason: resolution.reason });
  }
  if (resolution.kind === 'indeterminate') {
    return Object.freeze({ status: 'INDETERMINATE', reason: resolution.reason });
  }
  if (!REVISION.test(resolution.revision)) {
    return Object.freeze({ status: 'INDETERMINATE', reason: 'resolved_revision_invalid' });
  }
  const observed = record.provenance.resolved_revision;
  return resolution.revision === observed
    ? Object.freeze({ status: 'CURRENT', observed_revision: observed, current_revision: resolution.revision })
    : Object.freeze({ status: 'STALE', observed_revision: observed, current_revision: resolution.revision });
}

export interface AuthorityClaimProof {
  '@version': 'EMILIA-AUTHORITY-RECORD-CLAIM-v1';
  challenge: string;
  record_digest: string;
  repository_url: string;
  expires_at: string;
}

export function buildAuthorityClaimProof(input: {
  challenge: string;
  recordDigest: string;
  repositoryUrl: string;
  expiresAt: string;
}): AuthorityClaimProof {
  const repositoryUrl = normalizeGitHubRepositoryUrl(input.repositoryUrl);
  if (!CLAIM_CHALLENGE.test(input.challenge)
      || !DIGEST.test(input.recordDigest)
      || !repositoryUrl
      || !canonicalInstant(input.expiresAt)) {
    throw new TypeError('Authority Record claim proof input is invalid.');
  }
  return Object.freeze({
    '@version': 'EMILIA-AUTHORITY-RECORD-CLAIM-v1',
    challenge: input.challenge,
    record_digest: input.recordDigest,
    repository_url: repositoryUrl,
    expires_at: input.expiresAt,
  });
}

export function validateAuthorityClaimProof(
  input: unknown,
  expected: {
    challenge: string;
    recordDigest: string;
    repositoryUrl: string;
    now?: number;
  },
): Readonly<{ ok: true }> | AuthorityRecordError {
  const keys = ['@version', 'challenge', 'record_digest', 'repository_url', 'expires_at'];
  if (!requireExactKeys(input, keys)
      || input['@version'] !== 'EMILIA-AUTHORITY-RECORD-CLAIM-v1'
      || input.challenge !== expected.challenge
      || input.record_digest !== expected.recordDigest
      || normalizeGitHubRepositoryUrl(input.repository_url) !== normalizeGitHubRepositoryUrl(expected.repositoryUrl)
      || !canonicalInstant(input.expires_at)
      || Date.parse(input.expires_at) <= (expected.now ?? Date.now())) {
    return err('authority_record_claim_proof_invalid', 'Repository-control proof does not match the invitation.');
  }
  return Object.freeze({ ok: true });
}
