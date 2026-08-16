// SPDX-License-Identifier: Apache-2.0
//
// Consent-first Authority Record lifecycle. EMILIA may prepare a private
// public-source draft, but only repository control plus an explicit exact-byte
// owner approval can make that record public.

import crypto from 'node:crypto';

import {
  authorityRecordDigest,
  buildAuthorityClaimProof,
  normalizeGitHubRepositoryUrl,
  validateAuthorityClaimProof,
  validateAuthorityRecordProjection,
  type AuthorityRecordProjection,
} from './authority-record.js';

const ENTITY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECORD_ID = /^authority-record-[a-z0-9][a-z0-9-]{2,63}$/;
const INVITATION_TOKEN = /^ari1_[0-9a-f]{64}$/;
const OWNER_TOKEN = /^aro1_[0-9a-f]{64}$/;
const TOKEN_DIGEST = /^sha256:[0-9a-f]{64}$/;
const RECORD_DIGEST = /^sha256:[0-9a-f]{64}$/;
const IMMUTABLE_REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CLAIM_PATH = '/.well-known/emilia-authority-record.json';
const MAX_PROOF_BYTES = 64 * 1024;
const INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;

export type AuthorityRecordLifecycle = 'CLAIMED_PRIVATE' | 'PUBLISHED' | 'WITHDRAWN';

export type StoredAuthorityInvitation = {
  record_id: string;
  record_digest: string;
  projection: AuthorityRecordProjection;
  repository_url: string;
  contact_route: string;
  claim_challenge: string;
  invitation_expires_at: string;
  claimed_at: string | null;
};

export type StoredAuthorityOwnerState = {
  record_id: string;
  current_version: number;
  current_digest: string;
  current_projection: AuthorityRecordProjection;
  repository_url: string;
  status: AuthorityRecordLifecycle;
  approved_at: string | null;
  withdrawn_at: string | null;
};

export type StoredPublicAuthorityRecord = {
  record_id: string;
  version: number;
  record_digest: string;
  approved_at: string;
  projection: AuthorityRecordProjection;
};

type StoreFailure = Readonly<{ ok: false; code: string; detail: string }>;
type StoreSuccess<T extends object = Record<never, never>> = Readonly<{ ok: true } & T>;
type StoreResult<T extends object = Record<never, never>> = StoreSuccess<T> | StoreFailure;

export interface AuthorityRecordStore {
  createDraft(input: {
    record_id: string;
    record_digest: string;
    projection: AuthorityRecordProjection;
    repository_url: string;
    contact_route: string;
    created_by_entity_id: string;
    invitation_token_digest: string;
    claim_challenge: string;
    invitation_expires_at: string;
  }): Promise<StoreResult>;
  inspectInvitation(tokenDigest: string): Promise<StoreResult<{ invitation: StoredAuthorityInvitation | null }>>;
  claimInvitation(input: {
    invitation_token_digest: string;
    owner_token_digest: string;
    proof_url: string;
    proof_revision: string;
    proof_digest: string;
    claimed_at: string;
  }): Promise<StoreResult<{ state: StoredAuthorityOwnerState }>>;
  readOwnerState(
    recordId: string,
    ownerTokenDigest: string,
  ): Promise<StoreResult<{ state: StoredAuthorityOwnerState | null }>>;
  appendOwnerVersion(input: {
    record_id: string;
    owner_token_digest: string;
    record_digest: string;
    projection: AuthorityRecordProjection;
    created_at: string;
  }): Promise<StoreResult<{ state: StoredAuthorityOwnerState }>>;
  approveOwnerVersion(input: {
    record_id: string;
    owner_token_digest: string;
    record_digest: string;
    approved_at: string;
  }): Promise<StoreResult<{ state: StoredAuthorityOwnerState }>>;
  withdrawOwnerRecord(input: {
    record_id: string;
    owner_token_digest: string;
    withdrawn_at: string;
  }): Promise<StoreResult<{ state: StoredAuthorityOwnerState }>>;
  readPublicRecord(recordId: string): Promise<StoreResult<{ record: StoredPublicAuthorityRecord | null }>>;
  listPublicRecords(): Promise<StoreResult<{ records: StoredPublicAuthorityRecord[] }>>;
}

export class AuthorityRecordServiceError extends Error {
  constructor(public status: number, public code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AuthorityRecordServiceError';
  }
}

function fail(status: number, code: string, message: string, cause?: unknown): never {
  throw new AuthorityRecordServiceError(
    status,
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function requireStore<T extends object>(
  result: StoreResult<T>,
  context: 'create' | 'invite' | 'owner' | 'approve' | 'public',
): StoreSuccess<T> {
  if (result.ok === true) return result as StoreSuccess<T>;
  const failed = result as StoreFailure;
  if (failed.code === 'already_exists') {
    fail(409, 'authority_record_already_exists', 'An Authority Record already exists for this identifier.');
  }
  if (failed.code === 'invitation_unavailable') {
    fail(409, 'authority_record_invitation_unavailable', 'The claim invitation is unavailable.');
  }
  if (failed.code === 'record_digest_mismatch') {
    fail(409, 'authority_record_digest_mismatch', 'The approved digest is not the current Authority Record version.');
  }
  if (failed.code === 'owner_credential_invalid' || failed.code === 'not_found') {
    fail(404, 'authority_record_not_found', 'Authority Record not found.');
  }
  fail(503, 'authority_record_store_unavailable', `Authority Record ${context} storage is unavailable.`);
}

function canonicalInstant(now: number): string {
  if (!Number.isFinite(now)) fail(400, 'authority_record_time_invalid', 'Authority Record time is invalid.');
  return new Date(now).toISOString();
}

function randomHex(
  prefix: string,
  bytes: number,
  randomBytes: (size: number) => Buffer = crypto.randomBytes,
): string {
  const value = randomBytes(bytes);
  if (!Buffer.isBuffer(value) || value.length !== bytes) {
    fail(503, 'authority_record_randomness_unavailable', 'Authority Record credentials are unavailable.');
  }
  return `${prefix}${value.toString('hex')}`;
}

function tokenDigest(domain: string, token: string): string {
  return `sha256:${crypto.createHash('sha256').update(`${domain}\0${token}`, 'utf8').digest('hex')}`;
}

function validContactRoute(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 8 || value.length > 600) return false;
  return /^mailto:[^\s@]+@[^\s@]+$/i.test(value) || /^https:\/\/\S+$/i.test(value);
}

function canonicalSiteOrigin(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error('invalid');
    }
    return parsed.origin;
  } catch {
    fail(503, 'authority_record_origin_unavailable', 'Authority Record claim origin is unavailable.');
  }
}

export async function createAuthorityRecordDraft({
  actor,
  input,
  store,
  now = Date.now(),
  randomBytes = crypto.randomBytes,
  siteOrigin = 'https://www.emiliaprotocol.ai',
}: {
  actor: { entityId: string; isAdmin: boolean };
  input: { projection: unknown; contact_route: unknown };
  store: AuthorityRecordStore;
  now?: number;
  randomBytes?: (size: number) => Buffer;
  siteOrigin?: string;
}) {
  if (!actor?.isAdmin || !ENTITY_ID.test(actor.entityId)) {
    fail(403, 'authority_record_admin_required', 'Administrator authority is required to prepare a private scan.');
  }
  const parsed = validateAuthorityRecordProjection(input?.projection);
  if (!parsed.ok) fail(400, parsed.code, parsed.detail);
  if (!validContactRoute(input?.contact_route)) {
    fail(400, 'authority_record_contact_invalid', 'Contact route must be an HTTPS or mailto route.');
  }
  const observedAt = Date.parse(parsed.record.provenance.observed_at);
  if (observedAt > now + 5 * 60 * 1000) {
    fail(400, 'authority_record_observation_invalid', 'Authority Record observation is in the future.');
  }
  const createdAt = canonicalInstant(now);
  const invitationExpiresAt = new Date(now + INVITATION_LIFETIME_MS).toISOString();
  const invitationToken = randomHex('ari1_', 32, randomBytes);
  const invitationTokenDigest = tokenDigest('emilia-authority-record-invitation-v1', invitationToken);
  const challengeBytes = randomBytes(32);
  if (!Buffer.isBuffer(challengeBytes) || challengeBytes.length !== 32) {
    fail(503, 'authority_record_randomness_unavailable', 'Authority Record challenge is unavailable.');
  }
  const claimChallenge = `claim_${challengeBytes.toString('base64url')}`;
  const recordDigest = authorityRecordDigest(parsed.record);
  const proofDocument = buildAuthorityClaimProof({
    challenge: claimChallenge,
    recordDigest,
    repositoryUrl: parsed.record.subject.repository_url,
    expiresAt: invitationExpiresAt,
  });
  requireStore(await store.createDraft({
    record_id: parsed.record.record_id,
    record_digest: recordDigest,
    projection: parsed.record,
    repository_url: parsed.record.subject.repository_url,
    contact_route: input.contact_route,
    created_by_entity_id: actor.entityId,
    invitation_token_digest: invitationTokenDigest,
    claim_challenge: claimChallenge,
    invitation_expires_at: invitationExpiresAt,
  }), 'create');
  const origin = canonicalSiteOrigin(siteOrigin);
  return Object.freeze({
    record_id: parsed.record.record_id,
    record_digest: recordDigest,
    created_at: createdAt,
    invitation_token: invitationToken,
    invitation_expires_at: invitationExpiresAt,
    claim_challenge: claimChallenge,
    claim_url: `${origin}/works/claim#${invitationToken}`,
    proof_path: CLAIM_PATH,
    proof_document: proofDocument,
  });
}

type ParsedRawProofUrl = {
  repositoryUrl: string;
  revision: string;
  url: string;
};

function parseRawProofUrl(value: unknown): ParsedRawProofUrl | null {
  if (typeof value !== 'string' || value.length > 700) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:'
      || parsed.hostname.toLowerCase() !== 'raw.githubusercontent.com'
      || parsed.username || parsed.password || parsed.search || parsed.hash) return null;
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length !== 5
      || parts[3] !== '.well-known'
      || parts[4] !== 'emilia-authority-record.json'
      || !IMMUTABLE_REVISION.test(parts[2])) return null;
  const repositoryUrl = normalizeGitHubRepositoryUrl(`https://github.com/${parts[0]}/${parts[1]}`);
  if (!repositoryUrl) return null;
  return { repositoryUrl, revision: parts[2], url: parsed.toString() };
}

async function fetchClaimProof(
  proofUrl: ParsedRawProofUrl,
  fetchImpl: typeof fetch,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(proofUrl.url, {
      method: 'GET',
      redirect: 'manual',
      headers: { accept: 'application/json, text/plain;q=0.9' },
      signal: AbortSignal.timeout(8_000),
    });
  } catch (cause) {
    fail(422, 'authority_record_proof_unavailable', 'Repository-control proof is unavailable.', cause);
  }
  if (response.status !== 200 || response.headers.get('location')) {
    fail(422, 'authority_record_proof_unavailable', 'Repository-control proof must resolve directly.');
  }
  const declaredLength = Number(response.headers.get('content-length') || '0');
  if (Number.isFinite(declaredLength) && declaredLength > MAX_PROOF_BYTES) {
    fail(413, 'authority_record_proof_too_large', 'Repository-control proof is too large.');
  }
  const body = await response.text();
  if (Buffer.byteLength(body, 'utf8') > MAX_PROOF_BYTES) {
    fail(413, 'authority_record_proof_too_large', 'Repository-control proof is too large.');
  }
  try {
    return JSON.parse(body);
  } catch {
    fail(422, 'authority_record_proof_invalid', 'Repository-control proof is not valid JSON.');
  }
}

export async function claimAuthorityRecord({
  input,
  store,
  fetchImpl = fetch,
  now = Date.now(),
  randomBytes = crypto.randomBytes,
}: {
  input: { invitation_token: unknown; proof_url: unknown };
  store: AuthorityRecordStore;
  fetchImpl?: typeof fetch;
  now?: number;
  randomBytes?: (size: number) => Buffer;
}) {
  if (typeof input?.invitation_token !== 'string' || !INVITATION_TOKEN.test(input.invitation_token)) {
    fail(400, 'authority_record_invitation_invalid', 'Authority Record invitation is invalid.');
  }
  const proofUrl = parseRawProofUrl(input.proof_url);
  if (!proofUrl) {
    fail(400, 'authority_record_proof_url_invalid', 'Proof URL must pin the exact GitHub commit and claim path.');
  }
  const invitationTokenDigest = tokenDigest(
    'emilia-authority-record-invitation-v1', input.invitation_token,
  );
  const inspected = requireStore(await store.inspectInvitation(invitationTokenDigest), 'invite');
  const invitation = inspected.invitation;
  if (!invitation || invitation.claimed_at || Date.parse(invitation.invitation_expires_at) <= now) {
    fail(409, 'authority_record_invitation_unavailable', 'The claim invitation is unavailable.');
  }
  if (proofUrl.repositoryUrl !== normalizeGitHubRepositoryUrl(invitation.repository_url)) {
    fail(422, 'authority_record_proof_repository_mismatch', 'Proof must be hosted by the invited repository.');
  }
  const proof = await fetchClaimProof(proofUrl, fetchImpl);
  const proofResult = validateAuthorityClaimProof(proof, {
    challenge: invitation.claim_challenge,
    recordDigest: invitation.record_digest,
    repositoryUrl: invitation.repository_url,
    now,
  });
  if (!proofResult.ok) fail(422, proofResult.code, proofResult.detail);
  const ownerToken = randomHex('aro1_', 32, randomBytes);
  const ownerTokenDigest = tokenDigest('emilia-authority-record-owner-v1', ownerToken);
  const proofDigest = `sha256:${crypto.createHash('sha256')
    .update(JSON.stringify(proof), 'utf8').digest('hex')}`;
  const claimed = requireStore(await store.claimInvitation({
    invitation_token_digest: invitationTokenDigest,
    owner_token_digest: ownerTokenDigest,
    proof_url: proofUrl.url,
    proof_revision: proofUrl.revision,
    proof_digest: proofDigest,
    claimed_at: canonicalInstant(now),
  }), 'invite');
  return Object.freeze({
    record_id: claimed.state.record_id,
    owner_token: ownerToken,
    status: claimed.state.status,
    version: claimed.state.current_version,
    record_digest: claimed.state.current_digest,
    projection: claimed.state.current_projection,
  });
}

function ownerTokenDigest(ownerToken: unknown): string {
  if (typeof ownerToken !== 'string' || !OWNER_TOKEN.test(ownerToken)) {
    fail(404, 'authority_record_not_found', 'Authority Record not found.');
  }
  return tokenDigest('emilia-authority-record-owner-v1', ownerToken);
}

async function ownerState(
  store: AuthorityRecordStore,
  recordId: string,
  ownerToken: string,
): Promise<{ digest: string; state: StoredAuthorityOwnerState }> {
  if (!RECORD_ID.test(recordId)) fail(404, 'authority_record_not_found', 'Authority Record not found.');
  const digest = ownerTokenDigest(ownerToken);
  const loaded = requireStore(await store.readOwnerState(recordId, digest), 'owner');
  if (!loaded.state) fail(404, 'authority_record_not_found', 'Authority Record not found.');
  return { digest, state: loaded.state };
}

export async function reviseAuthorityRecord({
  recordId,
  ownerToken,
  projection,
  store,
  now = Date.now(),
}: {
  recordId: string;
  ownerToken: string;
  projection: unknown;
  store: AuthorityRecordStore;
  now?: number;
}) {
  const owner = await ownerState(store, recordId, ownerToken);
  const parsed = validateAuthorityRecordProjection(projection);
  if (!parsed.ok) fail(400, parsed.code, parsed.detail);
  if (parsed.record.record_id !== recordId) {
    fail(400, 'authority_record_identity_immutable', 'Authority Record identifier is immutable.');
  }
  if (parsed.record.subject.repository_url !== owner.state.repository_url
      || parsed.record.provenance.source_locator !== owner.state.repository_url) {
    fail(400, 'authority_record_repository_immutable', 'Claimed repository is immutable.');
  }
  const digest = authorityRecordDigest(parsed.record);
  const revised = requireStore(await store.appendOwnerVersion({
    record_id: recordId,
    owner_token_digest: owner.digest,
    record_digest: digest,
    projection: parsed.record,
    created_at: canonicalInstant(now),
  }), 'owner');
  return Object.freeze({
    record_id: revised.state.record_id,
    status: revised.state.status,
    version: revised.state.current_version,
    record_digest: revised.state.current_digest,
    projection: revised.state.current_projection,
  });
}

export async function getOwnerAuthorityRecord({
  recordId,
  ownerToken,
  store,
}: {
  recordId: string;
  ownerToken: string;
  store: AuthorityRecordStore;
}) {
  const owner = await ownerState(store, recordId, ownerToken);
  return Object.freeze({
    record_id: owner.state.record_id,
    status: owner.state.status,
    version: owner.state.current_version,
    record_digest: owner.state.current_digest,
    projection: owner.state.current_projection,
    approved_at: owner.state.approved_at,
    withdrawn_at: owner.state.withdrawn_at,
  });
}

export async function approveAuthorityRecord({
  recordId,
  ownerToken,
  recordDigest,
  store,
  now = Date.now(),
}: {
  recordId: string;
  ownerToken: string;
  recordDigest: string;
  store: AuthorityRecordStore;
  now?: number;
}) {
  if (!RECORD_DIGEST.test(recordDigest)) {
    fail(400, 'authority_record_digest_invalid', 'Authority Record digest is invalid.');
  }
  const owner = await ownerState(store, recordId, ownerToken);
  if (owner.state.current_digest !== recordDigest) {
    fail(409, 'authority_record_digest_mismatch', 'The approved digest is not the current Authority Record version.');
  }
  const approvedAt = canonicalInstant(now);
  const approved = requireStore(await store.approveOwnerVersion({
    record_id: recordId,
    owner_token_digest: owner.digest,
    record_digest: recordDigest,
    approved_at: approvedAt,
  }), 'approve');
  return Object.freeze({
    record_id: approved.state.record_id,
    status: approved.state.status,
    version: approved.state.current_version,
    record_digest: approved.state.current_digest,
    approved_at: approved.state.approved_at,
  });
}

export async function withdrawAuthorityRecord({
  recordId,
  ownerToken,
  store,
  now = Date.now(),
}: {
  recordId: string;
  ownerToken: string;
  store: AuthorityRecordStore;
  now?: number;
}) {
  const owner = await ownerState(store, recordId, ownerToken);
  const withdrawnAt = canonicalInstant(now);
  const withdrawn = requireStore(await store.withdrawOwnerRecord({
    record_id: recordId,
    owner_token_digest: owner.digest,
    withdrawn_at: withdrawnAt,
  }), 'owner');
  return Object.freeze({
    record_id: withdrawn.state.record_id,
    status: withdrawn.state.status,
    withdrawn_at: withdrawn.state.withdrawn_at,
  });
}

function validatePublicRow(
  stored: StoredPublicAuthorityRecord,
  now: number,
): StoredPublicAuthorityRecord | null {
  const parsed = validateAuthorityRecordProjection(stored.projection);
  if (!parsed.ok
      || parsed.record.record_id !== stored.record_id
      || authorityRecordDigest(parsed.record) !== stored.record_digest
      || !Number.isInteger(stored.version)
      || stored.version < 1
      || typeof stored.approved_at !== 'string'
      || !Number.isFinite(Date.parse(stored.approved_at))) {
    fail(503, 'authority_record_store_invalid', 'Stored public Authority Record is inconsistent.');
  }
  if (Date.parse(parsed.record.provenance.expires_at) <= now) return null;
  return Object.freeze({ ...stored, projection: parsed.record });
}

export async function getPublicAuthorityRecord({
  recordId,
  store,
  now = Date.now(),
}: {
  recordId: string;
  store: AuthorityRecordStore;
  now?: number;
}): Promise<StoredPublicAuthorityRecord | null> {
  if (!RECORD_ID.test(recordId)) return null;
  const loaded = requireStore(await store.readPublicRecord(recordId), 'public');
  return loaded.record ? validatePublicRow(loaded.record, now) : null;
}

export async function listPublicAuthorityRecords({
  store,
  now = Date.now(),
}: {
  store: AuthorityRecordStore;
  now?: number;
}): Promise<StoredPublicAuthorityRecord[]> {
  const loaded = requireStore(await store.listPublicRecords(), 'public');
  const records: StoredPublicAuthorityRecord[] = [];
  for (const row of loaded.records) {
    const record = validatePublicRow(row, now);
    if (record) records.push(record);
  }
  return records;
}

export const __authorityRecordServiceInternals = Object.freeze({
  invitationTokenDigest: (token: string) => tokenDigest('emilia-authority-record-invitation-v1', token),
  ownerTokenDigest: (token: string) => tokenDigest('emilia-authority-record-owner-v1', token),
  parseRawProofUrl,
  maxProofBytes: MAX_PROOF_BYTES,
});
