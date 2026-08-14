// SPDX-License-Identifier: Apache-2.0
//
// Verified interest in an Authority Record is an exact event, not a marketing
// estimate. Raw requester addresses are used only to deliver the one-time link;
// durable state receives keyed and domain-separated digests instead.

import crypto from 'node:crypto';

const RECORD_ID = /^authority-record-[a-z0-9][a-z0-9-]{2,63}$/;
const VERIFY_TOKEN = /^ardv1_[0-9a-f]{64}$/;
const VERIFY_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MIN_HMAC_KEY_BYTES = 32;

type StoreFailure = Readonly<{ ok: false; code: string; detail: string }>;
type StoreSuccess<T extends object = Record<never, never>> = Readonly<{ ok: true } & T>;
type StoreResult<T extends object = Record<never, never>> = StoreSuccess<T> | StoreFailure;

export interface AuthorityDemandStore {
  createRequest(input: {
    record_id: string;
    requester_digest: string;
    organization_domain: string;
    verification_token_digest: string;
    verification_expires_at: string;
    created_at: string;
  }): Promise<StoreResult<{ status: 'PENDING' | 'ALREADY_VERIFIED' }>>;
  verifyRequest(input: {
    verification_token_digest: string;
    verified_at: string;
  }): Promise<StoreResult<{
    result: {
      record_id: string;
      verified_requesters: number;
      verified_organizations: number;
      owner_contact_route?: string;
    };
  }>>;
  readCounts(recordId: string): Promise<StoreResult<{
    counts: { verified_requesters: number; verified_organizations: number };
  }>>;
}

export class DemandServiceError extends Error {
  constructor(public status: number, public code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'DemandServiceError';
  }
}

function fail(status: number, code: string, message: string, cause?: unknown): never {
  throw new DemandServiceError(status, code, message,
    cause === undefined ? undefined : { cause });
}

function canonicalNow(now: number): string {
  if (!Number.isFinite(now)) fail(400, 'authority_demand_time_invalid', 'Request time is invalid.');
  return new Date(now).toISOString();
}

function normalizeEmail(value: unknown): { email: string; domain: string } {
  if (typeof value !== 'string' || value.length > 320) {
    fail(400, 'authority_demand_email_invalid', 'A valid email address is required.');
  }
  const email = value.trim().toLowerCase();
  const at = email.lastIndexOf('@');
  if (at <= 0 || at !== email.indexOf('@')) {
    fail(400, 'authority_demand_email_invalid', 'A valid email address is required.');
  }
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (!local || !domain || local.length > 64 || /\s/.test(email)
      || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
    fail(400, 'authority_demand_email_invalid', 'A valid email address is required.');
  }
  return { email, domain };
}

function hmacKeyBytes(value: string): Buffer {
  if (typeof value !== 'string') {
    fail(503, 'authority_demand_unavailable', 'Verified request service is unavailable.');
  }
  const bytes = /^[0-9a-f]{64,}$/i.test(value) && value.length % 2 === 0
    ? Buffer.from(value, 'hex') : Buffer.from(value, 'utf8');
  if (bytes.length < MIN_HMAC_KEY_BYTES) {
    fail(503, 'authority_demand_unavailable', 'Verified request service is unavailable.');
  }
  return bytes;
}

function requesterDigest(email: string, hmacKey: Buffer): string {
  return `hmac-sha256:${crypto.createHmac('sha256', hmacKey)
    .update(`emilia-authority-demand-requester-v1\0${email}`, 'utf8').digest('hex')}`;
}

function tokenDigest(token: string): string {
  return `sha256:${crypto.createHash('sha256')
    .update(`emilia-authority-demand-verification-v1\0${token}`, 'utf8').digest('hex')}`;
}

function canonicalSiteOrigin(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password
        || parsed.search || parsed.hash) throw new Error('invalid');
    return parsed.origin;
  } catch {
    fail(503, 'authority_demand_unavailable', 'Verified request service is unavailable.');
  }
}

function storeResult<T extends object>(result: StoreResult<T>): StoreSuccess<T> {
  if (result.ok === true) return result as StoreSuccess<T>;
  const failed = result as StoreFailure;
  if (failed.code === 'not_found' || failed.code === 'token_unavailable') {
    fail(404, 'authority_demand_verification_unavailable', 'Verification link is unavailable.');
  }
  if (failed.code === 'record_unavailable') {
    fail(404, 'authority_record_not_found', 'Authority Record not found.');
  }
  fail(503, 'authority_demand_unavailable', 'Verified request service is unavailable.');
}

export async function createAuthorityRecordDemandRequest({
  input,
  store,
  hmacKey,
  siteOrigin = 'https://www.emiliaprotocol.ai',
  now = Date.now(),
  randomBytes = crypto.randomBytes,
  sendEmail,
}: {
  input: { record_id: unknown; email: unknown };
  store: AuthorityDemandStore;
  hmacKey: string;
  siteOrigin?: string;
  now?: number;
  randomBytes?: (size: number) => Buffer;
  sendEmail?: (input: { to: string; verifyUrl: string; recordId: string }) => Promise<{ delivered: boolean }>;
}): Promise<Readonly<{ accepted: true; verification_sent: boolean }>> {
  if (typeof input?.record_id !== 'string' || !RECORD_ID.test(input.record_id)) {
    fail(400, 'authority_record_id_invalid', 'Authority Record identifier is invalid.');
  }
  const { email, domain } = normalizeEmail(input.email);
  const key = hmacKeyBytes(hmacKey);
  const createdAt = canonicalNow(now);
  const random = randomBytes(32);
  if (!Buffer.isBuffer(random) || random.length !== 32) {
    fail(503, 'authority_demand_unavailable', 'Verified request service is unavailable.');
  }
  const token = `ardv1_${random.toString('hex')}`;
  const created = storeResult(await store.createRequest({
    record_id: input.record_id,
    requester_digest: requesterDigest(email, key),
    organization_domain: domain,
    verification_token_digest: tokenDigest(token),
    verification_expires_at: new Date(now + VERIFY_LIFETIME_MS).toISOString(),
    created_at: createdAt,
  }));

  let delivered = false;
  if (created.status === 'PENDING' && sendEmail) {
    try {
      const origin = canonicalSiteOrigin(siteOrigin);
      delivered = (await sendEmail({
        to: email,
        verifyUrl: `${origin}/works/request/verify#${token}`,
        recordId: input.record_id,
      })).delivered === true;
    } catch {
      delivered = false;
    }
  }
  return Object.freeze({ accepted: true, verification_sent: delivered });
}

export async function verifyAuthorityRecordDemandRequest({
  token,
  store,
  now = Date.now(),
}: {
  token: unknown;
  store: AuthorityDemandStore;
  now?: number;
}): Promise<Readonly<{
  record_id: string;
  verified_requesters: number;
  verified_organizations: number;
}>> {
  if (typeof token !== 'string' || !VERIFY_TOKEN.test(token)) {
    fail(404, 'authority_demand_verification_unavailable', 'Verification link is unavailable.');
  }
  const verified = storeResult(await store.verifyRequest({
    verification_token_digest: tokenDigest(token),
    verified_at: canonicalNow(now),
  }));
  return Object.freeze({
    record_id: verified.result.record_id,
    verified_requesters: verified.result.verified_requesters,
    verified_organizations: verified.result.verified_organizations,
  });
}

export async function readAuthorityRecordDemandCounts({
  recordId,
  store,
}: {
  recordId: unknown;
  store: AuthorityDemandStore;
}): Promise<Readonly<{ verified_requesters: number; verified_organizations: number }>> {
  if (typeof recordId !== 'string' || !RECORD_ID.test(recordId)) {
    fail(404, 'authority_record_not_found', 'Authority Record not found.');
  }
  return Object.freeze(storeResult(await store.readCounts(recordId)).counts);
}
