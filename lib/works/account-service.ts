// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';

export type WorksSessionActor = {
  accountId: string;
  ownerEntityId: string;
  displayName: string;
  emailVerified: true;
  emailNotifications: boolean;
  claimsVerified: false;
  authMethod: 'email_code';
};

export type AccountStoreResult<T> = ({ ok: true } & T) | { ok: false; code: string };

export interface WorksAccountStore {
  beginChallenge(input: {
    challengeId: string;
    emailDigest: string;
    clientDigest: string;
    codeDigest: string;
    mode: 'signup' | 'login';
    displayName: string | null;
    consent: boolean;
    emailNotifications: boolean;
  }): Promise<AccountStoreResult<{ challengeId: string }>>;
  markDelivery(input: {
    challengeId: string;
    codeDigest: string;
    delivered: boolean;
  }): Promise<AccountStoreResult<object>>;
  exchangeChallenge(input: {
    challengeId: string;
    emailDigest: string;
    codeDigest: string;
    sessionDigest: string;
    sessionExpiresAt: string;
  }): Promise<AccountStoreResult<{ actor: WorksSessionActor }>>;
  readSession(sessionDigest: string): Promise<AccountStoreResult<{ actor: WorksSessionActor | null }>>;
  revokeSession(sessionDigest: string): Promise<AccountStoreResult<{ revoked: boolean }>>;
}

export class AccountServiceError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = 'AccountServiceError';
  }
}

function normalizedEmail(value: unknown): string {
  if (typeof value !== 'string') throw new AccountServiceError(400, 'account_email_invalid', 'Enter a valid email address.');
  const email = value.trim().toLowerCase();
  if (email.length > 254
    || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(email)) {
    throw new AccountServiceError(400, 'account_email_invalid', 'Enter a valid email address.');
  }
  return email;
}

function displayName(value: unknown): string {
  if (typeof value !== 'string') throw new AccountServiceError(400, 'account_name_invalid', 'Enter the name you want shown on Works.');
  const name = value.trim().replace(/\s+/g, ' ');
  if (name.length < 2 || Buffer.byteLength(name, 'utf8') > 200 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new AccountServiceError(400, 'account_name_invalid', 'Enter the name you want shown on Works.');
  }
  return name;
}

function hmac(secret: string, scope: string, value: string): string {
  if (Buffer.byteLength(secret, 'utf8') < 32) {
    throw new AccountServiceError(503, 'account_service_unavailable', 'Account sign-in is unavailable.');
  }
  return `hmac-sha256:${crypto.createHmac('sha256', secret).update(`${scope}\0${value}`, 'utf8').digest('hex')}`;
}

function sessionDigest(token: string): string {
  return `sha256:${crypto.createHash('sha256').update(token, 'utf8').digest('hex')}`;
}

export async function startWorksAccountChallenge({
  input,
  clientAddress,
  secret,
  store,
  sendEmail,
}: {
  input: { email?: unknown; name?: unknown; consent?: unknown; emailNotifications?: unknown };
  clientAddress: string;
  secret: string;
  store: WorksAccountStore;
  sendEmail(input: { to: string; code: string }): Promise<{ delivered: boolean }>;
}): Promise<{ accepted: true; challengeId: string }> {
  const email = normalizedEmail(input.email);
  const mode = input.name === undefined ? 'login' : 'signup';
  const name = mode === 'signup' ? displayName(input.name) : null;
  if (mode === 'signup' && input.consent !== true) {
    throw new AccountServiceError(400, 'account_consent_required', 'Agree to the Works account terms to continue.');
  }
  const challengeId = crypto.randomUUID();
  const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
  const codeDigest = hmac(secret, 'code', `${challengeId}:${code}`);
  const begun = await store.beginChallenge({
    challengeId,
    emailDigest: hmac(secret, 'email', email),
    clientDigest: hmac(secret, 'client', clientAddress || 'unknown'),
    codeDigest,
    mode,
    displayName: name,
    consent: mode === 'signup',
    emailNotifications: mode === 'signup' && input.emailNotifications === true,
  });
  if (!begun.ok) {
    // Do not turn the durable email/client limit into an address-existence oracle.
    if (begun.code === 'request_limited') return { accepted: true, challengeId };
    throw new AccountServiceError(503, 'account_service_unavailable', 'Account sign-in is unavailable.');
  }

  const delivered = await sendEmail({ to: email, code });
  const marked = await store.markDelivery({ challengeId, codeDigest, delivered: delivered.delivered });
  if (!delivered.delivered || !marked.ok) {
    throw new AccountServiceError(503, 'account_delivery_unavailable', 'We could not send a sign-in code. Try again later.');
  }
  return { accepted: true, challengeId };
}

export async function verifyWorksAccountChallenge({
  input,
  secret,
  store,
}: {
  input: { email?: unknown; challengeId?: unknown; code?: unknown };
  secret: string;
  store: WorksAccountStore;
}): Promise<{ actor: WorksSessionActor; sessionToken: string; sessionExpiresAt: Date }> {
  const email = normalizedEmail(input.email);
  if (typeof input.challengeId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.challengeId)
    || typeof input.code !== 'string'
    || !/^\d{6}$/.test(input.code)) {
    throw new AccountServiceError(401, 'account_verification_failed', 'The code could not be verified. Start again and use the newest email.');
  }
  const sessionToken = `wss1_${crypto.randomBytes(32).toString('hex')}`;
  const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const exchanged = await store.exchangeChallenge({
    challengeId: input.challengeId,
    emailDigest: hmac(secret, 'email', email),
    codeDigest: hmac(secret, 'code', `${input.challengeId}:${input.code}`),
    sessionDigest: sessionDigest(sessionToken),
    sessionExpiresAt: sessionExpiresAt.toISOString(),
  });
  if (!exchanged.ok) {
    if (exchanged.code === 'store_unavailable' || exchanged.code === 'store_invalid') {
      throw new AccountServiceError(503, 'account_service_unavailable', 'Account sign-in is unavailable.');
    }
    throw new AccountServiceError(401, 'account_verification_failed', 'The code could not be verified. Start again and use the newest email.');
  }
  return { actor: exchanged.actor, sessionToken, sessionExpiresAt };
}
