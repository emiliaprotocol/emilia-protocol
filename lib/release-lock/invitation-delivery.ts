// SPDX-License-Identifier: Apache-2.0

import {
  parseJsonObject,
  requestBounded,
  responseHeader,
  validatePinnedOrigin,
  validateResponseLimit,
  validateTimeout,
} from '../integrations/action-escrow/bounded-fetch.js';

const RESEND_ORIGIN = 'https://api.resend.com';
const RESEND_HOSTS = new Set(['api.resend.com']);
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024;
const CONTROL = /[\u0000-\u001f\u007f]/;
const LOCK_ID = /^rlk_[a-f0-9]{32}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

function cleanText(value, name, max) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > max
      || CONTROL.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function email(value, name) {
  const candidate = cleanText(value, name, 254);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate)) {
    throw new TypeError(`${name} is invalid`);
  }
  return candidate;
}

function senderIdentity(value) {
  const candidate = cleanText(value, 'Release Lock invitation sender', 320);
  const bracketed = candidate.match(/^[^<>]{1,64}<([^<>]+)>$/);
  email(bracketed ? bracketed[1].trim() : candidate, 'Release Lock invitation sender');
  return candidate;
}

function publicOrigin(value) {
  return validatePinnedOrigin(value, {
    fieldName: 'Release Lock public origin',
  });
}

function invitationUrl(origin, input) {
  const url = new URL('/release-lock/c', origin);
  url.searchParams.set('lock_id', input.lockId);
  url.searchParams.set('role', input.role);
  url.hash = `cap=${input.token}`;
  return url.href;
}

interface ResendReleaseLockInvitationAdapterOptions {
  apiKey?: string;
  from?: string;
  publicAppOrigin?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export function createResendReleaseLockInvitationAdapter({
  apiKey,
  from,
  publicAppOrigin,
  fetch: fetchImpl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
}: ResendReleaseLockInvitationAdapterOptions = {}) {
  const key = cleanText(apiKey, 'Resend API key', 4096);
  if (/\s/.test(key)) throw new TypeError('Resend API key is invalid');
  const sender = senderIdentity(from);
  const origin = publicOrigin(publicAppOrigin);
  const timeout = validateTimeout(timeoutMs);
  const responseLimit = validateResponseLimit(maxResponseBytes, 'maxResponseBytes');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch must be injected');
  const boundFetch: typeof fetch = fetchImpl;
  const resendOrigin = validatePinnedOrigin(RESEND_ORIGIN, /** @type {any} */ ({
    allowedHosts: RESEND_HOSTS,
    fieldName: 'Resend API origin',
  }));

  async function deliver(input) {
    if (!input
        || !LOCK_ID.test(input.lockId || '')
        || !['contractor', 'customer'].includes(input.role)
        || input.channel !== 'email'
        || !TOKEN.test(input.token || '')
        || !Number.isFinite(Date.parse(input.expiresAt))) {
      throw new TypeError('Release Lock invitation is malformed');
    }
    const recipient = email(input.identifier, 'Release Lock invitation recipient');
    const link = invitationUrl(origin, input);
    const payload = JSON.stringify({
      from: sender,
      to: [recipient],
      subject: `Review Release Lock ${input.lockId}`,
      text: [
        `You were invited to the ${input.role} seat for Release Lock ${input.lockId}.`,
        '',
        'Open this single-use invitation:',
        link,
        '',
        `Invitation expires ${input.expiresAt}.`,
        'Opening the invitation does not approve either ceremony.',
      ].join('\n'),
    });
    const response = await requestBounded(
      boundFetch,
      `${resendOrigin}/emails`,
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json',
        },
        body: payload,
      },
      {
        expectedOrigin: resendOrigin,
        maxBytes: responseLimit,
        timeoutMs: timeout,
      },
    );
    if (response.kind !== 'response'
        || response.status < 200
        || response.status >= 300) {
      throw new Error('Resend invitation delivery failed');
    }
    const parsed = parseJsonObject(
      response.bytes,
      responseHeader(response, 'content-type'),
    );
    const reference = parsed.ok ? parsed.value.id : null;
    if (typeof reference !== 'string'
        || reference.length === 0
        || reference.length > 512
        || CONTROL.test(reference)) {
      throw new Error('Resend invitation delivery response is invalid');
    }
    return Object.freeze({
      kind: 'delivered',
      provider: 'resend',
      reference,
      channel: 'email',
      role: input.role,
      lock_id: input.lockId,
    });
  }

  return Object.freeze({
    kind: 'verified_contact_delivery',
    provider: 'resend',
    channel: 'email',
    deliver,
  });
}

export const releaseLockInvitationDeliveryInternals = Object.freeze({
  invitationUrl,
});
