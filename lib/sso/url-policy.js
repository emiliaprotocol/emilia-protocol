// SPDX-License-Identifier: Apache-2.0
//
// SSO provider URLs are later used by SAML redirect builders and OIDC
// discovery/token/JWKS fetches. Treat tenant-supplied URLs as hostile: they
// must never be able to target localhost, link-local/cloud metadata, or
// private network ranges from the server runtime.

import net from 'node:net';
import dns from 'node:dns/promises';

const BLOCKED_HOSTS = new Set([
  'localhost',
  'metadata.google.internal',
]);

const BLOCKED_SUFFIXES = [
  '.localhost',
];

export async function validateSsoProviderUrl(value, field = 'url', { lookup = dns.lookup } = {}) {
  let url;
  try {
    url = new URL(String(value || ''));
  } catch {
    return { valid: false, error: `${field} must be a valid URL` };
  }

  if (url.protocol !== 'https:') {
    return { valid: false, error: `${field} must use https` };
  }

  if (url.username || url.password) {
    return { valid: false, error: `${field} must not contain credentials` };
  }

  const hostname = normalizeHostname(url.hostname);
  if (!hostname) {
    return { valid: false, error: `${field} must include a hostname` };
  }

  if (isBlockedHost(hostname) || isPrivateAddress(hostname)) {
    return { valid: false, error: `${field} targets a blocked or private host` };
  }

  const resolved = await resolveHostname(hostname, lookup);
  if (!resolved.ok) {
    return { valid: false, error: `${field} hostname could not be resolved safely` };
  }
  if (resolved.addresses.some((address) => isPrivateAddress(address))) {
    return { valid: false, error: `${field} resolves to a blocked or private host` };
  }

  url.hash = '';
  return { valid: true, url: url.toString().replace(/\/$/, '') };
}

export function validateOidcRedirectUri(value, origin, field = 'oidc_redirect_uri') {
  if (value === undefined || value === null || value === '') {
    return { valid: true, url: null };
  }

  let base;
  let url;
  try {
    base = new URL(String(origin || ''));
    url = new URL(String(value), base);
  } catch {
    return { valid: false, error: `${field} must be a valid URL` };
  }

  if (url.username || url.password) {
    return { valid: false, error: `${field} must not contain credentials` };
  }
  if (url.origin !== base.origin) {
    return { valid: false, error: `${field} must stay on the service origin` };
  }
  if (url.pathname !== '/api/sso/oidc/callback') {
    return { valid: false, error: `${field} must target /api/sso/oidc/callback` };
  }
  if (url.search || url.hash) {
    return { valid: false, error: `${field} must not include query or fragment data` };
  }

  return { valid: true, url: url.toString() };
}

async function resolveHostname(hostname, lookup) {
  if (net.isIP(hostname)) return { ok: true, addresses: [hostname] };
  try {
    const records = await lookup(hostname, { all: true, verbatim: true });
    const addresses = Array.isArray(records)
      ? records.map((r) => r.address).filter(Boolean)
      : [records?.address].filter(Boolean);
    if (addresses.length === 0) return { ok: false, addresses: [] };
    return { ok: true, addresses };
  } catch {
    return { ok: false, addresses: [] };
  }
}

function normalizeHostname(hostname) {
  return String(hostname || '')
    .trim()
    .replace(/^\[(.*)\]$/, '$1')
    .replace(/\.$/, '')
    .toLowerCase();
}

function isBlockedHost(hostname) {
  if (BLOCKED_HOSTS.has(hostname)) return true;
  return BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

function isPrivateAddress(hostname) {
  const ipVersion = net.isIP(hostname);
  if (ipVersion === 4) return isPrivateIPv4(hostname);
  if (ipVersion === 6) return isPrivateIPv6(hostname);
  return false;
}

function isPrivateIPv4(hostname) {
  const parts = hostname.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return true;
  }
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIPv6(hostname) {
  const normalized = hostname.toLowerCase();
  return (
    normalized === '::1' ||
    normalized === '::' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe80:') ||
    normalized.startsWith('ff')
  );
}

export const _internals = {
  isPrivateIPv4,
  isPrivateIPv6,
  normalizeHostname,
  resolveHostname,
};
