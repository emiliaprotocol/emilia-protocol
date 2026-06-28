// SPDX-License-Identifier: Apache-2.0
//
// SSO provider URLs are later used by SAML redirect builders and OIDC
// discovery/token/JWKS fetches. Treat tenant-supplied URLs as hostile: they
// must never be able to target localhost, link-local/cloud metadata, or
// private network ranges from the server runtime.

import net from 'node:net';

const BLOCKED_HOSTS = new Set([
  'localhost',
  'metadata.google.internal',
]);

const BLOCKED_SUFFIXES = [
  '.localhost',
];

export function validateSsoProviderUrl(value, field = 'url') {
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

  url.hash = '';
  return { valid: true, url: url.toString().replace(/\/$/, '') };
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
};
