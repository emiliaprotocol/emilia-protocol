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

/**
 * @param {*} value - tenant-supplied URL; treated as hostile, coerced via String()
 * @param {string} [field]
 * @param {{ lookup?: typeof import('node:dns/promises').lookup }} [opts]
 */
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

  // Return the exact validated IP so the CALLER can pin the connection to it —
  // no second, independent DNS resolution can rebind to an internal address
  // between this check and the fetch (DNS-rebinding TOCTOU). All addresses passed
  // the non-private check above, so the first record is a safe pin target.
  const pin = resolved.records.find((r) => !isPrivateAddress(r.address)) || resolved.records[0];

  url.hash = '';
  return { valid: true, url: url.toString().replace(/\/$/, ''), address: pin.address, family: pin.family };
}

/**
 * @param {*} value - tenant-supplied redirect URI (relative or absolute); treated as hostile
 * @param {string} origin - trusted service origin to resolve/compare against
 * @param {string} [field]
 */
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

/**
 * @param {string} hostname
 * @param {typeof import('node:dns/promises').lookup} lookup
 */
async function resolveHostname(hostname, lookup) {
  const ipv = net.isIP(hostname);
  if (ipv) return { ok: true, addresses: [hostname], records: [{ address: hostname, family: ipv }] };
  try {
    const raw = await lookup(hostname, { all: true, verbatim: true });
    const list = Array.isArray(raw) ? raw : [raw];
    const records = list
      .filter((r) => r && r.address)
      .map((r) => ({ address: r.address, family: r.family || net.isIP(r.address) || 4 }));
    if (records.length === 0) return { ok: false, addresses: [], records: [] };
    return { ok: true, addresses: records.map((r) => r.address), records };
  } catch {
    return { ok: false, addresses: [], records: [] };
  }
}

/** @param {string} hostname */
function normalizeHostname(hostname) {
  return String(hostname || '')
    .trim()
    .replace(/^\[(.*)\]$/, '$1')
    .replace(/\.$/, '')
    .toLowerCase();
}

/** @param {string} hostname */
function isBlockedHost(hostname) {
  if (BLOCKED_HOSTS.has(hostname)) return true;
  return BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

/** @param {string} hostname */
function isPrivateAddress(hostname) {
  const ipVersion = net.isIP(hostname);
  if (ipVersion === 4) return isPrivateIPv4(hostname);
  if (ipVersion === 6) {
    // IPv4-mapped IPv6 (::ffff:169.254.169.254 or its hex form ::ffff:a9fe:a9fe)
    // smuggles a v4 target past the v6-only range checks below — the embedded v4
    // is what the socket actually connects to. Evaluate it against the v4 ranges.
    const mapped = embeddedMappedIpv4(hostname);
    if (mapped) return isPrivateIPv4(mapped);
    return isPrivateIPv6(hostname);
  }
  return false;
}

// Extract the embedded IPv4 from an IPv4-mapped IPv6 literal (::ffff:0:0/96), or
// null if `hostname` is not such an address. Both the dotted tail
// (::ffff:169.254.169.254) and the compressed hex tail (::ffff:a9fe:a9fe) that
// the URL parser and dns.lookup emit are handled, plus the fully-expanded
// 0:0:0:0:0:ffff:… prefix. Anchoring on the ::ffff: prefix avoids misreading a
// genuine public address that merely contains an ffff group (2001:db8::ffff:…).
/** @param {string} hostname */
function embeddedMappedIpv4(hostname) {
  const host = String(hostname).toLowerCase();
  if (net.isIP(host) !== 6) return null;
  const m = host.match(/^(?:::ffff:|(?:0:){5}ffff:)(.+)$/);
  if (!m) return null;
  const tail = m[1];
  if (net.isIPv4(tail)) return tail; // ::ffff:169.254.169.254
  const hex = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/); // ::ffff:a9fe:a9fe
  if (!hex) return null;
  const hi = parseInt(hex[1], 16);
  const lo = parseInt(hex[2], 16);
  if (hi > 0xffff || lo > 0xffff) return null;
  return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join('.');
}

/** @param {string} hostname */
function isPrivateIPv4(hostname) {
  const parts = hostname.split('.').map((/** @type {string} */ p) => Number(p));
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

/** @param {string} hostname */
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
  isPrivateAddress,
  embeddedMappedIpv4,
  normalizeHostname,
  resolveHostname,
};
