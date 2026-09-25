// SPDX-License-Identifier: Apache-2.0
//
// SSO provider URLs are later used by SAML redirect builders and OIDC
// discovery/token/JWKS fetches. Treat tenant-supplied URLs as hostile: they
// must never be able to target localhost, link-local/cloud metadata, or
// private network ranges from the server runtime.

import net from 'node:net';
import dns from 'node:dns/promises';
import { isPublicAddress } from '../net/public-address.js';

const BLOCKED_HOSTS = new Set([
  'localhost',
  'metadata.google.internal',
]);

const BLOCKED_SUFFIXES = [
  '.localhost',
];

export async function validateSsoProviderUrl(
  value: any,
  field: string = 'url',
  { lookup = dns.lookup }: { lookup?: typeof dns.lookup } = {}
): Promise<
  | { valid: false; error: string }
  | { valid: true; url: string; address: string; family: number }
> {
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
  // Every answer must be public unicast; a non-IP answer fails closed too.
  if (resolved.addresses.some((address) => !isPublicAddress(address))) {
    return { valid: false, error: `${field} resolves to a blocked or private host` };
  }

  // Return the exact validated IP so the CALLER can pin the connection to it —
  // no second, independent DNS resolution can rebind to an internal address
  // between this check and the fetch (DNS-rebinding TOCTOU). All addresses passed
  // the non-private check above, so the first record is a safe pin target.
  const pin = resolved.records[0];

  url.hash = '';
  return { valid: true, url: url.toString().replace(/\/$/, ''), address: pin.address, family: pin.family };
}

export function validateOidcRedirectUri(
  value: any,
  origin: string,
  field: string = 'oidc_redirect_uri'
): { valid: boolean; error?: string; url?: string | null } {
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

async function resolveHostname(
  hostname: string,
  lookup: typeof dns.lookup
): Promise<{
  ok: boolean;
  addresses: string[];
  records: Array<{ address: string; family: number }>;
}> {
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

function normalizeHostname(hostname: any): string {
  return String(hostname || '')
    .trim()
    .replace(/^\[(.*)\]$/, '$1')
    .replace(/\.$/, '')
    .toLowerCase();
}

function isBlockedHost(hostname: string): boolean {
  if (BLOCKED_HOSTS.has(hostname)) return true;
  return BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

// IP classification is an allowlist (lib/net/public-address.ts). The previous
// deny-list caught IPv4-mapped IPv6 but not the families that also carry an
// IPv4 target (NAT64 64:ff9b::/96, 6to4 2002::/16, IPv4-compatible ::a.b.c.d).
// DNS names return false here; resolveHostname's answers are checked instead.
function isPrivateAddress(hostname: string): boolean {
  if (!net.isIP(hostname)) return false;
  return !isPublicAddress(hostname);
}

export const _internals = {
  isPrivateAddress,
  normalizeHostname,
  resolveHostname,
};
