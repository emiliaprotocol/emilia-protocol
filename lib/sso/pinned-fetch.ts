// SPDX-License-Identifier: Apache-2.0
//
// DNS-rebinding-safe fetch for server-side SSO/OIDC requests.
//
// The OIDC RP fetches tenant-influenced URLs server-side: the discovery
// document, the token endpoint (ships the tenant's client secret), and the
// JWKS. Each is host-validated up front, but Node's global fetch RE-RESOLVES
// the hostname independently at connect time — so a tenant controlling
// authoritative DNS for their issuer can pass the validation lookup with a
// public IP and then serve 169.254.169.254 / 10.x / 127.0.0.1 on the fetch
// (time-of-check/time-of-use DNS rebinding).
//
// safePinnedFetch closes that: it validates AND resolves in ONE step
// (validateSsoProviderUrl returns the exact validated public IP), then connects
// via node:https with a fixed `lookup` that always returns that IP — so no
// second, independent resolution can rebind. TLS SNI + certificate validation
// still use the real hostname, so pinning does not weaken transport security.
// Same technique the webhook deliverer uses (lib/cloud/webhooks.js).
//
// Returns a minimal fetch-Response shim (.ok/.status/.json()/.text()) — the only
// surface discover()/exchangeCode() and jose's remote-JWKS fetch consume.

import https from 'node:https';
import type * as dnsPromises from 'node:dns/promises';
import { validateSsoProviderUrl } from './url-policy.js';

const MAX_RESPONSE_BYTES = 1024 * 1024; // discovery/JWKS/token responses are tiny; cap defensively
const DEFAULT_TIMEOUT_MS = 10_000;

// Same shape as node:dns/promises' `lookup` — the only thing tests inject.
type PromiseLookupFn = typeof dnsPromises.lookup;

interface PinnedFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer | null;
  signal?: AbortSignal;
  timeoutMs?: number;
  // Accepted for fetch-API-call-site compatibility (callers pass 'error' to
  // document the SSRF posture they intend) but never read: this shim never
  // follows redirects regardless of the value — a 3xx always surfaces as a
  // non-2xx status, per the module comment above.
  redirect?: 'error' | 'manual' | 'follow';
}

interface PinnedFetchOpts {
  lookup?: PromiseLookupFn;
}

interface PinnedFetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<any>;
  text(): Promise<string>;
}

/**
 * @param input   the URL to fetch (tenant-influenced, re-validated here)
 * @param init    fetch-like init: { method, headers, body, signal, timeoutMs }
 * @param opts    { lookup } — injectable DNS lookup (tests only)
 */
export async function safePinnedFetch(
  input: string | URL,
  init: PinnedFetchInit = {},
  { lookup }: PinnedFetchOpts = {},
): Promise<PinnedFetchResponse> {
  const target = input instanceof URL ? input.href : String(input);

  // Validate + resolve in one shot; get back the exact public IP to pin to.
  const check = await validateSsoProviderUrl(target, 'sso_fetch_url', lookup ? { lookup } : undefined);
  if (!check.valid) {
    throw new Error(`SSRF-blocked SSO fetch (${(check as { valid: false; error: string }).error})`);
  }

  const url = new URL(target);
  const method = (init.method || 'GET').toUpperCase();
  const { address, family } = check;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,   // preserved for SNI + certificate validation
        servername: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method,
        headers: { ...(init.headers || {}), Host: url.host },
        // Pin the connection to the already-validated IP — no rebind possible.
        lookup: (_hostname, _options, cb) => cb(null, address, family || 4),
        timeout: init.timeoutMs || DEFAULT_TIMEOUT_MS,
      },
      (res) => {
        const status = res.statusCode || 0;
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (c) => {
          total += c.length;
          if (total <= MAX_RESPONSE_BYTES) chunks.push(c);
          else res.destroy(new Error('SSO response exceeded size cap'));
        });
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          // We never follow redirects (no `location` handling) — a 3xx surfaces
          // as a non-2xx status, which every caller treats as failure. This is
          // the redirect:'error'/'manual' SSRF posture the call sites intend.
          resolve({
            ok: status >= 200 && status < 300,
            status,
            async json() { return JSON.parse(text); },
            async text() { return text; },
          });
        });
        res.on('error', reject);
      },
    );

    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('SSO fetch timed out')));

    if (init.signal) {
      if (init.signal.aborted) req.destroy(new Error('SSO fetch aborted'));
      else init.signal.addEventListener('abort', () => req.destroy(new Error('SSO fetch aborted')), { once: true });
    }

    if (init.body != null) req.write(init.body);
    req.end();
  });
}
