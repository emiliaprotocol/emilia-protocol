/**
 * EP-SX Host Adapters
 *
 * Each adapter normalizes platform-specific trust signals into
 * EP's software_meta format. This lets the pre-action enforcement endpoint
 * check platform-native properties without knowing platform internals.
 *
 * Adapter interface:
 *   async fetchSoftwareMeta(entityId, options) → { software_meta, raw }
 *
 * @license Apache-2.0
 */

import net from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import { getGitHubToken } from '@/lib/env';

/**
 * Normalized software metadata returned by every host adapter. `host`
 * identifies the adapter; the remaining fields vary per adapter, hence the
 * index signature for the adapter-specific extras.
 */
export interface SoftwareMeta {
  host: string;
  _adapter_status?: string;
  _status?: number;
  _error?: string;
  _note?: string;
  [key: string]: unknown;
}

export interface AdapterFetchResult {
  software_meta: SoftwareMeta;
  raw: unknown;
}

export interface GitHubAppAdapterOptions {
  github_token?: string;
  [key: string]: unknown;
}

// ============================================================================
// GitHub App Adapter
// ============================================================================

export async function fetchGitHubAppMeta(
  slug: string,
  options: GitHubAppAdapterOptions = {}
): Promise<AdapterFetchResult> {
  // slug format: "owner/app-name" or GitHub App slug
  const token = options.github_token || getGitHubToken();

  if (!token) {
    return {
      software_meta: { host: 'github', _adapter_status: 'no_token' },
      raw: null,
    };
  }

  try {
    // Fetch app metadata from GitHub API
    const res = await fetch(`https://api.github.com/apps/${slug}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!res.ok) {
      return {
        software_meta: { host: 'github', _adapter_status: 'api_error', _status: res.status },
        raw: null,
      };
    }

    const app = await res.json();

    // Normalize into EP software_meta
    const permissions = app.permissions || {};
    const permissionKeys = Object.keys(permissions);
    const hasWritePerms = Object.values(permissions).some(v => v === 'write');
    const hasAdminPerms = Object.values(permissions).some(v => v === 'admin');

    let permissionClass: 'no_access' | 'admin' | 'read_write' | 'read_only' = 'no_access';
    if (hasAdminPerms) permissionClass = 'admin';
    else if (hasWritePerms) permissionClass = 'read_write';
    else if (permissionKeys.length > 0) permissionClass = 'read_only';

    return {
      software_meta: {
        host: 'github',
        publisher_verified: !!app.owner?.verified || app.owner?.type === 'Organization',
        publisher_name: app.owner?.login || null,
        permission_class: permissionClass,
        permissions_declared: permissionKeys,
        install_scope: null, // Determined at install time, not app level
        registry_listed: !!app.external_url,
        created_at: app.created_at,
        updated_at: app.updated_at,
        _adapter_status: 'ok',
      },
      raw: app,
    };
  } catch (err: unknown) {
    return {
      software_meta: { host: 'github', _adapter_status: 'fetch_error', _error: err instanceof Error ? err.message : String(err) },
      raw: null,
    };
  }
}

// ============================================================================
// npm Package Adapter
// ============================================================================

export async function fetchNpmPackageMeta(packageName: string): Promise<AdapterFetchResult> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
    if (!res.ok) {
      return {
        software_meta: { host: 'npm', _adapter_status: 'not_found' },
        raw: null,
      };
    }

    const pkg = await res.json();
    const latest = pkg['dist-tags']?.latest;
    const latestVersion = latest ? pkg.versions?.[latest] : null;

    // Check for provenance / attestations
    const hasProvenance = !!(latestVersion?.dist?.attestations || latestVersion?.dist?.signatures?.length);
    const publisher = latestVersion?._npmUser?.name || pkg.maintainers?.[0]?.name || null;

    return {
      software_meta: {
        host: 'npm',
        publisher_verified: !!publisher,
        publisher_name: publisher,
        provenance_verified: hasProvenance,
        trusted_publishing: hasProvenance,
        latest_version: latest,
        license: latestVersion?.license || pkg.license || null,
        maintainer_count: (pkg.maintainers || []).length,
        created_at: pkg.time?.created || null,
        last_published: pkg.time?.[latest] || null,
        registry_listed: true,
        _adapter_status: 'ok',
      },
      raw: { name: pkg.name, description: pkg.description, latest, maintainers: pkg.maintainers },
    };
  } catch (err: unknown) {
    return {
      software_meta: { host: 'npm', _adapter_status: 'fetch_error', _error: err instanceof Error ? err.message : String(err) },
      raw: null,
    };
  }
}

// ============================================================================
// MCP Server Adapter
// ============================================================================

function normalizeHostname(hostname: unknown): string {
  return String(hostname || '')
    .trim()
    .replace(/^\[(.*)\]$/, '$1')
    .replace(/\.$/, '')
    .toLowerCase();
}

function isPrivateIp(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    const [a, b] = host.split('.').map((p) => Number(p));
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
  if (ipVersion === 6) {
    const mapped = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return (
      host === '::' ||
      host === '::1' ||
      host.startsWith('fc') ||
      host.startsWith('fd') ||
      host.startsWith('fe80:') ||
      host.startsWith('ff')
    );
  }
  return false;
}

function isBlockedHostname(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  return (
    !host ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    isPrivateIp(host)
  );
}

async function resolvesPublicly(hostname: string): Promise<boolean> {
  const host = normalizeHostname(hostname);
  if (net.isIP(host)) return !isPrivateIp(host);
  try {
    // dns.lookup's overload resolution doesn't reliably pick the `all: true`
    // (array-returning) signature for an inline options literal; the original
    // JSDoc-typed source carried the same explicit cast for this reason.
    const records = await dnsLookup(host, { all: true, verbatim: true }) as import('node:dns').LookupAddress[] | import('node:dns').LookupAddress;
    const addresses = Array.isArray(records)
      ? records.map((r) => r.address).filter(Boolean)
      : [records?.address].filter(Boolean);
    return addresses.length > 0 && addresses.every((addr) => !isPrivateIp(addr));
  } catch {
    return false;
  }
}

type PublicFetchUrlResult = { ok: true; url: string } | { ok: false; error: string };

/**
 * Validate that a URL does not point to a private/internal IP range.
 * SECURITY: Prevents SSRF attacks by blocking literal private hosts AND
 * public-looking DNS names that resolve to private/link-local addresses.
 */
async function validatePublicFetchUrl(urlStr: string): Promise<PublicFetchUrlResult> {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { ok: false, error: 'invalid URL' };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'unsupported URL protocol' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'URL credentials are not allowed' };
  }
  if (isBlockedHostname(parsed.hostname)) {
    return { ok: false, error: 'URL targets a private or internal host' };
  }
  if (!(await resolvesPublicly(parsed.hostname))) {
    return { ok: false, error: 'URL host does not resolve publicly' };
  }
  parsed.hash = '';
  return { ok: true, url: parsed.toString() };
}

export async function fetchMcpServerMeta(serverUrl: unknown): Promise<AdapterFetchResult> {
  // SECURITY: Validate URL before making any outbound requests to prevent SSRF
  const validated: PublicFetchUrlResult = typeof serverUrl === 'string'
    ? await validatePublicFetchUrl(serverUrl)
    : { ok: false, error: 'missing URL' };
  if (!validated.ok) {
    return {
      software_meta: {
        host: 'mcp',
        server_card_present: false,
        server_url: serverUrl,
        _adapter_status: 'blocked',
        _error: 'URL blocked by public-network validation',
      },
      raw: null,
    };
  }

  // MCP servers may expose a .well-known/mcp.json or Server Card
  try {
    // Try well-known discovery
    // validated.ok is guaranteed true here (blocked case returned above), so
    // validated is the { ok: true, url: string } branch of validatePublicFetchUrl's result.
    const baseUrl = validated.url.replace(/\/+$/, '');
    const cardRes = await fetch(`${baseUrl}/.well-known/mcp.json`, {
      signal: AbortSignal.timeout(5000),
      redirect: 'manual',
    });

    let serverCard: any = null;
    if (cardRes.ok) {
      serverCard = await cardRes.json();
    }

    return {
      software_meta: {
        host: 'mcp',
        server_card_present: !!serverCard,
        publisher_verified: !!serverCard?.publisher?.verified,
        publisher_name: serverCard?.publisher?.name || null,
        capabilities: serverCard?.capabilities || [],
        permission_class: serverCard?.permission_class || 'bounded_external_access',
        registry_listed: !!serverCard?.registry_url,
        server_url: serverUrl,
        _adapter_status: serverCard ? 'ok' : 'no_server_card',
      },
      raw: serverCard,
    };
  } catch (err: unknown) {
    return {
      software_meta: {
        host: 'mcp',
        server_card_present: false,
        server_url: serverUrl,
        _adapter_status: 'fetch_error',
        _error: err instanceof Error ? err.message : String(err),
      },
      raw: null,
    };
  }
}

// ============================================================================
// Chrome Extension Adapter
// ============================================================================

/**
 * @experimental Chrome adapter — not yet production-ready. Contributions welcome.
 */
export async function fetchChromeExtensionMeta(extensionId: string): Promise<AdapterFetchResult> {
  // Chrome Web Store doesn't have a public API for extension metadata.
  // This adapter uses what's publicly available.
  try {
    // The Chrome Web Store detail page can be scraped for basic info,
    // but a proper integration would use the Chrome Web Store API (restricted).
    // For now, return an experimental shell that can be populated from listing_review receipts.
    return {
      software_meta: {
        host: 'chrome',
        extension_id: extensionId,
        listing_review_passed: null, // Must be populated from external receipt
        publisher_verified: null,
        permission_class: null, // Must be extracted from manifest
        site_scope: null,
        _adapter_status: 'experimental',
        _note: 'Chrome Web Store does not provide a public metadata API. Populate via listing_review receipts.',
      },
      raw: null,
    };
  } catch (err: unknown) {
    return {
      software_meta: { host: 'chrome', _adapter_status: 'error', _error: err instanceof Error ? err.message : String(err) },
      raw: null,
    };
  }
}

// ============================================================================
// Adapter Registry
// ============================================================================

type Adapter = (identifier: string, options?: Record<string, unknown>) => Promise<AdapterFetchResult>;

const ADAPTERS: Record<string, Adapter> = {
  github: fetchGitHubAppMeta,
  npm: fetchNpmPackageMeta,
  mcp: fetchMcpServerMeta,
  chrome: fetchChromeExtensionMeta,
};

/**
 * Fetch software metadata from the appropriate host adapter.
 *
 * @param host - Platform identifier (github, npm, mcp, chrome)
 * @param identifier - Platform-specific entity identifier
 * @param options - Adapter-specific options (tokens, etc.)
 */
export async function fetchSoftwareMeta(
  host: string,
  identifier: string,
  options: Record<string, unknown> = {}
): Promise<AdapterFetchResult> {
  const adapter = ADAPTERS[host];
  if (!adapter) {
    return {
      software_meta: { host, _adapter_status: 'no_adapter', _note: `No adapter for host: ${host}` },
      raw: null,
    };
  }
  return adapter(identifier, options);
}
