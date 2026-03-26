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

import { getGitHubToken } from '@/lib/env';

// ============================================================================
// GitHub App Adapter
// ============================================================================

export async function fetchGitHubAppMeta(slug, options = {}) {
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

    let permissionClass = 'no_access';
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
  } catch (err) {
    return {
      software_meta: { host: 'github', _adapter_status: 'fetch_error', _error: err.message },
      raw: null,
    };
  }
}

// ============================================================================
// npm Package Adapter
// ============================================================================

export async function fetchNpmPackageMeta(packageName) {
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
  } catch (err) {
    return {
      software_meta: { host: 'npm', _adapter_status: 'fetch_error', _error: err.message },
      raw: null,
    };
  }
}

// ============================================================================
// MCP Server Adapter
// ============================================================================

/**
 * Validate that a URL does not point to a private/internal IP range.
 * SECURITY: Prevents SSRF attacks by blocking requests to internal networks.
 */
function isPrivateUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const hostname = parsed.hostname;
    // Block private IP ranges, localhost, and link-local
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('10.') ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('169.254.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      parsed.protocol === 'file:'
    ) {
      return true;
    }
    return false;
  } catch {
    return true; // Invalid URLs are treated as private/blocked
  }
}

export async function fetchMcpServerMeta(serverUrl) {
  // SECURITY: Validate URL before making any outbound requests to prevent SSRF
  if (!serverUrl || typeof serverUrl !== 'string' || isPrivateUrl(serverUrl)) {
    return {
      software_meta: {
        host: 'mcp',
        server_card_present: false,
        server_url: serverUrl,
        _adapter_status: 'blocked',
        _error: 'URL blocked by private IP validation',
      },
      raw: null,
    };
  }

  // MCP servers may expose a .well-known/mcp.json or Server Card
  try {
    // Try well-known discovery
    const baseUrl = serverUrl.replace(/\/+$/, '');
    const cardRes = await fetch(`${baseUrl}/.well-known/mcp.json`, {
      signal: AbortSignal.timeout(5000),
    });

    let serverCard = null;
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
  } catch (err) {
    return {
      software_meta: {
        host: 'mcp',
        server_card_present: false,
        server_url: serverUrl,
        _adapter_status: 'fetch_error',
        _error: err.message,
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
export async function fetchChromeExtensionMeta(extensionId) {
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
  } catch (err) {
    return {
      software_meta: { host: 'chrome', _adapter_status: 'error', _error: err.message },
      raw: null,
    };
  }
}

// ============================================================================
// Adapter Registry
// ============================================================================

const ADAPTERS = {
  github: fetchGitHubAppMeta,
  npm: fetchNpmPackageMeta,
  mcp: fetchMcpServerMeta,
  chrome: fetchChromeExtensionMeta,
};

/**
 * Fetch software metadata from the appropriate host adapter.
 * 
 * @param {string} host - Platform identifier (github, npm, mcp, chrome)
 * @param {string} identifier - Platform-specific entity identifier
 * @param {object} options - Adapter-specific options (tokens, etc.)
 * @returns {{ software_meta: object, raw: object|null }}
 */
export async function fetchSoftwareMeta(host, identifier, options = {}) {
  const adapter = ADAPTERS[host];
  if (!adapter) {
    return {
      software_meta: { host, _adapter_status: 'no_adapter', _note: `No adapter for host: ${host}` },
      raw: null,
    };
  }
  return adapter(identifier, options);
}
