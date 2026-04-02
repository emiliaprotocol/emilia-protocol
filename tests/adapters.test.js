/**
 * Tests for lib/adapters/index.js
 * Covers: fetchGitHubAppMeta, fetchNpmPackageMeta, fetchMcpServerMeta,
 *         fetchChromeExtensionMeta, fetchSoftwareMeta (registry dispatch)
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// Mock env module before importing adapters
vi.mock('@/lib/env', () => ({
  getGitHubToken: vi.fn(),
}));

import { getGitHubToken } from '@/lib/env';
import {
  fetchGitHubAppMeta,
  fetchNpmPackageMeta,
  fetchMcpServerMeta,
  fetchChromeExtensionMeta,
  fetchSoftwareMeta,
} from '@/lib/adapters/index.js';

// Helper to build a mock Response
function mockResponse(data, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(data),
  };
}

describe('fetchGitHubAppMeta', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    getGitHubToken.mockReturnValue('ghp_token123');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('returns no_token status when token is absent and none passed in options', async () => {
    getGitHubToken.mockReturnValue(null);
    const result = await fetchGitHubAppMeta('some-app', {});
    expect(result.software_meta._adapter_status).toBe('no_token');
    expect(result.software_meta.host).toBe('github');
    expect(result.raw).toBeNull();
  });

  it('uses token from options when provided (overrides env)', async () => {
    const appData = {
      id: 42,
      owner: { login: 'acme', type: 'Organization', verified: false },
      permissions: {},
      external_url: 'https://acme.com',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('acme-app', { github_token: 'opt_token' });
    expect(result.software_meta._adapter_status).toBe('ok');
    // options token was used; fetch should have been called
    expect(fetch).toHaveBeenCalledWith(
      'https://api.github.com/apps/acme-app',
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer opt_token' }) })
    );
  });

  it('returns api_error status when GitHub responds non-OK', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 404 }));
    const result = await fetchGitHubAppMeta('missing-app');
    expect(result.software_meta._adapter_status).toBe('api_error');
    expect(result.software_meta._status).toBe(404);
    expect(result.raw).toBeNull();
  });

  it('assigns permission_class=admin when any permission is "admin"', async () => {
    const appData = {
      owner: { login: 'acme', type: 'User', verified: false },
      permissions: { administration: 'admin', metadata: 'read' },
      external_url: 'https://acme.com',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('admin-app');
    expect(result.software_meta.permission_class).toBe('admin');
  });

  it('assigns permission_class=read_write when any permission is "write"', async () => {
    const appData = {
      owner: { login: 'acme', type: 'User', verified: false },
      permissions: { contents: 'write', metadata: 'read' },
      external_url: null,
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('write-app');
    expect(result.software_meta.permission_class).toBe('read_write');
  });

  it('assigns permission_class=read_only when permissions exist but none are write/admin', async () => {
    const appData = {
      owner: { login: 'acme', type: 'User', verified: false },
      permissions: { metadata: 'read', checks: 'read' },
      external_url: null,
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('read-app');
    expect(result.software_meta.permission_class).toBe('read_only');
  });

  it('assigns permission_class=no_access when permissions object is empty', async () => {
    const appData = {
      owner: { login: 'acme', type: 'User', verified: false },
      permissions: {},
      external_url: null,
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('no-perms-app');
    expect(result.software_meta.permission_class).toBe('no_access');
  });

  it('sets publisher_verified=true for Organization type owner', async () => {
    const appData = {
      owner: { login: 'orgname', type: 'Organization', verified: false },
      permissions: {},
      external_url: 'https://example.com',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('org-app');
    expect(result.software_meta.publisher_verified).toBe(true);
    expect(result.software_meta.publisher_name).toBe('orgname');
  });

  it('sets registry_listed=true when external_url is present', async () => {
    const appData = {
      owner: { login: 'acme', type: 'User', verified: false },
      permissions: {},
      external_url: 'https://acme.com/app',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('listed-app');
    expect(result.software_meta.registry_listed).toBe(true);
  });

  it('returns fetch_error status when network throws', async () => {
    fetch.mockRejectedValue(new Error('Network failure'));
    const result = await fetchGitHubAppMeta('broken-app');
    expect(result.software_meta._adapter_status).toBe('fetch_error');
    expect(result.software_meta._error).toBe('Network failure');
    expect(result.raw).toBeNull();
  });

  it('includes raw app data on successful response', async () => {
    const appData = {
      id: 99,
      owner: { login: 'test', type: 'User', verified: false },
      permissions: { metadata: 'read' },
      external_url: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-06-01T00:00:00Z',
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await fetchGitHubAppMeta('test-app');
    expect(result.raw).toEqual(appData);
  });
});

describe('fetchNpmPackageMeta', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('returns not_found status when registry returns non-OK', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 404 }));
    const result = await fetchNpmPackageMeta('nonexistent-pkg');
    expect(result.software_meta._adapter_status).toBe('not_found');
    expect(result.software_meta.host).toBe('npm');
  });

  it('returns ok status with normalized data for a valid package', async () => {
    const pkgData = {
      name: 'my-pkg',
      description: 'A test package',
      'dist-tags': { latest: '1.2.3' },
      versions: {
        '1.2.3': {
          license: 'MIT',
          _npmUser: { name: 'authorname' },
          dist: { attestations: { url: 'https://example.com', provenance: {} } },
        },
      },
      maintainers: [{ name: 'authorname', email: 'a@b.com' }],
      time: { created: '2022-01-01T00:00:00Z', '1.2.3': '2023-06-01T00:00:00Z' },
    };
    fetch.mockResolvedValue(mockResponse(pkgData));
    const result = await fetchNpmPackageMeta('my-pkg');
    expect(result.software_meta._adapter_status).toBe('ok');
    expect(result.software_meta.host).toBe('npm');
    expect(result.software_meta.latest_version).toBe('1.2.3');
    expect(result.software_meta.license).toBe('MIT');
    expect(result.software_meta.publisher_name).toBe('authorname');
    expect(result.software_meta.provenance_verified).toBe(true);
    expect(result.software_meta.maintainer_count).toBe(1);
  });

  it('sets provenance_verified=false when no attestations or signatures', async () => {
    const pkgData = {
      name: 'no-prov',
      'dist-tags': { latest: '1.0.0' },
      versions: {
        '1.0.0': {
          license: 'ISC',
          dist: {},
        },
      },
      maintainers: [{ name: 'dev' }],
      time: { created: '2022-01-01T00:00:00Z' },
    };
    fetch.mockResolvedValue(mockResponse(pkgData));
    const result = await fetchNpmPackageMeta('no-prov');
    expect(result.software_meta.provenance_verified).toBe(false);
    expect(result.software_meta.trusted_publishing).toBe(false);
  });

  it('sets provenance_verified=true when dist.signatures has entries', async () => {
    const pkgData = {
      name: 'signed-pkg',
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '2.0.0': {
          dist: { signatures: [{ keyid: 'key1', sig: 'abc' }] },
        },
      },
      maintainers: [{ name: 'dev' }],
      time: {},
    };
    fetch.mockResolvedValue(mockResponse(pkgData));
    const result = await fetchNpmPackageMeta('signed-pkg');
    expect(result.software_meta.provenance_verified).toBe(true);
  });

  it('always sets registry_listed=true for npm packages', async () => {
    const pkgData = {
      name: 'any-pkg',
      'dist-tags': { latest: '0.1.0' },
      versions: { '0.1.0': {} },
      maintainers: [],
      time: {},
    };
    fetch.mockResolvedValue(mockResponse(pkgData));
    const result = await fetchNpmPackageMeta('any-pkg');
    expect(result.software_meta.registry_listed).toBe(true);
  });

  it('returns fetch_error when network throws', async () => {
    fetch.mockRejectedValue(new Error('DNS failure'));
    const result = await fetchNpmPackageMeta('bad-pkg');
    expect(result.software_meta._adapter_status).toBe('fetch_error');
    expect(result.software_meta._error).toBe('DNS failure');
  });

  it('includes raw summary with name, description, latest, maintainers', async () => {
    const pkgData = {
      name: 'sum-pkg',
      description: 'Summary pkg',
      'dist-tags': { latest: '3.0.0' },
      versions: { '3.0.0': {} },
      maintainers: [{ name: 'me' }],
      time: {},
    };
    fetch.mockResolvedValue(mockResponse(pkgData));
    const result = await fetchNpmPackageMeta('sum-pkg');
    expect(result.raw).toMatchObject({ name: 'sum-pkg', description: 'Summary pkg', latest: '3.0.0' });
  });
});

describe('fetchMcpServerMeta', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    vi.stubGlobal('AbortSignal', { timeout: vi.fn().mockReturnValue({}) });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('blocks null serverUrl with blocked status', async () => {
    const result = await fetchMcpServerMeta(null);
    expect(result.software_meta._adapter_status).toBe('blocked');
    expect(result.raw).toBeNull();
  });

  it('blocks localhost URLs', async () => {
    const result = await fetchMcpServerMeta('http://localhost:3000/mcp');
    expect(result.software_meta._adapter_status).toBe('blocked');
  });

  it('blocks 127.0.0.1 URLs', async () => {
    const result = await fetchMcpServerMeta('http://127.0.0.1/mcp');
    expect(result.software_meta._adapter_status).toBe('blocked');
  });

  it('blocks private 192.168.x.x range', async () => {
    const result = await fetchMcpServerMeta('http://192.168.1.1/mcp');
    expect(result.software_meta._adapter_status).toBe('blocked');
  });

  it('blocks 10.x.x.x private range', async () => {
    const result = await fetchMcpServerMeta('http://10.0.0.1/mcp');
    expect(result.software_meta._adapter_status).toBe('blocked');
  });

  it('blocks .local hostnames', async () => {
    const result = await fetchMcpServerMeta('http://myserver.local/mcp');
    expect(result.software_meta._adapter_status).toBe('blocked');
  });

  it('returns ok status with server card when .well-known/mcp.json responds OK', async () => {
    const serverCard = {
      publisher: { name: 'MCP Corp', verified: true },
      capabilities: ['tools', 'resources'],
      permission_class: 'read_only',
      registry_url: 'https://registry.example.com/mcp-corp',
    };
    fetch.mockResolvedValue(mockResponse(serverCard));
    const result = await fetchMcpServerMeta('https://mcp.example.com');
    expect(result.software_meta._adapter_status).toBe('ok');
    expect(result.software_meta.server_card_present).toBe(true);
    expect(result.software_meta.publisher_verified).toBe(true);
    expect(result.software_meta.publisher_name).toBe('MCP Corp');
    expect(result.software_meta.capabilities).toEqual(['tools', 'resources']);
    expect(result.software_meta.registry_listed).toBe(true);
    expect(result.raw).toEqual(serverCard);
  });

  it('returns no_server_card status when well-known responds non-OK', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 404 }));
    const result = await fetchMcpServerMeta('https://mcp.example.com');
    expect(result.software_meta._adapter_status).toBe('no_server_card');
    expect(result.software_meta.server_card_present).toBe(false);
  });

  it('returns fetch_error status when network throws', async () => {
    fetch.mockRejectedValue(new Error('Timeout'));
    const result = await fetchMcpServerMeta('https://mcp.example.com');
    expect(result.software_meta._adapter_status).toBe('fetch_error');
    expect(result.software_meta._error).toBe('Timeout');
  });

  it('strips trailing slashes before appending .well-known path', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 404 }));
    await fetchMcpServerMeta('https://mcp.example.com///');
    expect(fetch).toHaveBeenCalledWith(
      'https://mcp.example.com/.well-known/mcp.json',
      expect.anything()
    );
  });

  it('defaults permission_class to bounded_external_access when card has none', async () => {
    const serverCard = { publisher: { name: 'X', verified: false } };
    fetch.mockResolvedValue(mockResponse(serverCard));
    const result = await fetchMcpServerMeta('https://mcp.example.com');
    expect(result.software_meta.permission_class).toBe('bounded_external_access');
  });
});

describe('fetchChromeExtensionMeta', () => {
  it('returns experimental status for any extension id', async () => {
    const result = await fetchChromeExtensionMeta('abc123def456');
    expect(result.software_meta._adapter_status).toBe('experimental');
    expect(result.software_meta.host).toBe('chrome');
    expect(result.software_meta.extension_id).toBe('abc123def456');
  });

  it('has null listing_review_passed and publisher_verified by default', async () => {
    const result = await fetchChromeExtensionMeta('xyz789');
    expect(result.software_meta.listing_review_passed).toBeNull();
    expect(result.software_meta.publisher_verified).toBeNull();
    expect(result.software_meta.permission_class).toBeNull();
    expect(result.software_meta.site_scope).toBeNull();
  });

  it('raw is always null for the experimental adapter', async () => {
    const result = await fetchChromeExtensionMeta('test-id');
    expect(result.raw).toBeNull();
  });
});

describe('fetchSoftwareMeta (registry dispatch)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    getGitHubToken.mockReturnValue(null);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('dispatches to github adapter for host=github', async () => {
    // No token → fast return path
    const result = await fetchSoftwareMeta('github', 'some-app');
    expect(result.software_meta.host).toBe('github');
  });

  it('dispatches to npm adapter for host=npm', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 404 }));
    const result = await fetchSoftwareMeta('npm', 'some-pkg');
    expect(result.software_meta.host).toBe('npm');
  });

  it('dispatches to chrome adapter for host=chrome', async () => {
    const result = await fetchSoftwareMeta('chrome', 'some-extension-id');
    expect(result.software_meta.host).toBe('chrome');
    expect(result.software_meta._adapter_status).toBe('experimental');
  });

  it('returns no_adapter status for unknown host', async () => {
    const result = await fetchSoftwareMeta('slack', 'some-app');
    expect(result.software_meta._adapter_status).toBe('no_adapter');
    expect(result.software_meta.host).toBe('slack');
    expect(result.raw).toBeNull();
  });

  it('passes options through to the github adapter', async () => {
    const result = await fetchSoftwareMeta('github', 'my-app', { github_token: 'test_tok' });
    // token was provided in options, so fetch should be called
    expect(fetch).toHaveBeenCalled();
  });

  it('dispatches mcp and passes identifier as serverUrl', async () => {
    // Blocked URL — fast path without fetch
    const result = await fetchSoftwareMeta('mcp', 'http://localhost/mcp');
    expect(result.software_meta.host).toBe('mcp');
    expect(result.software_meta._adapter_status).toBe('blocked');
  });
});
