/**
 * Tests for lib/adapters/github.js
 * Covers: getGitHubAppMetadata, verifyGitHubOrgControl, classifyGitHubPermissions
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  getGitHubAppMetadata,
  verifyGitHubOrgControl,
  classifyGitHubPermissions,
} from '@/lib/adapters/github.js';

function mockResponse(data, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(data),
  };
}

describe('getGitHubAppMetadata', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('returns error and available=false when API returns non-OK status', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 404 }));
    const result = await getGitHubAppMetadata('missing-app');
    expect(result.available).toBe(false);
    expect(result.error).toMatch('404');
  });

  it('returns full metadata object on success', async () => {
    const appData = {
      id: 12345,
      slug: 'my-app',
      name: 'My App',
      description: 'A great app',
      external_url: 'https://myapp.com',
      html_url: 'https://github.com/apps/my-app',
      created_at: '2022-01-01T00:00:00Z',
      updated_at: '2023-01-01T00:00:00Z',
      permissions: { contents: 'read', metadata: 'read' },
      events: ['push', 'pull_request'],
      installations_count: 50,
      owner: { login: 'acme', type: 'Organization' },
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await getGitHubAppMetadata('my-app', 'ghp_token');
    expect(result.available).toBe(true);
    expect(result.app_id).toBe(12345);
    expect(result.slug).toBe('my-app');
    expect(result.name).toBe('My App');
    expect(result.owner).toBe('acme');
    expect(result.owner_type).toBe('Organization');
    expect(result.description).toBe('A great app');
    expect(result.external_url).toBe('https://myapp.com');
    expect(result.permissions).toEqual({ contents: 'read', metadata: 'read' });
    expect(result.events).toEqual(['push', 'pull_request']);
    expect(result.installations_count).toBe(50);
  });

  it('populates trust_signals correctly', async () => {
    const appData = {
      id: 1,
      slug: 'test',
      name: 'Test',
      description: 'Desc',
      external_url: 'https://example.com',
      html_url: 'https://github.com/apps/test',
      created_at: new Date(Date.now() - 10 * 86400000).toISOString(),
      updated_at: new Date().toISOString(),
      permissions: { contents: 'read', metadata: 'read' },
      events: ['push'],
      installations_count: 100,
      owner: { login: 'corp', type: 'Organization' },
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await getGitHubAppMetadata('test');
    expect(result.trust_signals.publisher_is_org).toBe(true);
    expect(result.trust_signals.has_description).toBe(true);
    expect(result.trust_signals.has_external_url).toBe(true);
    expect(result.trust_signals.permission_count).toBe(2);
    expect(result.trust_signals.event_count).toBe(1);
    expect(result.trust_signals.installations).toBe(100);
    expect(result.trust_signals.age_days).toBeGreaterThanOrEqual(10);
  });

  it('sets publisher_is_org=false for User type owner', async () => {
    const appData = {
      id: 2,
      slug: 'user-app',
      name: 'User App',
      description: '',
      external_url: null,
      html_url: '',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
      permissions: {},
      events: [],
      installations_count: 0,
      owner: { login: 'dev', type: 'User' },
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await getGitHubAppMetadata('user-app');
    expect(result.trust_signals.publisher_is_org).toBe(false);
  });

  it('adds Authorization header when token is provided', async () => {
    fetch.mockResolvedValue(mockResponse({
      id: 1, slug: 'x', name: 'X', description: '', external_url: null, html_url: '',
      created_at: '2023-01-01T00:00:00Z', updated_at: '2023-06-01T00:00:00Z',
      permissions: {}, events: [], installations_count: 0, owner: { login: 'o', type: 'User' },
    }));
    await getGitHubAppMetadata('x', 'ghp_abc123');
    expect(fetch).toHaveBeenCalledWith(
      'https://api.github.com/apps/x',
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer ghp_abc123' }) })
    );
  });

  it('does not include Authorization header when no token', async () => {
    fetch.mockResolvedValue(mockResponse({
      id: 1, slug: 'x', name: 'X', description: '', external_url: null, html_url: '',
      created_at: '2023-01-01T00:00:00Z', updated_at: '2023-06-01T00:00:00Z',
      permissions: {}, events: [], installations_count: 0, owner: { login: 'o', type: 'User' },
    }));
    await getGitHubAppMetadata('x');
    const callHeaders = fetch.mock.calls[0][1].headers;
    expect(callHeaders).not.toHaveProperty('Authorization');
  });

  it('returns error and available=false when fetch throws', async () => {
    fetch.mockRejectedValue(new Error('Network error'));
    const result = await getGitHubAppMetadata('err-app', 'token');
    expect(result.available).toBe(false);
    expect(result.error).toBe('Network error');
  });

  it('handles missing events array gracefully', async () => {
    const appData = {
      id: 3,
      slug: 'no-events',
      name: 'No Events',
      description: 'desc',
      external_url: null,
      html_url: '',
      created_at: '2023-01-01T00:00:00Z',
      updated_at: '2023-06-01T00:00:00Z',
      permissions: { metadata: 'read' },
      // events intentionally omitted
      installations_count: 5,
      owner: { login: 'dev', type: 'User' },
    };
    fetch.mockResolvedValue(mockResponse(appData));
    const result = await getGitHubAppMetadata('no-events');
    expect(result.events).toEqual([]);
    expect(result.trust_signals.event_count).toBe(0);
  });
});

describe('verifyGitHubOrgControl', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('returns verified=false and reason when token is missing', async () => {
    const result = await verifyGitHubOrgControl('acme-org', null);
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/Token required/);
  });

  it('returns verified=false when API returns non-OK', async () => {
    fetch.mockResolvedValue(mockResponse(null, { ok: false, status: 403 }));
    const result = await verifyGitHubOrgControl('acme-org', 'ghp_token');
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch('403');
  });

  it('returns verified=true when membership role is admin', async () => {
    fetch.mockResolvedValue(mockResponse({ role: 'admin', state: 'active' }));
    const result = await verifyGitHubOrgControl('acme-org', 'ghp_token');
    expect(result.verified).toBe(true);
    expect(result.role).toBe('admin');
    expect(result.state).toBe('active');
    expect(result.org).toBe('acme-org');
  });

  it('returns verified=false when membership role is member (not admin)', async () => {
    fetch.mockResolvedValue(mockResponse({ role: 'member', state: 'active' }));
    const result = await verifyGitHubOrgControl('acme-org', 'ghp_token');
    expect(result.verified).toBe(false);
    expect(result.role).toBe('member');
  });

  it('returns verified=false and reason when fetch throws', async () => {
    fetch.mockRejectedValue(new Error('Timeout'));
    const result = await verifyGitHubOrgControl('acme-org', 'ghp_token');
    expect(result.verified).toBe(false);
    expect(result.reason).toBe('Timeout');
  });

  it('sends Authorization header with bearer token', async () => {
    fetch.mockResolvedValue(mockResponse({ role: 'admin', state: 'active' }));
    await verifyGitHubOrgControl('acme-org', 'ghp_secret');
    expect(fetch).toHaveBeenCalledWith(
      'https://api.github.com/orgs/acme-org/memberships',
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer ghp_secret' }) })
    );
  });
});

describe('classifyGitHubPermissions', () => {
  it('returns "dangerous" when a dangerous perm has write access', () => {
    expect(classifyGitHubPermissions({ administration: 'write', metadata: 'read' })).toBe('dangerous');
    expect(classifyGitHubPermissions({ organization_administration: 'write' })).toBe('dangerous');
    expect(classifyGitHubPermissions({ members: 'write' })).toBe('dangerous');
    expect(classifyGitHubPermissions({ organization_secrets: 'write' })).toBe('dangerous');
    expect(classifyGitHubPermissions({ actions: 'write' })).toBe('dangerous');
  });

  it('returns "sensitive" when a sensitive perm has write access (no dangerous writes)', () => {
    expect(classifyGitHubPermissions({ contents: 'write' })).toBe('sensitive');
    expect(classifyGitHubPermissions({ issues: 'write' })).toBe('sensitive');
    expect(classifyGitHubPermissions({ pull_requests: 'write' })).toBe('sensitive');
    expect(classifyGitHubPermissions({ workflows: 'write' })).toBe('sensitive');
    expect(classifyGitHubPermissions({ packages: 'write' })).toBe('sensitive');
  });

  it('returns "moderate" when there are write perms not in dangerous/sensitive lists', () => {
    expect(classifyGitHubPermissions({ statuses: 'write' })).toBe('moderate');
    expect(classifyGitHubPermissions({ checks: 'write' })).toBe('moderate');
  });

  it('returns "read_only" when permissions exist but none are write', () => {
    expect(classifyGitHubPermissions({ metadata: 'read', checks: 'read' })).toBe('read_only');
    expect(classifyGitHubPermissions({ contents: 'read' })).toBe('read_only');
  });

  it('returns "minimal" when permissions object is empty', () => {
    expect(classifyGitHubPermissions({})).toBe('minimal');
  });

  it('dangerous takes priority over sensitive (both present as write)', () => {
    const perms = { administration: 'write', contents: 'write', metadata: 'read' };
    expect(classifyGitHubPermissions(perms)).toBe('dangerous');
  });

  it('sensitive takes priority over moderate', () => {
    const perms = { contents: 'write', statuses: 'write' };
    expect(classifyGitHubPermissions(perms)).toBe('sensitive');
  });

  it('handles admin access value (not just write)', () => {
    // "admin" is not "write", so should not trigger write logic — only read_only
    const perms = { metadata: 'admin' };
    // admin !== 'write' and key exists → read_only
    expect(classifyGitHubPermissions(perms)).toBe('read_only');
  });
});
