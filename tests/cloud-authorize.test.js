import { describe, it, expect } from 'vitest';
import {
  requirePermission,
  permissionForMethod,
  CloudAuthorizationError,
} from '../lib/cloud/authorize.js';

// ── requirePermission ────────────────────────────────────────────────────────

describe('requirePermission', () => {
  // Helpers
  function makeAuth(permissions) {
    return { tenantId: 'tenant-1', environment: 'production', permissions };
  }

  // Happy paths — exact match
  it('does not throw when auth has exact required permission (read)', () => {
    expect(() => requirePermission(makeAuth(['read']), 'read')).not.toThrow();
  });

  it('does not throw when auth has exact required permission (write)', () => {
    expect(() => requirePermission(makeAuth(['write']), 'write')).not.toThrow();
  });

  it('does not throw when auth has exact required permission (admin)', () => {
    expect(() => requirePermission(makeAuth(['admin']), 'admin')).not.toThrow();
  });

  // Hierarchy — higher satisfies lower
  it('write satisfies a read requirement', () => {
    expect(() => requirePermission(makeAuth(['write']), 'read')).not.toThrow();
  });

  it('admin satisfies a read requirement', () => {
    expect(() => requirePermission(makeAuth(['admin']), 'read')).not.toThrow();
  });

  it('admin satisfies a write requirement', () => {
    expect(() => requirePermission(makeAuth(['admin']), 'write')).not.toThrow();
  });

  // Hierarchy — lower does NOT satisfy higher
  it('read does not satisfy a write requirement', () => {
    expect(() => requirePermission(makeAuth(['read']), 'write')).toThrow(CloudAuthorizationError);
  });

  it('read does not satisfy an admin requirement', () => {
    expect(() => requirePermission(makeAuth(['read']), 'admin')).toThrow(CloudAuthorizationError);
  });

  it('write does not satisfy an admin requirement', () => {
    expect(() => requirePermission(makeAuth(['write']), 'admin')).toThrow(CloudAuthorizationError);
  });

  // Multiple permissions — any one is enough
  it('passes when at least one permission in the array satisfies the requirement', () => {
    expect(() => requirePermission(makeAuth(['read', 'write']), 'write')).not.toThrow();
  });

  it('passes when admin is among multiple permissions', () => {
    expect(() => requirePermission(makeAuth(['read', 'admin']), 'admin')).not.toThrow();
  });

  // Empty / missing permissions
  it('throws when permissions array is empty', () => {
    expect(() => requirePermission(makeAuth([]), 'read')).toThrow(CloudAuthorizationError);
  });

  it('throws when permissions contains only unknown strings', () => {
    expect(() => requirePermission(makeAuth(['superuser']), 'read')).toThrow(CloudAuthorizationError);
  });

  // No valid auth context
  it('throws CloudAuthorizationError when authResult is null', () => {
    expect(() => requirePermission(null, 'read')).toThrow(CloudAuthorizationError);
  });

  it('throws CloudAuthorizationError when authResult is undefined', () => {
    expect(() => requirePermission(undefined, 'read')).toThrow(CloudAuthorizationError);
  });

  it('throws when authResult.permissions is not an array', () => {
    expect(() => requirePermission({ permissions: 'read' }, 'read')).toThrow(CloudAuthorizationError);
  });

  it('throws when authResult.permissions is null', () => {
    expect(() => requirePermission({ permissions: null }, 'read')).toThrow(CloudAuthorizationError);
  });

  // Unknown required permission
  it('throws when requiredPermission is an unknown string', () => {
    expect(() => requirePermission(makeAuth(['admin']), 'superuser')).toThrow(CloudAuthorizationError);
  });

  // Error shape
  it('thrown error has name CloudAuthorizationError', () => {
    try {
      requirePermission(makeAuth(['read']), 'write');
    } catch (err) {
      expect(err.name).toBe('CloudAuthorizationError');
    }
  });

  it('thrown error exposes requiredPermission property', () => {
    try {
      requirePermission(makeAuth(['read']), 'admin');
    } catch (err) {
      expect(err.requiredPermission).toBe('admin');
    }
  });

  it('thrown error message mentions the required permission', () => {
    try {
      requirePermission(makeAuth([]), 'write');
    } catch (err) {
      expect(err.message).toContain('write');
    }
  });
});

// ── permissionForMethod ──────────────────────────────────────────────────────

describe('permissionForMethod', () => {
  it('maps GET to read', () => {
    expect(permissionForMethod('GET')).toBe('read');
  });

  it('maps HEAD to read', () => {
    expect(permissionForMethod('HEAD')).toBe('read');
  });

  it('maps OPTIONS to read', () => {
    expect(permissionForMethod('OPTIONS')).toBe('read');
  });

  it('maps POST to write', () => {
    expect(permissionForMethod('POST')).toBe('write');
  });

  it('maps PUT to write', () => {
    expect(permissionForMethod('PUT')).toBe('write');
  });

  it('maps PATCH to write', () => {
    expect(permissionForMethod('PATCH')).toBe('write');
  });

  it('maps DELETE to write', () => {
    expect(permissionForMethod('DELETE')).toBe('write');
  });

  it('is case-insensitive (get → read)', () => {
    expect(permissionForMethod('get')).toBe('read');
  });

  it('is case-insensitive (post → write)', () => {
    expect(permissionForMethod('post')).toBe('write');
  });

  it('defaults to read for unknown methods', () => {
    expect(permissionForMethod('CONNECT')).toBe('read');
  });

  it('defaults to read for null method', () => {
    expect(permissionForMethod(null)).toBe('read');
  });

  it('defaults to read for undefined method', () => {
    expect(permissionForMethod(undefined)).toBe('read');
  });
});

// ── CloudAuthorizationError ──────────────────────────────────────────────────

describe('CloudAuthorizationError', () => {
  it('is an instance of Error', () => {
    const err = new CloudAuthorizationError('denied', 'write');
    expect(err).toBeInstanceOf(Error);
  });

  it('stores message', () => {
    const err = new CloudAuthorizationError('Access denied', 'read');
    expect(err.message).toBe('Access denied');
  });

  it('stores requiredPermission', () => {
    const err = new CloudAuthorizationError('Nope', 'admin');
    expect(err.requiredPermission).toBe('admin');
  });

  it('has name CloudAuthorizationError', () => {
    const err = new CloudAuthorizationError('x', 'read');
    expect(err.name).toBe('CloudAuthorizationError');
  });
});
