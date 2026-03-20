import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

// =============================================================================
// Middleware Route Policy Tests
//
// Asserts that the ROUTE_POLICIES metadata in middleware.js accurately reflects
// the actual auth requirements of each route handler. Public form-submission
// endpoints must have useAuth: false; authenticated endpoints must have
// useAuth: true.
// =============================================================================

// Parse ROUTE_POLICIES from middleware.js source (avoids ESM/Next.js import issues)
function parseRoutePolicies() {
  const src = fs.readFileSync(path.resolve(__dirname, '../middleware.js'), 'utf-8');
  const match = src.match(/const ROUTE_POLICIES\s*=\s*\{([\s\S]*?)\n\};/);
  if (!match) throw new Error('Could not parse ROUTE_POLICIES from middleware.js');

  const entries = {};
  // Match lines like:  'POST /api/operators/apply':  { rateCategory: 'submit', useAuth: false },
  const lineRe = /['"](\w+ \/api\/[^'"]+)['"]\s*:\s*\{\s*rateCategory:\s*'([^']+)',\s*useAuth:\s*(true|false)\s*\}/g;
  let m;
  while ((m = lineRe.exec(match[1]))) {
    entries[m[1]] = { rateCategory: m[2], useAuth: m[3] === 'true' };
  }
  return entries;
}

// Scan a route handler file for "No auth required" or similar public markers.
// Returns true (public), false (requires API-key auth), or null (can't determine).
function isRoutePublic(routeFilePath) {
  if (!fs.existsSync(routeFilePath)) return null; // can't determine
  const src = fs.readFileSync(routeFilePath, 'utf-8');

  // Internal/cron routes use CRON_SECRET, not API-key auth — skip these
  if (/CRON_SECRET|@internal|@access\s+cron/i.test(src)) return null;

  // Public markers: "No auth required", "public", no API key validation
  const publicMarkers = [
    /no\s+auth\s+required/i,
    /public\s+(application|signup|form|submission|endpoint)/i,
  ];
  const authMarkers = [
    /getApiKey|validateApiKey|requireAuth|authenticateRequest|x-api-key/i,
  ];
  const hasPublicMarker = publicMarkers.some((re) => re.test(src));
  const hasAuthMarker = authMarkers.some((re) => re.test(src));
  if (hasPublicMarker && !hasAuthMarker) return true;
  if (hasAuthMarker && !hasPublicMarker) return false;
  return null; // ambiguous
}

// Map a policy route pattern to a filesystem route file
function policyKeyToFilePath(policyKey) {
  // e.g. 'POST /api/operators/apply' -> 'app/api/operators/apply/route.js'
  const parts = policyKey.split(' ');
  const urlPath = parts[1];
  // Replace wildcard segments with a placeholder directory name
  const fsPath = urlPath.replace(/\/\*/g, '/[id]');
  return path.resolve(__dirname, '..', `app${fsPath}/route.js`);
}

const policies = parseRoutePolicies();

// =============================================================================
// 1. Public form routes must be useAuth: false
// =============================================================================

describe('Public form routes have useAuth: false', () => {
  const publicFormRoutes = [
    'POST /api/operators/apply',
    'POST /api/inquiries',
    'POST /api/waitlist',
  ];

  for (const route of publicFormRoutes) {
    it(`${route} should have useAuth: false`, () => {
      const policy = policies[route];
      expect(policy, `${route} missing from ROUTE_POLICIES`).toBeDefined();
      expect(policy.useAuth).toBe(false);
    });
  }
});

// =============================================================================
// 2. Registration route (no API key yet) must be useAuth: false
// =============================================================================

describe('Registration route has useAuth: false', () => {
  it('POST /api/entities/register should have useAuth: false', () => {
    const policy = policies['POST /api/entities/register'];
    expect(policy).toBeDefined();
    expect(policy.useAuth).toBe(false);
  });
});

// =============================================================================
// 3. Authenticated write routes must be useAuth: true
// =============================================================================

describe('Authenticated write routes have useAuth: true', () => {
  const authenticatedRoutes = [
    'POST /api/receipts/submit',
    'POST /api/receipts/confirm',
    'POST /api/receipts/auto-submit',
    'POST /api/disputes/file',
    'POST /api/disputes/respond',
    'POST /api/disputes/resolve',
    'POST /api/disputes/report',
    'POST /api/disputes/appeal',
    'POST /api/disputes/withdraw',
    'POST /api/delegations/create',
    'POST /api/identity/bind',
    'POST /api/identity/verify',
    'POST /api/needs/broadcast',
    'POST /api/commit/issue',
    'POST /api/trust/zk-proof',
  ];

  for (const route of authenticatedRoutes) {
    it(`${route} should have useAuth: true`, () => {
      const policy = policies[route];
      expect(policy, `${route} missing from ROUTE_POLICIES`).toBeDefined();
      expect(policy.useAuth).toBe(true);
    });
  }
});

// =============================================================================
// 4. Read-only routes should be useAuth: false
// =============================================================================

describe('Read-only routes have useAuth: false', () => {
  const readRoutes = [
    'GET /api/trust/profile/*',
    'POST /api/trust/evaluate',
    'POST /api/trust/install-preflight',
    // 'POST /api/trust/gate' — now authenticated (audit finding 12)
    'GET /api/trust/domain-score/*',
    'GET /api/trust/zk-proof',
    'GET /api/entities/search',
    'GET /api/delegations/*/verify',
    'POST /api/commit/verify',
  ];

  for (const route of readRoutes) {
    it(`${route} should have useAuth: false`, () => {
      const policy = policies[route];
      expect(policy, `${route} missing from ROUTE_POLICIES`).toBeDefined();
      expect(policy.useAuth).toBe(false);
    });
  }
});

// =============================================================================
// 5. Cross-check: route handler files marked public should not have useAuth: true
// =============================================================================

describe('Route handler files marked public match policy metadata', () => {
  for (const [policyKey, policy] of Object.entries(policies)) {
    const filePath = policyKeyToFilePath(policyKey);
    const isPublic = isRoutePublic(filePath);
    if (isPublic === null) continue; // skip if we can't determine

    it(`${policyKey}: handler says ${isPublic ? 'public' : 'auth required'}, policy says useAuth: ${policy.useAuth}`, () => {
      if (isPublic) {
        expect(policy.useAuth).toBe(false);
      } else {
        expect(policy.useAuth).toBe(true);
      }
    });
  }
});
