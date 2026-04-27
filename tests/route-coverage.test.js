import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import fg from 'fast-glob';
import yaml from 'js-yaml';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ROOT = path.resolve(import.meta.dirname, '..');
const API_DIR = path.join(ROOT, 'app', 'api');
const MIDDLEWARE_PATH = path.join(ROOT, 'middleware.js');
const OPENAPI_PATH = path.join(ROOT, 'openapi.yaml');

/** Read all `route.js` files under app/api/ and return their API paths. */
function discoverRouteFiles() {
  const files = fg.sync('app/api/**/route.js', { cwd: ROOT });
  return files.map((f) => {
    // app/api/disputes/[disputeId]/adjudicate/route.js -> /api/disputes/[disputeId]/adjudicate
    const relative = f
      .replace(/^app/, '')
      .replace(/\/route\.js$/, '');
    return { file: f, apiPath: relative };
  });
}

/** Check which HTTP methods a route file exports (POST, PUT, PATCH, DELETE, GET). */
function exportedMethods(routeFile) {
  const src = fs.readFileSync(path.join(ROOT, routeFile), 'utf-8');
  const methods = [];
  for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    // Match `export async function POST` or `export function POST` or `export const POST`
    if (new RegExp(`export\\s+(?:async\\s+)?(?:function|const)\\s+${m}\\b`).test(src)) {
      methods.push(m);
    }
  }
  return methods;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Extract ROUTE_POLICIES keys from middleware.js. */
function parseRoutePolicies() {
  const src = fs.readFileSync(MIDDLEWARE_PATH, 'utf-8');
  // Match lines like: 'POST /api/receipts/submit':  or "GET /api/trust/profile":
  const re = /['"](\w+)\s+(\/api\/[^'"]+)['"]\s*:/g;
  const entries = [];
  let m;
  while ((m = re.exec(src)) !== null) {
    entries.push({ method: m[1], pathPattern: m[2] });
  }
  return entries;
}

/**
 * Convert an app/api file-system path to a "normalised" form that matches
 * ROUTE_POLICIES patterns (which use `*` for dynamic segments).
 *
 * /api/disputes/[disputeId]/adjudicate  ->  /api/disputes/* /adjudicate  (no space)
 * /api/needs/[id]/claim                 ->  /api/needs/* /claim
 */
function normalisePath(apiPath) {
  return apiPath.replace(/\[[^\]]+\]/g, '*');
}

/** Parse openapi.yaml and return the path keys (e.g. /api/trust/profile/{entityId}). */
function parseOpenAPIPaths() {
  const doc = yaml.load(fs.readFileSync(OPENAPI_PATH, 'utf-8'));
  return Object.keys(doc.paths || {});
}

/**
 * Convert an OpenAPI path to the filesystem convention:
 *   /api/trust/profile/{entityId} -> /api/trust/profile/[entityId]
 */
function openapiPathToFs(p) {
  return p.replace(/\{([^}]+)\}/g, '[$1]');
}

/**
 * Convert a filesystem API path to OpenAPI convention:
 *   /api/trust/profile/[entityId] -> /api/trust/profile/{entityId}
 */
function fsPathToOpenapi(p) {
  return p.replace(/\[([^\]]+)\]/g, '{$1}');
}

// ---------------------------------------------------------------------------
// Exemption lists — document why each route is exempt.
// ---------------------------------------------------------------------------

/**
 * Routes that export mutating handlers but intentionally rely on the
 * middleware default ('read' category) rather than having an explicit
 * ROUTE_POLICIES entry. Keep this list as short as possible.
 */
const MUTATING_POLICY_EXEMPTIONS = [
  // Signoff routes — middleware policies to be added in a follow-up.
  '/api/signoff/challenge',
  '/api/signoff/[challengeId]/attest',
  '/api/signoff/[challengeId]/deny',
  '/api/signoff/[challengeId]/revoke',
  '/api/signoff/[challengeId]/consume',
  // Cloud control-plane routes — not part of the public protocol API.
  '/api/cloud/policies/[policyId]/rollout',
  '/api/cloud/policies/[policyId]/simulate',
  '/api/cloud/signoff/escalate',
  '/api/cloud/signoff/notify',
];

/**
 * Routes that exist in the filesystem but are intentionally omitted from
 * openapi.yaml because they are internal / not part of the public API.
 */
const OPENAPI_EXEMPTIONS = [
  // Cron jobs are triggered by Vercel cron, not by external callers.
  '/api/cron/expire',
  // Blockchain anchoring is an internal operations endpoint.
  '/api/blockchain/anchor',
  // Protocol-standard surfaces (singular: /api/entity, /api/receipt, /api/trust,
  // /api/discovery/keys). These are the EP-RECEIPT-v1 / .well-known compatible
  // endpoints. Full OpenAPI specs to be added in a follow-up; the routes
  // themselves are wired with ROUTE_POLICIES in middleware.js.
  '/api/entity',
  '/api/receipt',
  '/api/trust',
  '/api/discovery/keys',
  // EP Commit routes — OpenAPI spec to be added in a follow-up.
  '/api/commit/issue',
  '/api/commit/verify',
  '/api/commit/[commitId]',
  '/api/commit/[commitId]/revoke',
  '/api/commit/[commitId]/receipt',
  '/api/commit/[commitId]/dispute',
  // Signoff routes — OpenAPI spec to be added in a follow-up.
  '/api/signoff/challenge',
  '/api/signoff/[challengeId]',
  '/api/signoff/[challengeId]/attest',
  '/api/signoff/[challengeId]/deny',
  '/api/signoff/[challengeId]/revoke',
  '/api/signoff/[challengeId]/consume',
  // Cloud control-plane routes — internal, not part of the public protocol API.
  '/api/cloud/audit/export',
  '/api/cloud/audit/integrity',
  '/api/cloud/audit/report',
  '/api/cloud/events/search',
  '/api/cloud/events/timeline/[handshakeId]',
  '/api/cloud/policies/[policyId]/diff',
  '/api/cloud/policies/[policyId]/rollout',
  '/api/cloud/policies/[policyId]/simulate',
  '/api/cloud/policies/[policyId]/versions',
  '/api/cloud/signoff/analytics',
  '/api/cloud/signoff/dashboard',
  '/api/cloud/signoff/escalate',
  '/api/cloud/signoff/notify',
  '/api/cloud/signoff/pending',
  '/api/cloud/signoff/queue',
  // Webhook routes — cloud control-plane, not part of the public protocol API.
  '/api/cloud/webhooks',
  '/api/cloud/webhooks/[endpointId]',
  '/api/cloud/webhooks/[endpointId]/deliveries',
  '/api/cloud/webhooks/[endpointId]/test',
  // Key management — internal operational endpoint, not public API.
  '/api/keys/rotate',
  // Cloud scoring calibration — cloud control-plane.
  '/api/cloud/scoring/recommendations',
  // GovGuard + FinGuard product API (v1) — OpenAPI spec to be added in a
  // follow-up. The endpoints are wired in middleware.js ROUTE_POLICIES.
  '/api/v1/trust-receipts',
  '/api/v1/trust-receipts/[receiptId]',
  '/api/v1/trust-receipts/[receiptId]/consume',
  '/api/v1/trust-receipts/[receiptId]/evidence',
  '/api/v1/signoffs/request',
  '/api/v1/signoffs/[signoffId]/approve',
  '/api/v1/signoffs/[signoffId]/reject',
  '/api/v1/adapters/gov/benefit-bank-change/precheck',
  '/api/v1/adapters/gov/caseworker-override/precheck',
  '/api/v1/adapters/fin/vendor-bank-change/precheck',
  '/api/v1/adapters/fin/beneficiary-creation/precheck',
  '/api/v1/adapters/fin/payment-release/precheck',
];


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('every mutating route is in ROUTE_POLICIES', () => {
  const routes = discoverRouteFiles();
  const policies = parseRoutePolicies();

  // Segment-by-segment matcher (no RegExp engine). pathPattern is split on
  // '/' and each segment compared literally — except '*' which matches any
  // single non-empty segment. This mirrors middleware.js semantics without
  // constructing dynamic regexes (which the linter flags as ReDoS-adjacent
  // even when inputs come from a controlled source). Faster too.
  const PATH_PATTERN_SAFE = /^\/[A-Za-z0-9_/\-*\[\]]+$/;
  const compiledPatterns = policies.map(({ method, pathPattern }) => {
    if (!PATH_PATTERN_SAFE.test(pathPattern)) {
      throw new Error(`unsafe path pattern in middleware.js ROUTE_POLICIES: ${JSON.stringify(pathPattern)}`);
    }
    const segments = pathPattern.split('/');
    return { method, segments };
  });

  function pathMatchesSegments(apiPath, segments) {
    const pathSegs = apiPath.split('/');
    if (pathSegs.length !== segments.length) return false;
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === '*') {
        if (pathSegs[i].length === 0) return false;
      } else if (segments[i] !== pathSegs[i]) {
        return false;
      }
    }
    return true;
  }

  function hasPolicy(method, apiPath) {
    for (const { method: m, segments } of compiledPatterns) {
      if (m === method && pathMatchesSegments(apiPath, segments)) return true;
    }
    return false;
  }

  for (const { file, apiPath } of routes) {
    const methods = exportedMethods(file);
    const mutating = methods.filter((m) => MUTATING_METHODS.has(m));

    for (const method of mutating) {
      const exemptKey = apiPath.replace(/^\/?/, '/');

      if (MUTATING_POLICY_EXEMPTIONS.includes(exemptKey)) continue;

      it(`${method} ${apiPath} has a ROUTE_POLICIES entry`, () => {
        expect(
          hasPolicy(method, apiPath),
          `Missing ROUTE_POLICIES entry for "${method} ${apiPath}". ` +
            `Add it to middleware.js or to MUTATING_POLICY_EXEMPTIONS if intentional.`,
        ).toBe(true);
      });
    }
  }
});

describe('every public route exists in OpenAPI', () => {
  const routes = discoverRouteFiles();
  const openapiPaths = parseOpenAPIPaths();

  // Build a set of normalised OpenAPI paths for easy lookup
  const openapiSet = new Set(openapiPaths.map(openapiPathToFs));
  // Build a set of filesystem API paths for reverse lookup
  const fsSet = new Set(routes.map((r) => r.apiPath));

  it('every OpenAPI path has a corresponding route file', () => {
    const missing = [];
    for (const oaPath of openapiPaths) {
      const fsPath = openapiPathToFs(oaPath);
      if (!fsSet.has(fsPath)) {
        missing.push(oaPath);
      }
    }
    expect(
      missing,
      `OpenAPI paths with no matching route file:\n  ${missing.join('\n  ')}`,
    ).toEqual([]);
  });

  it('every API route file has a corresponding OpenAPI entry (or is exempted)', () => {
    const missing = [];
    for (const { apiPath } of routes) {
      const normPath = apiPath.replace(/^\/?/, '/');
      if (OPENAPI_EXEMPTIONS.includes(normPath)) continue;
      if (!openapiSet.has(apiPath)) {
        missing.push(apiPath);
      }
    }
    expect(
      missing,
      `Route files with no matching OpenAPI entry (add to OPENAPI_EXEMPTIONS if internal):\n  ${missing.join('\n  ')}`,
    ).toEqual([]);
  });
});

describe('no orphaned ROUTE_POLICIES entries', () => {
  const routes = discoverRouteFiles();
  const policies = parseRoutePolicies();

  // Same safety + matcher contract as the previous describe block: validate
  // pathPattern up-front against an allowlist charset, then split on '/' and
  // compare segment-by-segment ('*' matches any single non-empty segment).
  // Avoids constructing dynamic regexes from input — silences ReDoS lints.
  const PATH_PATTERN_SAFE_ORPHAN = /^\/[A-Za-z0-9_/\-*\[\]]+$/;

  function pathMatchesSegmentsOrphan(apiPath, segments) {
    const pathSegs = apiPath.split('/');
    if (pathSegs.length !== segments.length) return false;
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === '*') {
        if (pathSegs[i].length === 0) return false;
      } else if (segments[i] !== pathSegs[i]) {
        return false;
      }
    }
    return true;
  }

  for (const { method, pathPattern } of policies) {
    const policyKey = `${method} ${pathPattern}`;

    it(`${policyKey} maps to an actual route file`, () => {
      if (!PATH_PATTERN_SAFE_ORPHAN.test(pathPattern)) {
        throw new Error(`unsafe path pattern in middleware.js ROUTE_POLICIES: ${JSON.stringify(pathPattern)}`);
      }
      // Normalise filesystem [foo] dynamic segments to '*' so they match the
      // policy pattern's '*' wildcard.
      const segments = pathPattern.split('/');
      const allApiPaths = routes.map((r) => normalisePath(r.apiPath));
      const match = allApiPaths.some((p) => pathMatchesSegmentsOrphan(p, segments));
      expect(
        match,
        `ROUTE_POLICIES entry "${policyKey}" has no matching route file. ` +
          `Remove it from middleware.js or create the route.`,
      ).toBe(true);
    });
  }
});
