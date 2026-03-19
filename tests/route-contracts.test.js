import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync as _readdirSync } from 'fs';
import { join } from 'path';
import jsYaml from 'js-yaml';

// ============================================================================
// Route-contract tests
//
// Ensures no route is undocumented and no middleware policy is orphaned.
//   1. Every ROUTE_POLICIES entry in middleware.js maps to an actual route file.
//   2. Every non-internal OpenAPI path has a corresponding route file.
// ============================================================================

const ROOT = join(import.meta.dirname, '..');

/**
 * Convert an OpenAPI path like /api/trust/profile/{entityId}
 * to the Next.js App Router file path:
 *   app/api/trust/profile/[entityId]/route.js
 */
function openapiPathToRouteFile(apiPath) {
  const converted = apiPath.replace(/\{([^}]+)\}/g, '[$1]');
  return join(ROOT, 'app', converted, 'route.js');
}

// Check whether a route file exists for a middleware policy path.
// Handles three cases:
//   1. Exact match:  /api/health -> app/api/health/route.js
//   2. Prefix match: /api/trust/profile -> app/api/trust/profile/[...]/route.js
//   3. Wildcards:    /api/entities/*/auto-receipt -> app/api/entities/[param]/auto-receipt/route.js
function findRouteFile(routePath) {
  const parts = routePath.split('/').filter(Boolean);
  const candidates = resolvePathParts(join(ROOT, 'app'), parts);
  return candidates.some(dir => existsSync(join(dir, 'route.js')));
}

function resolvePathParts(base, parts) {
  if (parts.length === 0) {
    // Also check one level deeper for dynamic-segment children (prefix match)
    const dirs = [base];
    for (const child of readdirSafe(base)) {
      if (child.startsWith('[')) {
        dirs.push(join(base, child));
      }
    }
    return dirs;
  }

  const part = parts[0];
  const rest = parts.slice(1);

  if (part === '*') {
    // Wildcard: try all dynamic-segment directories
    const results = [];
    for (const child of readdirSafe(base)) {
      if (child.startsWith('[')) {
        results.push(...resolvePathParts(join(base, child), rest));
      }
    }
    return results;
  }

  return resolvePathParts(join(base, part), rest);
}

function readdirSafe(dir) {
  try {
    return _readdirSync(dir);
  } catch {
    return [];
  }
}


// ---------------------------------------------------------------------------
// 1. Parse ROUTE_POLICIES from middleware.js
// ---------------------------------------------------------------------------

function extractRoutePolicies() {
  const src = readFileSync(join(ROOT, 'middleware.js'), 'utf8');

  // Match lines like:  'GET /api/trust/profile':  { ... },
  const pattern = /^\s*'((?:GET|POST|PUT|PATCH|DELETE)\s+\/api\/[^']+)'/gm;
  const entries = [];
  let m;
  while ((m = pattern.exec(src)) !== null) {
    const [method, path] = m[1].split(/\s+/);
    entries.push({ method, path, raw: m[1] });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// 2. Parse OpenAPI paths + detect internal tags
// ---------------------------------------------------------------------------

function extractOpenApiPaths() {
  const raw = readFileSync(join(ROOT, 'openapi.yaml'), 'utf8');
  const doc = jsYaml.load(raw);
  const results = [];

  for (const [path, methods] of Object.entries(doc.paths || {})) {
    // Check if ALL methods on this path are internal
    const methodEntries = Object.entries(methods).filter(
      ([k]) => ['get', 'post', 'put', 'patch', 'delete'].includes(k)
    );
    const allInternal = methodEntries.every(
      ([, spec]) => spec.tags && spec.tags.includes('Internal')
    );
    results.push({ path, internal: allInternal });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Route contracts', () => {
  const routePolicies = extractRoutePolicies();
  const openApiPaths = extractOpenApiPaths();

  it('middleware.js ROUTE_POLICIES table is non-empty', () => {
    expect(routePolicies.length).toBeGreaterThan(0);
  });

  it('every ROUTE_POLICIES entry maps to an actual route file', () => {
    const missing = [];

    for (const { path, raw } of routePolicies) {
      if (!findRouteFile(path)) {
        missing.push(raw);
      }
    }

    expect(missing, `Orphaned ROUTE_POLICIES entries (no route file):\n  ${missing.join('\n  ')}`).toEqual([]);
  });

  it('openapi.yaml is parseable and has paths', () => {
    expect(openApiPaths.length).toBeGreaterThan(0);
  });

  it('every non-internal OpenAPI path has a corresponding route file', () => {
    const publicPaths = openApiPaths.filter(p => !p.internal);
    const missing = [];

    for (const { path } of publicPaths) {
      const routeFile = openapiPathToRouteFile(path);
      if (!existsSync(routeFile)) {
        missing.push(path);
      }
    }

    expect(missing, `OpenAPI paths with no route file:\n  ${missing.join('\n  ')}`).toEqual([]);
  });
});
