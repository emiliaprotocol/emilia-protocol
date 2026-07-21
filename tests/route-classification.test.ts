// SPDX-License-Identifier: Apache-2.0
//
// Guard: every mutating API route MUST be explicitly classified in
// middleware.js ROUTE_POLICIES. The middleware default is fail-open for rate
// limiting (an unclassified route falls back to the weak `read` category), so
// an unclassified POST/PUT/PATCH/DELETE silently gets read-tier limits — a DoS
// vector. This test makes that classification mandatory: add the route to the
// policy table or CI fails. (Auth itself is enforced in-route, not here; this
// guard is specifically about deliberate rate-limit + auth-keying per surface.)

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

// Parse "METHOD /api/path/*" entries out of the policy table. No dynamic RegExp:
// the table's `*` is always exactly one path segment, so a segment-wise compare
// is an exact equivalent of middleware's `*` -> `[^/]+` and avoids ReDoS risk.
function policyPatterns() {
  const mw = readFileSync(join(ROOT, 'middleware.ts'), 'utf8');
  const entry = /["'](GET|POST|PUT|PATCH|DELETE) (\/api\/[^"']+)["']/g;
  const out = [];
  let m;
  while ((m = entry.exec(mw)) !== null) out.push({ method: m[1], segments: m[2].split('/') });
  return out;
}

function segmentsMatch(patternSegments, pathSegments) {
  if (patternSegments.length !== pathSegments.length) return false;
  return patternSegments.every((seg, i) => seg === '*' || seg === pathSegments[i]);
}

function walk(dir, acc = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name === 'route.js' || e.name === 'route.ts') acc.push(p);
  }
  return acc;
}

// app/api/foo/[id]/route.js -> /api/foo/*
function routePath(file) {
  return file
    .slice(ROOT.length)
    .replace(/^\/?app/, '')
    .replace(/\/route\.(?:js|ts)$/, '')
    .replace(/\[[^\]]+\]/g, '*');
}

describe('route classification completeness (middleware ROUTE_POLICIES)', () => {
  const patterns = policyPatterns();
  const files = walk(join(ROOT, 'app/api'));

  it('every mutating API route is explicitly classified', () => {
    const unclassified = [];
    for (const file of files) {
      const src = readFileSync(file, 'utf8');
      const methods = [...src.matchAll(/export async function (GET|POST|PUT|PATCH|DELETE)/g)].map(
        (mm) => mm[1],
      );
      const segments = routePath(file).split('/');
      for (const method of methods) {
        if (!WRITE_METHODS.includes(method)) continue;
        const classified = patterns.some(
          (p) => p.method === method && segmentsMatch(p.segments, segments),
        );
        if (!classified) unclassified.push(`${method} ${routePath(file)}`);
      }
    }
    expect(
      unclassified,
      `Unclassified mutating routes — add them to ROUTE_POLICIES in middleware.js:\n  ${unclassified.join('\n  ')}`,
    ).toEqual([]);
  });

  it('found a non-trivial number of route files (scan sanity)', () => {
    expect(files.length).toBeGreaterThan(50);
  });
});
