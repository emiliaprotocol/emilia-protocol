// SPDX-License-Identifier: Apache-2.0
//
// Route-boundary regression sweep. Route handlers must never obtain the raw
// service-role client: that bypasses the runtime write guard. Internal library
// modules may still use getServiceClient() for canonical/protocol writes; this
// sweep is deliberately limited to app/api route modules.

import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_DIR = path.join(ROOT, 'app', 'api');
const AUTH_BOUNDARY_ROUTES = [
  'app/api/handshake/[handshakeId]/present/route.js',
  'app/api/handshake/[handshakeId]/verify/route.js',
  'app/api/cloud/webhooks/[endpointId]/route.js',
  'app/api/keys/rotate/route.js',
];
const ACTOR_BOUNDARY_DIRS = [
  path.join(ROOT, 'app', 'api', 'handshake'),
  path.join(ROOT, 'app', 'api', 'disputes'),
];

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(fullPath, files);
    else if (entry.name === 'route.js' || entry.name === 'route.ts') files.push(fullPath);
  }
  return files;
}

function withoutComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|\s)\/\/.*$/gm, '$1');
}

const routeFiles = walk(API_DIR).sort();

describe('route auth/write boundary sweep', () => {
  it('scans a non-trivial route surface', () => {
    expect(routeFiles.length).toBeGreaterThan(50);
  });

  it.each(routeFiles)('%s cannot import or call getServiceClient()', (file) => {
    const source = withoutComments(fs.readFileSync(file, 'utf8'));
    expect(source, `${path.relative(ROOT, file)} bypasses getGuardedClient()`).not.toMatch(/\bgetServiceClient\b/);
  });

  it.each(AUTH_BOUNDARY_ROUTES)('%s uses the guarded client boundary', (relativeFile) => {
    const source = fs.readFileSync(path.join(ROOT, relativeFile), 'utf8');
    expect(source).toContain('getGuardedClient');
  });

  it('does not pass the raw auth.entity object through handshake/dispute routes', () => {
    const rawActor = /\b(?:actor|callerEntity)\s*:\s*auth\.entity\b|,\s*auth\.entity\s*[),]/;
    const offenders = [];
    for (const dir of ACTOR_BOUNDARY_DIRS) {
      for (const file of walk(dir)) {
        const source = withoutComments(fs.readFileSync(file, 'utf8'));
        if (rawActor.test(source)) offenders.push(path.relative(ROOT, file));
      }
    }
    expect(offenders).toEqual([]);
  });
});
