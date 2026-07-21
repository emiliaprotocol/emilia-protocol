// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const publicRoot = path.resolve(process.cwd(), 'app/api/v1/release-locks');
const internalRoot = path.resolve(process.cwd(), 'app/api/internal/release-lock');
const openApiPath = path.resolve(process.cwd(), 'openapi.yaml');

function routeFiles(root) {
  return fs.readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && (entry.name === 'route.js' || entry.name === 'route.ts'))
    .map((entry) => path.join(entry.parentPath || entry.path || root, entry.name));
}

describe('Release Lock API contract', () => {
  it('protects every success and refusal through the common response boundary', () => {
    const routes = [...routeFiles(publicRoot), ...routeFiles(internalRoot)];
    expect(routes).toHaveLength(14);
    for (const route of routes) {
      const source = fs.readFileSync(route, 'utf8');
      expect(source, route).toContain('releaseLockJson');
      expect(source, route).toContain('releaseLockProblem');
      expect(source, route).not.toMatch(/\bconsole\.(?:log|warn|error)\b/);
      expect(source, route).not.toMatch(/\blogger\./);
    }
  });

  it('exchanges raw invitation input only into the strict session cookie', () => {
    const exchange = fs.readFileSync(
      path.join(publicRoot, 'invitations/exchange/route.ts'),
      'utf8',
    );
    expect(exchange).toContain('rawSessionToken');
    expect(exchange).toContain('setReleaseLockSessionCookie');
    expect(exchange).toContain('const { rawSessionToken, ...result }');
    const pairingExchange = fs.readFileSync(
      path.join(publicRoot, 'pairings/exchange/route.ts'),
      'utf8',
    );
    expect(pairingExchange).toContain('rawSessionToken');
    expect(pairingExchange).toContain('setReleaseLockSessionCookie');
    expect(pairingExchange).toContain('const { rawSessionToken, ...result }');
  });

  it('exposes both approval rounds without a public effect retry/refund route', () => {
    const paths = routeFiles(publicRoot).map((file) => path.relative(publicRoot, file));
    expect(paths).toContain(
      '[lockId]/rounds/[round]/action-check/options/route.ts',
    );
    expect(paths).toContain('[lockId]/rounds/[round]/approvals/route.ts');
    expect(paths).toContain('[lockId]/rounds/[round]/pairings/route.ts');
    expect(paths.some((file) => /(^|\/)(retry|refund|release)\/route\.(?:js|ts)$/.test(file)))
      .toBe(false);
    expect(routeFiles(internalRoot).map((file) => path.relative(internalRoot, file)))
      .toEqual(['reconcile/route.ts']);
  });

  it('keeps organization writes bound to the existing authenticated-org pattern', () => {
    for (const relative of [
      'route.ts',
      '[lockId]/draw-release/route.ts',
      '[lockId]/amendments/route.ts',
      '[lockId]/evidence/route.ts',
    ]) {
      const source = fs.readFileSync(path.join(publicRoot, relative), 'utf8');
      expect(source).toContain('authenticateReleaseLockOrg');
    }
  });

  it('documents the real dynamic cookie transport and same-origin mutation boundary', () => {
    const contract = fs.readFileSync(openApiPath, 'utf8');
    expect(contract).toContain('ReleaseLockSession:');
    expect(contract).toContain('name: Cookie');
    expect(contract).toContain('`__Host-ep_release_lock_session_{lockId}=<token>`');
    expect(contract).toContain('ReleaseLockOrigin:');
    expect(contract).toContain('name: Origin');
    expect(contract.match(
      /\$ref: '#\/components\/parameters\/ReleaseLockOrigin'/g,
    )).toHaveLength(7);
    expect(contract).not.toContain('name: __Host-ep_release_lock_session_{lockId}');
  });
});
