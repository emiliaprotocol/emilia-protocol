// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GATE_ROUTE_PATHS } from '../src/routes.js';

test('OpenAPI contract covers every service route and critical fail-closed semantics', async () => {
  const document = JSON.parse(await fs.readFile(
    new URL('../openapi.json', import.meta.url),
    'utf8',
  ));
  assert.match(document.openapi, /^3\./);
  assert.deepEqual(
    Object.keys(document.paths).sort(),
    Object.values(GATE_ROUTE_PATHS).sort(),
  );
  assert.ok(document.components.securitySchemes.bearerAuth);
  assert.ok(document.paths['/v1/actions/{id}/execute'].post.responses['428']);
  assert.ok(
    document.paths['/v1/actions/{id}/execute'].post.responses['428']
      .headers['Receipt-Required'],
  );
  assert.ok(document.components.schemas.ActionStatus.enum.includes('indeterminate'));
  assert.match(
    document.components.schemas.Indeterminate.description,
    /must not be retried automatically/i,
  );
  for (const path of [
    '/v1/actions',
    '/v1/actions/{id}',
    '/v1/actions/{id}/execute',
    '/v1/evidence/head',
    '/v1/evidence/records/{recordId}',
    '/v1/evidence/history',
    '/v1/evidence/verify',
    '/v1/evidence/export',
    '/v1/metrics',
  ]) {
    const operation = document.paths[path].get ?? document.paths[path].post;
    assert.deepEqual(operation.security, [{ bearerAuth: [] }], `${path} must require bearer auth`);
  }
});
