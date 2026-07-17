// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createStaticBearerAuthenticator } from '../src/auth.js';

const TOKEN = 'gate-token-000000000000000000000001';
const PRINCIPAL = Object.freeze({ id: 'operator:gate', roles: ['repo-admin'] });

function request(header, rawHeaders = ['Authorization', header]) {
  return { headers: { authorization: header }, rawHeaders };
}

test('static bearer authentication accepts only one exact token', async () => {
  const authenticate = createStaticBearerAuthenticator(TOKEN, PRINCIPAL);
  assert.deepEqual(await authenticate(request(`Bearer ${TOKEN}`)), PRINCIPAL);
  assert.equal(await authenticate(request('Bearer gate-token-000000000000000000000002')), null);
  assert.equal(await authenticate(request(`bearer ${TOKEN}`)), null);
  assert.equal(await authenticate(request(`Bearer ${TOKEN}`, [
    'Authorization', `Bearer ${TOKEN}`,
    'Authorization', `Bearer ${TOKEN}`,
  ])), null);
});

test('static bearer authentication rejects unsafe tokens and principals', () => {
  assert.throws(() => createStaticBearerAuthenticator('short', PRINCIPAL), /32-1024/);
  assert.throws(
    () => createStaticBearerAuthenticator(`gate-token-${'x'.repeat(40)}\n`, PRINCIPAL),
    /visible non-space/,
  );
  assert.throws(() => createStaticBearerAuthenticator(TOKEN), /principal/i);
  assert.throws(() => createStaticBearerAuthenticator(TOKEN, { id: 'bad\nprincipal' }), /principal/i);
});
