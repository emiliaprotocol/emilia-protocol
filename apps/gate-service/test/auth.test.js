// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createStaticBearerAuthenticator } from '../src/auth.js';

const TOKEN = 'gate-token-000000000000000000000001';

function request(header, rawHeaders = ['Authorization', header]) {
  return { headers: { authorization: header }, rawHeaders };
}

test('static bearer authentication accepts only one exact token', async () => {
  const authenticate = createStaticBearerAuthenticator(TOKEN);
  assert.equal(await authenticate(request(`Bearer ${TOKEN}`)), true);
  assert.equal(await authenticate(request('Bearer gate-token-000000000000000000000002')), false);
  assert.equal(await authenticate(request(`bearer ${TOKEN}`)), false);
  assert.equal(await authenticate(request(`Bearer ${TOKEN}`, [
    'Authorization', `Bearer ${TOKEN}`,
    'Authorization', `Bearer ${TOKEN}`,
  ])), false);
});

test('static bearer authentication rejects unsafe configured tokens', () => {
  assert.throws(() => createStaticBearerAuthenticator('short'), /32-1024/);
  assert.throws(
    () => createStaticBearerAuthenticator(`gate-token-${'x'.repeat(40)}\n`),
    /visible non-space/,
  );
});
