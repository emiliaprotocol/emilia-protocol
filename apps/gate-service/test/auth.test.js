// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
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
  assert.equal(await authenticate(request(`Bearer ${TOKEN.slice(0, -1)}`)), null);
  assert.equal(await authenticate(request(`Bearer ${TOKEN}x`)), null);
  assert.equal(await authenticate(request(`bearer ${TOKEN}`)), null);
  assert.equal(await authenticate(request(`Bearer ${TOKEN}`, [
    'Authorization', `Bearer ${TOKEN}`,
    'Authorization', `Bearer ${TOKEN}`,
  ])), null);
});

test('static bearer authentication compares every valid token at one fixed size', async () => {
  const authenticate = createStaticBearerAuthenticator(TOKEN, PRINCIPAL);
  const originalTimingSafeEqual = crypto.timingSafeEqual;
  const comparisons = [];
  crypto.timingSafeEqual = (actual, expected) => {
    comparisons.push([actual.length, expected.length]);
    return originalTimingSafeEqual(actual, expected);
  };

  try {
    assert.equal(await authenticate(request(`Bearer ${TOKEN.slice(0, -1)}`)), null);
    assert.equal(await authenticate(request(`Bearer ${TOKEN}x`)), null);
  } finally {
    crypto.timingSafeEqual = originalTimingSafeEqual;
  }

  assert.deepEqual(comparisons.map(([actual, expected]) => actual === expected), [true, true]);
  assert.equal(new Set(comparisons.flat()).size, 1);
});

test('static bearer authentication fails closed for malformed requests and candidates', async () => {
  const authenticate = createStaticBearerAuthenticator(TOKEN, PRINCIPAL);
  assert.equal(await authenticate(null), null);
  assert.equal(await authenticate({
    headers: { authorization: `Bearer ${TOKEN}` },
    rawHeaders: ['Authorization'],
  }), null);
  assert.equal(await authenticate({
    headers: { authorization: `Bearer ${TOKEN}` },
    rawHeaders: ['Authorization', 'Bearer gate-token-000000000000000000000002'],
  }), null);
  assert.equal(await authenticate(request(`Bearer ${TOKEN}\n`)), null);
  assert.equal(await authenticate(request(`Bearer ${'x'.repeat(1025)}`)), null);
});

test('static bearer authentication rejects unsafe tokens and principals', () => {
  assert.throws(() => createStaticBearerAuthenticator('short', PRINCIPAL), /32-1024/);
  assert.throws(
    () => createStaticBearerAuthenticator(`gate-token-${'x'.repeat(40)}\n`, PRINCIPAL),
    /printable ASCII/,
  );
  assert.throws(() => createStaticBearerAuthenticator('é'.repeat(32), PRINCIPAL), /printable ASCII/);
  assert.throws(() => createStaticBearerAuthenticator('x'.repeat(1025), PRINCIPAL), /32-1024/);
  assert.throws(() => createStaticBearerAuthenticator(TOKEN), /principal/i);
  assert.throws(() => createStaticBearerAuthenticator(TOKEN, { id: 'bad\nprincipal' }), /principal/i);
});
