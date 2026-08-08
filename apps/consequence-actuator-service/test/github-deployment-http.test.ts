// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { createGitHubDeploymentWebhookHttpServer } from '../src/github-deployment-server.js';

async function withServer(server: any, work: (origin: string) => Promise<void>) {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  try {
    await work(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('HTTP boundary preserves the raw webhook body for HMAC verification', async () => {
  const calls: any[] = [];
  const server = createGitHubDeploymentWebhookHttpServer({
    gate: {
      handle: async (input: any) => {
        calls.push(input);
        return { ok: true, status: 200, state: 'APPROVED' };
      },
    },
  });
  await withServer(server, async (origin) => {
    const source = '{"z":1,"a":2}';
    const response = await fetch(`${origin}/v1/github/deployment-protection`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-test-header': 'preserved',
      },
      body: source,
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, status: 200, state: 'APPROVED' });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.toString('utf8'), source);
    assert.equal(calls[0].headers['x-test-header'], 'preserved');
  });
});

test('HTTP boundary closes methods, paths, query strings, and oversized bodies', async () => {
  let gateCalls = 0;
  const server = createGitHubDeploymentWebhookHttpServer({
    gate: { handle: async () => { gateCalls += 1; return { ok: true, status: 200 }; } },
    maxBodyBytes: 128,
  });
  await withServer(server, async (origin) => {
    assert.equal((await fetch(`${origin}/v1/github/deployment-protection`)).status, 405);
    assert.equal((await fetch(`${origin}/other`, { method: 'POST', body: '{}' })).status, 404);
    assert.equal((await fetch(`${origin}/v1/github/deployment-protection?x=1`, { method: 'POST', body: '{}' })).status, 400);
    const oversized = await fetch(`${origin}/v1/github/deployment-protection`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'x'.repeat(129),
    });
    assert.equal(oversized.status, 413);
  });
  assert.equal(gateCalls, 0);
});

test('HTTP responses are non-cacheable and do not expose stack traces', async () => {
  const server = createGitHubDeploymentWebhookHttpServer({
    gate: { handle: async () => { throw new Error('sensitive detail'); } },
  });
  await withServer(server, async (origin) => {
    const response = await fetch(`${origin}/v1/github/deployment-protection`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    assert.equal(response.status, 500);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.text();
    assert.equal(body.includes('sensitive detail'), false);
  });
});
