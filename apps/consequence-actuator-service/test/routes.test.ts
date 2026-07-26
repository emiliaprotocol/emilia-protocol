// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterEach, describe, it } from 'node:test';

import { createHttpServer } from '../src/server.ts';

const servers = new Set<http.Server>();

afterEach(async () => {
  await Promise.all([...servers].map((server) => new Promise<void>((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  })));
  servers.clear();
});

async function startedServer() {
  const runtime = {
    limits: {
      maxBodyBytes: 1024,
      maxHeaderBytes: 8192,
      requestTimeoutMs: 5000,
    },
    async authenticate(authorization: unknown) {
      return authorization === 'Bearer authorized-actuator-client';
    },
    live() {
      return { status: 200, body: { status: 'live' } };
    },
    async ready() {
      return { status: 200, body: { status: 'ready' } };
    },
    async execute() {
      return { status: 200, body: { status: 'committed' } };
    },
    async observe() {
      return { status: 200, body: { status: 'observed' } };
    },
  };
  const server = createHttpServer(runtime);
  servers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert(address && typeof address === 'object');
  return `http://127.0.0.1:${address.port}`;
}

describe('authenticated bounded actuator HTTP surface', () => {
  it('requires authentication on live, ready, execute, and observe', async () => {
    const origin = await startedServer();
    for (const [path, method, body] of [
      ['/v1/live', 'GET', undefined],
      ['/v1/ready', 'GET', undefined],
      ['/v1/execute', 'POST', '{}'],
      ['/v1/observe', 'POST', '{}'],
    ] as const) {
      const response = await fetch(`${origin}${path}`, {
        method,
        ...(body === undefined
          ? {}
          : { headers: { 'content-type': 'application/json' }, body }),
      });
      assert.equal(response.status, 401, path);
      assert.deepEqual(await response.json(), {
        status: 'refused',
        error: { code: 'authentication_required' },
      });
    }

    const authorized = await fetch(`${origin}/v1/ready`, {
      headers: { authorization: 'Bearer authorized-actuator-client' },
    });
    assert.equal(authorized.status, 200);
    assert.deepEqual(await authorized.json(), { status: 'ready' });
  });

  it('rejects an oversized body before JSON parsing or execution', async () => {
    const origin = await startedServer();
    const response = await fetch(`${origin}/v1/execute`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer authorized-actuator-client',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ padding: 'x'.repeat(100 * 1024) }),
    });

    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), {
      status: 'refused',
      error: { code: 'body_too_large' },
    });
  });
});
