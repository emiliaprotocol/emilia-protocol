// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import {
  createHttpServer,
  installShutdownHandlers,
} from '../src/server.js';

function runtimeFixture() {
  const calls = [];
  const idleWaiters = new Set();
  let accepting = true;
  let active = 0;
  const notifyIdle = () => {
    if (active !== 0) return;
    for (const resolve of idleWaiters) resolve(true);
    idleWaiters.clear();
  };
  const runtime = {
    limits: {
      maxBodyBytes: 1024 * 1024,
      maxHeaderBytes: 32 * 1024,
      requestTimeoutMs: 30_000,
    },
    live: () => ({ status: 200, body: { status: 'ok' } }),
    ready: async () => ({ status: 200, body: { status: 'ok' } }),
    authenticate: async (request) => (
      request.headers.authorization === 'Bearer gate-token'
        ? { id: 'principal:operator' }
        : null
    ),
    admit: () => {
      if (!accepting) return null;
      active += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        active -= 1;
        notifyIdle();
      };
    },
    stopAdmission: () => {
      accepting = false;
    },
    waitForIdle: async (timeoutMs) => {
      if (active === 0) return true;
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          idleWaiters.delete(done);
          resolve(false);
        }, timeoutMs);
        const done = (value) => {
          clearTimeout(timer);
          resolve(value);
        };
        idleWaiters.add(done);
      });
    },
    close: async () => {
      calls.push(['close']);
    },
  };
  for (const method of [
    'prepare',
    'beginApproval',
    'pollApproval',
    'lookupAttempt',
    'execute',
    'reconcile',
    'repair',
  ]) {
    runtime[method] = async (input) => {
      calls.push([method, input]);
      if (!input.principal) {
        return { status: 401, body: { status: 'refused', error: { code: 'authentication_required' } } };
      }
      return { status: method === 'prepare' ? 201 : 200, body: { status: 'ok', method } };
    };
  }
  return { runtime, calls };
}

async function withServer(runtime, callback) {
  const server = createHttpServer(runtime);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('health routes are unauthenticated and carry hardened response headers', async () => {
  const { runtime } = runtimeFixture();
  await withServer(runtime, async (origin) => {
    const response = await fetch(`${origin}/v1/live`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.deepEqual(await response.json(), { status: 'ok' });
  });
});

test('proposal preparation requires application bearer authentication', async () => {
  const { runtime, calls } = runtimeFixture();
  await withServer(runtime, async (origin) => {
    const denied = await fetch(`${origin}/v1/proposals`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        profile_id: 'github.repo.delete.v1',
        operation_id: 'operation:0000000000000001',
        action: {},
      }),
    });
    assert.equal(denied.status, 401);

    const allowed = await fetch(`${origin}/v1/proposals`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer gate-token',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        profile_id: 'github.repo.delete.v1',
        operation_id: 'operation:0000000000000001',
        action: {},
      }),
    });
    assert.equal(allowed.status, 201);
    assert.equal(calls.at(-1)[0], 'prepare');
    assert.equal(calls.at(-1)[1].principal.id, 'principal:operator');
  });
});

test('strict JSON rejects duplicate members before runtime dispatch', async () => {
  const { runtime, calls } = runtimeFixture();
  await withServer(runtime, async (origin) => {
    const response = await fetch(`${origin}/v1/proposals`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer gate-token',
        'content-type': 'application/json',
      },
      body: '{"profile_id":"github.repo.delete.v1","profile_id":"other","operation_id":"operation:1","action":{}}',
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, 'json_invalid');
    assert.equal(calls.length, 0);
  });
});

test('proposal lifecycle paths dispatch only their exact method', async () => {
  const { runtime, calls } = runtimeFixture();
  const cases = [
    ['/v1/proposals/proposal:0000000000000001/approval-requests', 'beginApproval'],
    ['/v1/proposals/proposal:0000000000000001/approval-requests/poll', 'pollApproval'],
    ['/v1/proposals/proposal:0000000000000001/attempts/lookup', 'lookupAttempt'],
    ['/v1/proposals/proposal:0000000000000001/execute', 'execute'],
    ['/v1/proposals/proposal:0000000000000001/reconcile', 'reconcile'],
    ['/v1/proposals/proposal:0000000000000001/repair', 'repair'],
  ];
  await withServer(runtime, async (origin) => {
    for (const [path, method] of cases) {
      const response = await fetch(`${origin}${path}`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer gate-token',
          'content-type': 'application/json',
        },
        body: '{}',
      });
      assert.equal(response.status, 200);
      assert.equal(calls.at(-1)[0], method);
      assert.equal(calls.at(-1)[1].proposalId, 'proposal:0000000000000001');
    }
  });
});

test('unsupported methods and paths are closed without authentication work', async () => {
  const { runtime, calls } = runtimeFixture();
  let authCalls = 0;
  runtime.authenticate = async () => {
    authCalls += 1;
    return { id: 'principal:operator' };
  };
  await withServer(runtime, async (origin) => {
    assert.equal((await fetch(`${origin}/v1/proposals`)).status, 405);
    assert.equal((await fetch(`${origin}/v1/not-a-route`)).status, 404);
  });
  assert.equal(authCalls, 0);
  assert.equal(calls.length, 0);
});

test('admission stop refuses new lifecycle work before authentication or body dispatch', async () => {
  const { runtime, calls } = runtimeFixture();
  let authCalls = 0;
  runtime.authenticate = async () => {
    authCalls += 1;
    return { id: 'principal:operator' };
  };
  runtime.stopAdmission();
  await withServer(runtime, async (origin) => {
    const response = await fetch(`${origin}/v1/proposals`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer gate-token',
        'content-type': 'application/json',
      },
      body: '{}',
    });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error.code, 'service_draining');
  });
  assert.equal(authCalls, 0);
  assert.equal(calls.length, 0);
});

test('SIGTERM stops admission and drains an in-flight provider call before runtime close', async () => {
  const { runtime, calls } = runtimeFixture();
  let releaseProvider;
  let providerStarted;
  const started = new Promise((resolve) => {
    providerStarted = resolve;
  });
  runtime.execute = async (input) => {
    calls.push(['execute', input]);
    providerStarted();
    await new Promise((resolve) => {
      releaseProvider = resolve;
    });
    return { status: 200, body: { status: 'completed' } };
  };

  const server = createHttpServer(runtime);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const processLike = new EventEmitter();
  processLike.exitCode = undefined;
  const signals = installShutdownHandlers(
    { server, runtime },
    { processLike, graceMs: 1_000 },
  );
  const { port } = server.address();
  const providerResponse = fetch(
    `http://127.0.0.1:${port}/v1/proposals/proposal:0000000000000001/execute`,
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer gate-token',
        'content-type': 'application/json',
      },
      body: '{}',
    },
  );
  await started;

  processLike.emit('SIGTERM');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.some(([name]) => name === 'close'), false);

  releaseProvider();
  assert.equal((await providerResponse).status, 200);
  await signals.done();
  assert.equal(calls.filter(([name]) => name === 'close').length, 1);
  assert.equal(processLike.exitCode, undefined);
  signals.dispose();
});

test('SIGTERM bounds provider drain and closes runtime after grace expires', async () => {
  const { runtime, calls } = runtimeFixture();
  let releaseProvider;
  let providerStarted;
  const started = new Promise((resolve) => {
    providerStarted = resolve;
  });
  runtime.execute = async (input) => {
    calls.push(['execute', input]);
    providerStarted();
    await new Promise((resolve) => {
      releaseProvider = resolve;
    });
    return { status: 200, body: { status: 'completed' } };
  };

  const server = createHttpServer(runtime);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const processLike = new EventEmitter();
  processLike.exitCode = undefined;
  const signals = installShutdownHandlers(
    { server, runtime },
    { processLike, graceMs: 25 },
  );
  const { port } = server.address();
  const providerResponse = fetch(
    `http://127.0.0.1:${port}/v1/proposals/proposal:0000000000000001/execute`,
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer gate-token',
        'content-type': 'application/json',
      },
      body: '{}',
    },
  ).catch((error) => error);
  await started;

  const shutdownStartedAt = Date.now();
  processLike.emit('SIGTERM');
  await signals.done();
  const elapsed = Date.now() - shutdownStartedAt;
  assert.ok(elapsed >= 20);
  assert.ok(elapsed < 500);
  assert.equal(calls.filter(([name]) => name === 'close').length, 1);

  releaseProvider();
  await providerResponse;
  signals.dispose();
});
