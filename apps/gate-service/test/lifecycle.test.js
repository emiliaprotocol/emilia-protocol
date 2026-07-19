// SPDX-License-Identifier: Apache-2.0
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  installShutdownHandlers,
  shutdownGateService,
} from '../src/server.js';
import {
  DELETE_BODY,
  createServiceFixture,
  receiptCarrier,
} from './helpers.js';

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`${signal} marks the runtime unready, stops the listener, and closes adapters`, async (t) => {
    let connectorCloses = 0;
    let siemCloses = 0;
    const fixture = await createServiceFixture(t, {
      connectorClose: async () => { connectorCloses += 1; },
      siemForwarder: {
        async forward() { return { delivered: true }; },
        async close() { siemCloses += 1; },
      },
    });
    const processLike = new EventEmitter();
    processLike.stderr = { write() {} };
    processLike.exitCode = undefined;
    const controls = installShutdownHandlers(
      { server: fixture.server, runtime: fixture.runtime },
      { processLike },
    );

    processLike.emit(signal);
    const result = await controls.shutdownPromise;

    assert.equal(result.graceMs, fixture.server.requestTimeout);
    assert.equal((await fixture.runtime.ready()).status, 503);
    assert.equal(fixture.server.listening, false);
    assert.equal(connectorCloses, 1);
    assert.equal(siemCloses, 1);
    assert.equal(processLike.exitCode, 0);
    controls.dispose();
  });
}

test('shutdown drains an active destructive request before closing adapters', async (t) => {
  let releaseDelete;
  let deleteStartedResolve;
  const deleteStarted = new Promise((resolve) => { deleteStartedResolve = resolve; });
  let connectorCloses = 0;
  const fixture = await createServiceFixture(t, {
    connectorClose: async () => { connectorCloses += 1; },
    deleteImpl: async () => {
      deleteStartedResolve();
      return new Promise((resolve) => { releaseDelete = resolve; });
    },
  });
  const request = fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  });
  await deleteStarted;

  const shutdown = shutdownGateService(
    { server: fixture.server, runtime: fixture.runtime },
    { graceMs: 500, adapterCloseTimeoutMs: 100 },
  );
  assert.equal((await fixture.runtime.ready()).status, 503);
  releaseDelete({ status: 204 });

  assert.equal((await request).status, 200);
  const result = await shutdown;
  assert.equal(result.drained, true);
  assert.equal(result.forced, false);
  assert.equal(connectorCloses, 1);
});

test('shutdown reports a configured adapter close failure', async (t) => {
  const fixture = await createServiceFixture(t, {
    connectorClose: async () => { throw new Error('close refused'); },
  });

  const result = await shutdownGateService(
    { server: fixture.server, runtime: fixture.runtime },
    { graceMs: 100, adapterCloseTimeoutMs: 100 },
  );

  assert.equal(result.drained, true);
  assert.equal(result.adaptersClosed, false);
});

test('shutdown force-closes a request that exceeds its bounded grace', async (t) => {
  let releaseDelete;
  let deleteStartedResolve;
  const deleteStarted = new Promise((resolve) => { deleteStartedResolve = resolve; });
  const fixture = await createServiceFixture(t, {
    deleteImpl: async () => {
      deleteStartedResolve();
      return new Promise((resolve) => { releaseDelete = resolve; });
    },
  });
  const request = fixture.request('/v1/actions', {
    method: 'POST',
    body: DELETE_BODY,
    carrier: receiptCarrier(fixture.harness.mint({ outcome: 'allow_with_signoff' })),
  }).catch((error) => error);
  await deleteStarted;

  const started = Date.now();
  const result = await shutdownGateService(
    { server: fixture.server, runtime: fixture.runtime },
    { graceMs: 30, adapterCloseTimeoutMs: 30 },
  );
  assert.equal(result.drained, false);
  assert.equal(result.forced, true);
  assert.ok(Date.now() - started < 500);

  releaseDelete({ status: 204 });
  assert.ok(await request instanceof Error);
});
