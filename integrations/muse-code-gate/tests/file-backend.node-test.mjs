// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { createDurableConsumptionStore } from '../../../packages/gate/index.js';
import {
  FILE_BACKEND_LOCK_VERSION,
  createFileKvBackend,
} from '../file-backend.mjs';

async function temporaryState(t) {
  const directory = await mkdtemp(join(tmpdir(), 'emilia-muse-file-store-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, statePath: join(directory, 'consumption-state.json') };
}

function definitelyDeadPid() {
  const candidate = 2_147_483_647;
  try {
    process.kill(candidate, 0);
  } catch (error) {
    if (error?.code === 'ESRCH') return candidate;
  }
  throw new Error('test could not identify a definitely dead PID');
}

async function installLock(statePath, { pid, ownerHostname = hostname(), token = '01234567-89ab-cdef-0123-456789abcdef' }) {
  const lockDirectory = `${statePath}.lock`;
  await mkdir(lockDirectory, { mode: 0o700 });
  await writeFile(join(lockDirectory, 'owner.json'), `${JSON.stringify({
    version: FILE_BACKEND_LOCK_VERSION,
    pid,
    hostname: ownerHostname,
    token,
    created_at: '2026-09-23T00:00:00.000Z',
  })}\n`, { mode: 0o600 });
  return lockDirectory;
}

async function installRecoveryMarker(lockDirectory, {
  pid,
  ownerHostname = hostname(),
  token = 'abcdef01-2345-6789-abcd-ef0123456789',
}) {
  await writeFile(join(lockDirectory, 'recovery.json'), `${JSON.stringify({
    version: FILE_BACKEND_LOCK_VERSION,
    pid,
    hostname: ownerHostname,
    token,
    created_at: '2026-09-23T00:00:00.000Z',
    observed_owner_token: null,
  })}\n`, { mode: 0o600 });
}

test('committed replay state survives backend reconstruction (restart)', async (t) => {
  const { statePath } = await temporaryState(t);
  const firstBackend = await createFileKvBackend(statePath);
  const firstStore = createDurableConsumptionStore(firstBackend, {
    reservationTokenFactory: () => 'first-process-token-000000000001',
  });
  assert.equal(await firstStore.reserve('receipt:restart'), true);
  assert.equal(await firstStore.commit('receipt:restart'), true);

  // A fresh backend/store instance models a stopped and restarted MCP server.
  const restartedBackend = await createFileKvBackend(statePath);
  const restartedStore = createDurableConsumptionStore(restartedBackend, {
    reservationTokenFactory: () => 'second-process-token-00000000002',
  });
  assert.equal(await restartedStore.has('receipt:restart'), true);
  assert.equal(await restartedStore.reserve('receipt:restart'), false);
  const persisted = JSON.parse(await readFile(statePath, 'utf8'));
  assert.equal(persisted['receipt:restart'], 'committed:v2');
});

test('dead same-host lock is recovered before the state mutation', async (t) => {
  const { statePath } = await temporaryState(t);
  await installLock(statePath, { pid: definitelyDeadPid() });
  const backend = await createFileKvBackend(statePath, { lockRetries: 3, lockDelayMs: 0 });
  assert.equal(await backend.addIfAbsent('receipt:after-crash', 'committed:v2'), true);
  assert.equal(await backend.has('receipt:after-crash'), true);
});

test('ownerless and invalid lock directories recover only after the configured grace', async (t) => {
  for (const ownerContents of [null, '{"truncated":']) {
    const { statePath } = await temporaryState(t);
    const lockDirectory = `${statePath}.lock`;
    await mkdir(lockDirectory, { mode: 0o700 });
    if (ownerContents !== null) {
      await writeFile(join(lockDirectory, 'owner.json'), ownerContents, { mode: 0o600 });
    }

    const failClosedBackend = await createFileKvBackend(statePath, {
      lockRetries: 1,
      lockDelayMs: 0,
      orphanLockGraceMs: 60_000,
    });
    await assert.rejects(
      failClosedBackend.addIfAbsent('receipt:before-grace', 'committed:v2'),
      /consumption_store_lock_timeout/,
    );
    assert.equal((await stat(lockDirectory)).isDirectory(), true);

    const recoveringBackend = await createFileKvBackend(statePath, {
      lockRetries: 3,
      lockDelayMs: 0,
      orphanLockGraceMs: 0,
    });
    assert.equal(
      await recoveringBackend.addIfAbsent('receipt:after-grace', 'committed:v2'),
      true,
    );
  }
});

test('zero orphan grace recovers despite a fractional future filesystem mtime', async (t) => {
  const { statePath } = await temporaryState(t);
  const lockDirectory = `${statePath}.lock`;
  await mkdir(lockDirectory, { mode: 0o700 });
  const fractionalFutureSeconds = (Date.now() + 0.75) / 1000;
  await utimes(lockDirectory, fractionalFutureSeconds, fractionalFutureSeconds);
  const backend = await createFileKvBackend(statePath, {
    lockRetries: 2,
    lockDelayMs: 0,
    orphanLockGraceMs: 0,
  });
  assert.equal(await backend.addIfAbsent('receipt:fractional-mtime', 'committed:v2'), true);
});

test('a dead recovery owner remains fail-closed for operator repair', async (t) => {
  const { statePath } = await temporaryState(t);
  const lockDirectory = await installLock(statePath, { pid: definitelyDeadPid() });
  await installRecoveryMarker(lockDirectory, { pid: definitelyDeadPid() });
  const backend = await createFileKvBackend(statePath, {
    lockRetries: 2,
    lockDelayMs: 0,
    orphanLockGraceMs: 0,
  });
  await assert.rejects(
    backend.addIfAbsent('receipt:recovery-restart', 'committed:v2'),
    /consumption_store_lock_timeout/,
  );
  const marker = JSON.parse(await readFile(join(lockDirectory, 'recovery.json'), 'utf8'));
  assert.equal(marker.pid, definitelyDeadPid());
});

test('ownerless lock with a recovery marker remains fail-closed', async (t) => {
  const { statePath } = await temporaryState(t);
  const lockDirectory = `${statePath}.lock`;
  await mkdir(lockDirectory, { mode: 0o700 });
  await installRecoveryMarker(lockDirectory, { pid: definitelyDeadPid() });
  const backend = await createFileKvBackend(statePath, {
    lockRetries: 2,
    lockDelayMs: 0,
    orphanLockGraceMs: 0,
  });
  await assert.rejects(
    backend.addIfAbsent('receipt:owner-unlinked', 'committed:v2'),
    /consumption_store_lock_timeout/,
  );
  assert.equal((await stat(join(lockDirectory, 'recovery.json'))).isFile(), true);
});

test('live recovery owner is never stolen', async (t) => {
  const { statePath } = await temporaryState(t);
  const lockDirectory = await installLock(statePath, { pid: definitelyDeadPid() });
  const recoveryToken = 'live-recovery-token-0123456789abcdef';
  await installRecoveryMarker(lockDirectory, { pid: process.pid, token: recoveryToken });
  const backend = await createFileKvBackend(statePath, {
    lockRetries: 2,
    lockDelayMs: 0,
    orphanLockGraceMs: 0,
  });
  await assert.rejects(
    backend.addIfAbsent('receipt:must-not-steal-recovery', 'committed:v2'),
    /consumption_store_lock_timeout/,
  );
  const recoveryOwner = JSON.parse(await readFile(join(lockDirectory, 'recovery.json'), 'utf8'));
  assert.equal(recoveryOwner.pid, process.pid);
  assert.equal(recoveryOwner.token, recoveryToken);
});

test('two backend instances serialize addIfAbsent on one state file', async (t) => {
  const { statePath } = await temporaryState(t);
  const first = await createFileKvBackend(statePath);
  const second = await createFileKvBackend(statePath);
  const results = await Promise.all([
    first.addIfAbsent('receipt:contended', 'first'),
    second.addIfAbsent('receipt:contended', 'second'),
  ]);
  assert.deepEqual([...results].sort(), [false, true]);
  const state = JSON.parse(await readFile(statePath, 'utf8'));
  assert.equal(['first', 'second'].includes(state['receipt:contended']), true);
});

test('backend get returns the exact stored value for reconciliation pinning', async (t) => {
  const { statePath } = await temporaryState(t);
  const backend = await createFileKvBackend(statePath);
  assert.equal(await backend.get('reconcile:missing'), null);
  assert.equal(await backend.addIfAbsent('reconcile:one', '{"terminal":true}'), true);
  assert.equal(await backend.get('reconcile:one'), '{"terminal":true}');
});

test('live lock ownership is never stolen', async (t) => {
  const { statePath } = await temporaryState(t);
  const token = 'live-owner-token-0123456789abcdef';
  const lockDirectory = await installLock(statePath, { pid: process.pid, token });
  const backend = await createFileKvBackend(statePath, { lockRetries: 2, lockDelayMs: 0 });
  await assert.rejects(
    backend.addIfAbsent('receipt:must-not-write', 'committed:v2'),
    /consumption_store_lock_timeout/,
  );
  const owner = JSON.parse(await readFile(join(lockDirectory, 'owner.json'), 'utf8'));
  assert.equal(owner.pid, process.pid);
  assert.equal(owner.token, token);
  await assert.rejects(readFile(statePath, 'utf8'), { code: 'ENOENT' });
});

test('foreign-host lock fails closed even when its PID is absent locally', async (t) => {
  const { statePath } = await temporaryState(t);
  const lockDirectory = await installLock(statePath, {
    pid: definitelyDeadPid(),
    ownerHostname: 'some-other-host.invalid',
  });
  const backend = await createFileKvBackend(statePath, { lockRetries: 2, lockDelayMs: 0 });
  await assert.rejects(
    backend.addIfAbsent('receipt:foreign-host', 'committed:v2'),
    /consumption_store_lock_timeout/,
  );
  const owner = JSON.parse(await readFile(join(lockDirectory, 'owner.json'), 'utf8'));
  assert.equal(owner.hostname, 'some-other-host.invalid');
});
