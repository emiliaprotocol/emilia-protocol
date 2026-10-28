// SPDX-License-Identifier: Apache-2.0
// Generated from replay-history-checkpoint.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, unlink, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createFileReplayHistoryCheckpoint, provisionReplayHistoryCheckpoint } from './replay-history-checkpoint.js';
const root = `sha256:${'a'.repeat(64)}`;
const next = `sha256:${'b'.repeat(64)}`;
async function fixture(run) {
    const parent = await mkdtemp(join(import.meta.dirname, '.replay-checkpoint-'));
    try {
        const directory = join(parent, 'witness');
        await provisionReplayHistoryCheckpoint(directory, root);
        await run(directory);
    }
    finally {
        await rm(parent, { recursive: true, force: true });
    }
}
test('checkpoint live CAS admits one concurrent advance and survives new process handle', async () => fixture(async (directory) => {
    const first = createFileReplayHistoryCheckpoint(directory);
    const second = createFileReplayHistoryCheckpoint(directory);
    const before = { sequence: 0, checkpoint_digest: root };
    const after = { sequence: 1, checkpoint_digest: next };
    const results = await Promise.allSettled([first.advance(before, after), second.advance(before, after)]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.deepEqual(await createFileReplayHistoryCheckpoint(directory).read(), after);
    await assert.rejects(second.advance(before, after));
}));
test('checkpoint provisioning cannot reset an existing witness', async () => fixture(async (directory) => {
    await assert.rejects(provisionReplayHistoryCheckpoint(directory, next));
    assert.equal((await createFileReplayHistoryCheckpoint(directory).read()).checkpoint_digest, root);
}));
test('checkpoint missing genesis or coverage gap is uncertain', async () => fixture(async (directory) => {
    const witness = createFileReplayHistoryCheckpoint(directory);
    await witness.advance({ sequence: 0, checkpoint_digest: root }, { sequence: 1, checkpoint_digest: next });
    await unlink(join(directory, '0000000000000000.json'));
    await assert.rejects(witness.read(), /gap/);
}));
test('checkpoint corrupted bytes and stale lock fail closed', async () => fixture(async (directory) => {
    const witness = createFileReplayHistoryCheckpoint(directory);
    await mkdir(join(directory, '.lock'));
    await assert.rejects(witness.read());
    await rm(join(directory, '.lock'), { recursive: true });
    await writeFile(join(directory, '0000000000000000.json'), 'corrupt');
    await assert.rejects(witness.read());
}));
test('checkpoint missing directory never bootstraps on read', async () => fixture(async (directory) => {
    await rm(directory, { recursive: true });
    await assert.rejects(createFileReplayHistoryCheckpoint(directory).read());
}));
