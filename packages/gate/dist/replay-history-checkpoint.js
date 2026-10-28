// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/** Durable append-only checkpoint witness; deploy on an independently retained
 * filesystem outside BOTH authority PostgreSQL and operational-store rollback.
 * Owner/admin rollback of this witness together with the authority is excluded.
 * No clock freshness claims: every read/CAS takes the live filesystem lock.
 * Stale locks fail closed and require operator investigation, never auto-break.
 */
import { open, mkdir, readdir, readFile, link, unlink, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
const valid = (x) => x && Number.isSafeInteger(x.sequence) && x.sequence >= 0
    && typeof x.checkpoint_digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(x.checkpoint_digest);
const equal = (a, b) => a.sequence === b.sequence && a.checkpoint_digest === b.checkpoint_digest;
const filename = (sequence) => `${String(sequence).padStart(16, '0')}.json`;
async function syncDirectory(directory) { const file = await open(directory, 'r'); try {
    await file.sync();
}
finally {
    await file.close();
} }
async function append(directory, value) {
    const temporary = join(directory, `.pending-${randomUUID()}`);
    const file = await open(temporary, 'wx', 0o600);
    try {
        await file.writeFile(JSON.stringify(value));
        await file.sync();
    }
    finally {
        await file.close();
    }
    // link is exclusive: a committed checkpoint is never overwritten.
    try {
        await link(temporary, join(directory, filename(value.sequence)));
        await syncDirectory(directory);
    }
    finally {
        await unlink(temporary);
    }
}
/** Explicit one-time provisioning. Existing directories are NEVER reinitialized. */
export async function provisionReplayHistoryCheckpoint(directory, genesis) {
    if (typeof genesis !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(genesis))
        throw Error('checkpoint_genesis_invalid');
    await mkdir(directory, { mode: 0o700 });
    await append(directory, { sequence: 0, checkpoint_digest: genesis });
    await syncDirectory(join(directory, '..'));
}
export function createFileReplayHistoryCheckpoint(directory) {
    async function locked(operation) {
        const lock = join(directory, '.lock');
        await mkdir(lock, { mode: 0o700 });
        try {
            return await operation();
        }
        finally {
            await rmdir(lock);
        }
    }
    async function latest() {
        const files = (await readdir(directory)).filter(x => x.endsWith('.json')).sort();
        if (files.length === 0)
            throw Error('checkpoint_history_missing');
        let previous;
        for (let i = 0; i < files.length; i++) {
            if (files[i] !== filename(i))
                throw Error('checkpoint_history_gap');
            const value = JSON.parse(await readFile(join(directory, files[i]), 'utf8'));
            if (!valid(value) || value.sequence !== i)
                throw Error('checkpoint_history_invalid');
            previous = value;
        }
        return Object.freeze(previous);
    }
    return Object.freeze({
        read: () => locked(latest),
        advance: (expected, next) => locked(async () => {
            if (!valid(expected) || !valid(next) || next.sequence !== expected.sequence + 1
                || !equal(await latest(), expected))
                throw Error('checkpoint_compare_exchange_failed');
            await append(directory, next);
            return Object.freeze({ ...next });
        }),
    });
}
//# sourceMappingURL=replay-history-checkpoint.js.map