// SPDX-License-Identifier: Apache-2.0
/** Local, single-host atomic backend for the runnable demo consumption store. */
import { mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

const LOCK_RETRIES = 250;
const LOCK_DELAY_MS = 20;

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function readState(path) {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('state_not_object');
    return parsed;
  } catch (error) {
    if (error?.code === 'ENOENT') return Object.create(null);
    throw error;
  }
}

async function writeState(path, state) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(state)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
}

async function withLock(path, operation) {
  const lockPath = `${path}.lock`;
  let lock;
  for (let attempt = 0; attempt < LOCK_RETRIES; attempt += 1) {
    try {
      lock = await open(lockPath, 'wx', 0o600);
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      await pause(LOCK_DELAY_MS);
    }
  }
  if (!lock) throw new Error('consumption_store_lock_timeout');
  try {
    return await operation();
  } finally {
    await lock.close();
    await unlink(lockPath).catch(() => {});
  }
}

/**
 * Backend contract consumed by Gate's createDurableConsumptionStore(). It is
 * suitable for one local Muse MCP server. Multi-host deployments need a
 * linearizable shared backend such as Postgres, DynamoDB, or Redis.
 */
export async function createFileKvBackend(path) {
  if (typeof path !== 'string' || path.length === 0) throw new TypeError('state_file_required');
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  return Object.freeze({
    durable: true,
    async health() {
      try {
        await stat(dirname(path));
        return { ok: true };
      } catch {
        return { ok: false, reason: 'state_directory_unavailable' };
      }
    },
    async addIfAbsent(key, value) {
      return withLock(path, async () => {
        const state = await readState(path);
        if (Object.hasOwn(state, key)) return false;
        state[key] = value;
        await writeState(path, state);
        return true;
      });
    },
    async compareAndSet(key, expected, replacement) {
      return withLock(path, async () => {
        const state = await readState(path);
        if (state[key] !== expected) return false;
        state[key] = replacement;
        await writeState(path, state);
        return true;
      });
    },
    async deleteIfValue(key, expected) {
      return withLock(path, async () => {
        const state = await readState(path);
        if (state[key] !== expected) return false;
        delete state[key];
        await writeState(path, state);
        return true;
      });
    },
    async has(key) {
      return withLock(path, async () => Object.hasOwn(await readState(path), key));
    },
  });
}
