// SPDX-License-Identifier: Apache-2.0
/** Local, single-host atomic backend for the runnable demo consumption store. */
import {
  mkdir,
  lstat,
  open,
  readFile,
  rename,
  rmdir,
  stat,
  unlink,
} from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { hostname as localHostname } from 'node:os';
import { dirname, join } from 'node:path';

export const FILE_BACKEND_LOCK_VERSION = 'EP-MUSE-FILE-LOCK-v1';
const DEFAULT_LOCK_RETRIES = 250;
const DEFAULT_LOCK_DELAY_MS = 20;
const DEFAULT_ORPHAN_LOCK_GRACE_MS = 2_000;
const OWNER_FILE = 'owner.json';
const RECOVERY_FILE = 'recovery.json';

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function validPositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function validOwner(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && value.version === FILE_BACKEND_LOCK_VERSION
    && validPositiveInteger(value.pid)
    && typeof value.hostname === 'string'
    && value.hostname.length > 0
    && typeof value.token === 'string'
    && value.token.length >= 16
    && typeof value.created_at === 'string'
    && !Number.isNaN(Date.parse(value.created_at));
}

function sameOwner(left, right) {
  return validOwner(left)
    && validOwner(right)
    && left.pid === right.pid
    && left.hostname === right.hostname
    && left.token === right.token;
}

function pidIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means a process exists but this uid cannot signal it. Only ESRCH
    // proves non-existence; every other result fails closed as live/unknown.
    return error?.code !== 'ESRCH';
  }
}

async function syncDirectory(path) {
  const handle = await open(path, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function writeSyncedJson(path, value) {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readState(path) {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('state_not_object');
    // Null-prototype reconstruction keeps signed receipt identifiers from ever
    // becoming magic properties such as __proto__ in the persisted map.
    const state = Object.create(null);
    for (const [key, value] of Object.entries(parsed)) state[key] = value;
    return state;
  } catch (error) {
    if (error?.code === 'ENOENT') return Object.create(null);
    throw error;
  }
}

async function writeState(path, state) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let renamed = false;
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(state)}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    renamed = true;
    // fsync(file) persists the bytes; fsync(parent directory) persists the
    // rename itself across a crash/restart.
    await syncDirectory(dirname(path));
  } finally {
    if (!renamed) await unlink(temporary).catch(() => {});
  }
}

async function readLockOwner(lockDirectory) {
  try {
    const owner = await readJson(join(lockDirectory, OWNER_FILE));
    return validOwner(owner) ? owner : null;
  } catch {
    return null;
  }
}

async function readRecoveryOwner(recoveryPath) {
  try {
    const owner = await readJson(recoveryPath);
    return validOwner(owner) ? owner : null;
  } catch {
    return null;
  }
}

async function lockDirectorySnapshot(lockDirectory) {
  try {
    const details = await lstat(lockDirectory);
    if (!details.isDirectory()) return null;
    return {
      device: details.dev,
      inode: details.ino,
      modifiedAtMs: details.mtimeMs,
    };
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function sameLockDirectory(left, right) {
  return left !== null
    && right !== null
    && left.device === right.device
    && left.inode === right.inode;
}

async function removeRecoveryMarker(
  lockDirectory,
  recoveryPath,
  observedDirectory,
  recoveryOwner,
) {
  const currentDirectory = await lockDirectorySnapshot(lockDirectory);
  const currentRecoveryOwner = await readRecoveryOwner(recoveryPath);
  if (sameLockDirectory(observedDirectory, currentDirectory)
    && sameOwner(recoveryOwner, currentRecoveryOwner)) {
    await unlink(recoveryPath).catch(() => {});
  }
}

/**
 * Recover a lock only after proving its recorded owner is a dead PID on this
 * host. A recovery file is created inside the still-existing lock directory,
 * so other recovery attempts cannot race a new live acquisition into the path.
 */
async function recoverStaleLock(lockDirectory, hostname, orphanLockGraceMs) {
  const observedDirectory = await lockDirectorySnapshot(lockDirectory);
  if (!observedDirectory) return false;
  const observed = await readLockOwner(lockDirectory);
  const deadSameHostOwner = observed
    && observed.hostname === hostname
    && !pidIsAlive(observed.pid);
  // Date.now() is integer milliseconds while APFS mtimeMs can be fractional
  // and slightly ahead within the same millisecond. An explicit zero grace
  // means recover immediately, not "only if the rounded age is nonnegative".
  const orphanedLongEnough = !observed
    && (orphanLockGraceMs === 0
      || Date.now() - observedDirectory.modifiedAtMs >= orphanLockGraceMs);
  if (!deadSameHostOwner && !orphanedLongEnough) return false;

  const recoveryPath = join(lockDirectory, RECOVERY_FILE);
  const recoveryOwner = {
    version: FILE_BACKEND_LOCK_VERSION,
    pid: process.pid,
    hostname,
    token: randomUUID(),
    created_at: new Date().toISOString(),
    observed_owner_token: observed?.token ?? null,
  };
  try {
    await writeSyncedJson(recoveryPath, recoveryOwner);
  } catch (error) {
    if (error?.code === 'EEXIST') {
      // Never reclaim another recovery marker automatically. A process can
      // die mid-recovery, but check-then-delete reclamation can also delete a
      // newly created live marker and admit two writers. This demo chooses a
      // fail-closed operator repair over that replay-safety risk.
      return false;
    }
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
  await syncDirectory(lockDirectory);

  const fencedDirectory = await lockDirectorySnapshot(lockDirectory);
  const fencedRecoveryOwner = await readRecoveryOwner(recoveryPath);
  if (!sameLockDirectory(observedDirectory, fencedDirectory)
    || !sameOwner(recoveryOwner, fencedRecoveryOwner)) {
    await removeRecoveryMarker(
      lockDirectory,
      recoveryPath,
      observedDirectory,
      recoveryOwner,
    );
    return false;
  }

  const confirmed = await readLockOwner(lockDirectory);
  if (observed) {
    if (!sameOwner(observed, confirmed)
      || confirmed.hostname !== hostname
      || pidIsAlive(confirmed.pid)) {
      await removeRecoveryMarker(
        lockDirectory,
        recoveryPath,
        observedDirectory,
        recoveryOwner,
      );
      return false;
    }
  } else if (confirmed) {
    // A creator that was paused between mkdir and publishing owner metadata
    // won the race. Its live owner is never stolen; a dead owner can be
    // considered by a later recovery attempt.
    await removeRecoveryMarker(
      lockDirectory,
      recoveryPath,
      observedDirectory,
      recoveryOwner,
    );
    return false;
  }

  const finalDirectory = await lockDirectorySnapshot(lockDirectory);
  const finalRecoveryOwner = await readRecoveryOwner(recoveryPath);
  if (!sameLockDirectory(observedDirectory, finalDirectory)
    || !sameOwner(recoveryOwner, finalRecoveryOwner)) {
    await removeRecoveryMarker(
      lockDirectory,
      recoveryPath,
      observedDirectory,
      recoveryOwner,
    );
    return false;
  }

  // For a valid dead owner, this removes the exact owner revalidated above.
  // For an invalid owner, the recovery marker fences its would-be publisher:
  // acquisition does not succeed until it re-reads its owner and sees no
  // recovery marker. Thus a partially written owner can be removed safely.
  await unlink(join(lockDirectory, OWNER_FILE)).catch((error) => {
    if (error?.code !== 'ENOENT') throw error;
  });
  await unlink(recoveryPath);
  try {
    await rmdir(lockDirectory);
  } catch (error) {
    // A paused creator may publish an owner after the final check. rmdir then
    // fails closed rather than deleting a newly active lock.
    if (error?.code === 'ENOTEMPTY' || error?.code === 'EEXIST') return false;
    throw error;
  }
  await syncDirectory(dirname(lockDirectory));
  return true;
}

async function acquireLock(lockDirectory, {
  hostname,
  lockRetries,
  lockDelayMs,
  orphanLockGraceMs,
}) {
  for (let attempt = 0; attempt < lockRetries; attempt += 1) {
    const owner = {
      version: FILE_BACKEND_LOCK_VERSION,
      pid: process.pid,
      hostname,
      token: randomUUID(),
      created_at: new Date().toISOString(),
    };
    try {
      await mkdir(lockDirectory, { mode: 0o700 });
      try {
        await writeSyncedJson(join(lockDirectory, OWNER_FILE), owner);
        await syncDirectory(lockDirectory);
        const published = await readLockOwner(lockDirectory);
        try {
          await lstat(join(lockDirectory, RECOVERY_FILE));
          throw new Error('consumption_store_lock_recovery_in_progress');
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error;
        }
        if (!sameOwner(owner, published)) {
          throw new Error('consumption_store_lock_ownership_lost');
        }
        await syncDirectory(dirname(lockDirectory));
        return owner;
      } catch (error) {
        // We created the directory but failed to publish durable ownership.
        // Remove only our empty/partial directory; another process cannot have
        // acquired it while the directory existed.
        await unlink(join(lockDirectory, OWNER_FILE)).catch(() => {});
        await rmdir(lockDirectory).catch(() => {});
        throw error;
      }
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      await recoverStaleLock(lockDirectory, hostname, orphanLockGraceMs);
      if (attempt + 1 < lockRetries) await pause(lockDelayMs);
    }
  }
  throw new Error('consumption_store_lock_timeout');
}

async function releaseLock(lockDirectory, owner) {
  const current = await readLockOwner(lockDirectory);
  if (!sameOwner(owner, current)) throw new Error('consumption_store_lock_ownership_lost');
  await unlink(join(lockDirectory, OWNER_FILE));
  await rmdir(lockDirectory);
  await syncDirectory(dirname(lockDirectory));
}

async function withLock(path, options, operation) {
  const lockDirectory = `${path}.lock`;
  const owner = await acquireLock(lockDirectory, options);
  try {
    return await operation();
  } finally {
    await releaseLock(lockDirectory, owner);
  }
}

/**
 * Backend contract consumed by Gate's createDurableConsumptionStore(). It is
 * suitable for one local Muse MCP server. Multi-host deployments need a
 * linearizable shared backend such as Postgres, DynamoDB, or Redis.
 */
export async function createFileKvBackend(path, {
  lockRetries = DEFAULT_LOCK_RETRIES,
  lockDelayMs = DEFAULT_LOCK_DELAY_MS,
  orphanLockGraceMs = DEFAULT_ORPHAN_LOCK_GRACE_MS,
} = {}) {
  if (typeof path !== 'string' || path.length === 0) throw new TypeError('state_file_required');
  if (!validPositiveInteger(lockRetries)) throw new TypeError('lockRetries_must_be_positive_integer');
  if (!Number.isSafeInteger(lockDelayMs) || lockDelayMs < 0) {
    throw new TypeError('lockDelayMs_must_be_nonnegative_integer');
  }
  if (!Number.isSafeInteger(orphanLockGraceMs) || orphanLockGraceMs < 0) {
    throw new TypeError('orphanLockGraceMs_must_be_nonnegative_integer');
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const lockOptions = Object.freeze({
    hostname: localHostname(),
    lockRetries,
    lockDelayMs,
    orphanLockGraceMs,
  });
  return Object.freeze({
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    atomicReplayFenced: true,
    async health() {
      try {
        await stat(dirname(path));
        return { ok: true };
      } catch {
        return { ok: false, reason: 'state_directory_unavailable' };
      }
    },
    async addIfAbsent(key, value) {
      return withLock(path, lockOptions, async () => {
        const state = await readState(path);
        if (Object.hasOwn(state, key)) return false;
        state[key] = value;
        await writeState(path, state);
        return true;
      });
    },
    async compareAndSet(key, expected, replacement) {
      return withLock(path, lockOptions, async () => {
        const state = await readState(path);
        if (state[key] !== expected) return false;
        state[key] = replacement;
        await writeState(path, state);
        return true;
      });
    },
    async deleteIfValue(key, expected) {
      return withLock(path, lockOptions, async () => {
        const state = await readState(path);
        if (state[key] !== expected) return false;
        delete state[key];
        await writeState(path, state);
        return true;
      });
    },
    async get(key) {
      return withLock(path, lockOptions, async () => {
        const state = await readState(path);
        return Object.hasOwn(state, key) ? state[key] : null;
      });
    },
    async has(key) {
      return withLock(path, lockOptions, async () => Object.hasOwn(await readState(path), key));
    },
  });
}
