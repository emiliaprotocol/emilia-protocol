// SPDX-License-Identifier: Apache-2.0
/**
 * Lifetime management for read-only scratch trees under the OS temp directory.
 *
 * The reproducibility verifiers make their reviewed source snapshots read-only
 * and spend almost all of their runtime blocked in spawnSync. A signal handler
 * registered in such a process cannot run until the synchronous work returns
 * (a SIGTERM delivered during spawnSync is simply never observed), so in-process
 * handlers cannot clean up after a kill and would turn `kill` into a no-op.
 * Instead, the CLI entry point supervises: it owns a private scratch root, runs
 * the real work in a child process group whose TMPDIR is that root, and removes
 * the root once the whole group is gone, whatever ended it. A startup sweep of
 * day-old leftovers covers the only case supervision cannot, the supervisor
 * itself being SIGKILLed.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const STALE_SCRATCH_AGE_MS: number = 24 * 60 * 60 * 1000;
const MKDTEMP_SUFFIX: RegExp = /^[A-Za-z0-9]{6}$/u;
const FORWARDED_SIGNALS: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
const KILL_GRACE_MS: number = 5_000;

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === 'ENOENT';
}

/**
 * Restore owner permissions throughout `target` and remove it. Directories need
 * owner write and search permission before their entries can be unlinked;
 * Windows additionally refuses to delete read-only files. Symlinks are removed
 * as links and never followed or chmodded. Entries that vanish concurrently
 * (another sweep, a dying writer) are tolerated.
 */
export function removeScratchTree(target: string): void {
  const restore = (entry: string): void => {
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(entry);
      if (stat.isSymbolicLink()) return;
      if (stat.isDirectory()) {
        if ((stat.mode & 0o700) !== 0o700) fs.chmodSync(entry, 0o700);
        for (const name of fs.readdirSync(entry)) restore(path.join(entry, name));
      } else if (process.platform === 'win32' && (stat.mode & 0o200) === 0) {
        fs.chmodSync(entry, 0o600);
      }
    } catch (error) {
      if (!isMissing(error)) throw error;
    }
  };
  restore(target);
  fs.rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

/**
 * Remove `<directory>/<prefix>XXXXXX` scratch directories (the exact mkdtemp
 * shape) that this user owns and that nothing has modified for `maxAgeMs`.
 * Symlinks, other users' directories and non-matching names are left alone.
 * Platforms without POSIX ownership are never swept. Best effort: a directory
 * that cannot be removed now is retried by the next run. Returns the removed paths.
 */
export function sweepStaleScratchDirectories(
  prefix: string,
  {
    directory = os.tmpdir(),
    maxAgeMs = STALE_SCRATCH_AGE_MS,
    now = Date.now(),
    uid = process.getuid?.() ?? null,
  }: {
    directory?: string;
    maxAgeMs?: number;
    now?: number;
    uid?: number | null;
  } = {},
): string[] {
  if (uid === null) return [];
  let names: string[];
  try {
    names = fs.readdirSync(directory);
  } catch {
    return [];
  }
  const removed: string[] = [];
  for (const name of names) {
    if (!name.startsWith(prefix) || !MKDTEMP_SUFFIX.test(name.slice(prefix.length))) continue;
    const candidate: string = path.join(directory, name);
    try {
      const stat: fs.Stats = fs.lstatSync(candidate);
      if (!stat.isDirectory() || stat.uid !== uid) continue;
      if (now - Math.max(stat.mtimeMs, stat.ctimeMs) < maxAgeMs) continue;
      removeScratchTree(candidate);
      removed.push(candidate);
    } catch {
      // Left for the next sweep.
    }
  }
  return removed;
}

/**
 * Re-run the current CLI (`process.execPath` with the same execArgv, script
 * and arguments) as a supervised worker, marked by `workerEnv=1`, whose
 * TMPDIR/TMP/TEMP is a fresh `<prefix>XXXXXX` root. The root is removed when
 * the worker exits for any reason, when this process receives SIGINT, SIGTERM
 * or SIGHUP (forwarded to the worker's whole process group first, escalating
 * to SIGKILL after a grace period, then re-raised so the caller sees the
 * signal), and on this process's own exit, including exits caused by uncaught
 * errors. Stale roots from earlier runs are swept before starting. The worker's
 * exit status becomes this process's exit status.
 */
export function superviseScratchRoot(prefix: string, workerEnv: string): void {
  const swept: string[] = sweepStaleScratchDirectories(prefix);
  if (swept.length > 0) {
    console.error(`removed ${swept.length} stale ${prefix}* scratch director${swept.length === 1 ? 'y' : 'ies'}`);
  }
  const root: string = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  // A POSIX worker leads its own process group so one kill reaches every
  // spawnSync descendant (npm, git, tar, package builds) still writing into
  // the root. Windows has no process groups; there only the worker is signalled.
  const ownGroup: boolean = process.platform !== 'win32';
  let removed: boolean = false;
  let received: NodeJS.Signals | null = null;

  const signalWorkers = (signal: NodeJS.Signals): void => {
    if (worker.pid === undefined) return;
    try {
      if (ownGroup) process.kill(-worker.pid, signal);
      else if (worker.exitCode === null && worker.signalCode === null) worker.kill(signal);
    } catch {
      // ESRCH: nothing left to signal.
    }
  };
  const cleanup = (): void => {
    if (removed) return;
    removed = true;
    // Stragglers must be gone before the tree is removed or they may recreate it.
    signalWorkers('SIGKILL');
    removeScratchTree(root);
  };
  const onSignal = (signal: NodeJS.Signals): void => {
    if (received) {
      signalWorkers('SIGKILL');
      return;
    }
    received = signal;
    signalWorkers(signal);
    setTimeout(() => signalWorkers('SIGKILL'), KILL_GRACE_MS).unref();
  };

  const worker = spawn(process.execPath, [...process.execArgv, ...process.argv.slice(1)], {
    detached: ownGroup,
    env: { ...process.env, [workerEnv]: '1', TMPDIR: root, TMP: root, TEMP: root },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  for (const signal of FORWARDED_SIGNALS) process.on(signal, onSignal);
  process.on('exit', cleanup);
  worker.on('error', (error: Error) => {
    console.error(`could not start supervised worker: ${error.message}`);
    cleanup();
    process.exitCode = 1;
  });
  worker.on('exit', (code: number | null, signal: NodeJS.Signals | null) => {
    cleanup();
    if (received) {
      for (const forwarded of FORWARDED_SIGNALS) process.removeListener(forwarded, onSignal);
      process.kill(process.pid, received);
      return;
    }
    process.exitCode = code ?? 128 + (signal ? os.constants.signals[signal] : 0);
  });
}
