// SPDX-License-Identifier: Apache-2.0
// Generated from scratch-directory.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
 * the root once that group has no live members, whatever ended it. Descendants
 * deliberately detached into another session/group are outside this mechanism.
 * A startup sweep offers best-effort recovery of day-old leftovers from an
 * interrupted supervisor or failed cleanup.
 */
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
export const STALE_SCRATCH_AGE_MS = 24 * 60 * 60 * 1000;
const MKDTEMP_SUFFIX = /^[A-Za-z0-9]{6}$/u;
const FORWARDED_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
const KILL_GRACE_MS = 5_000;
const GROUP_POLL_MS = 25;
const PAUSE_WORD = new Int32Array(new SharedArrayBuffer(4));
function readProcessGroup(group, timeoutMs) {
    const result = spawnSync('/bin/ps', ['-A', '-o', 'pid=', '-o', 'pgid=', '-o', 'stat='], {
        encoding: 'utf8',
        timeout: Math.max(1, Math.ceil(timeoutMs)),
        killSignal: 'SIGKILL',
        maxBuffer: 16 * 1024 * 1024,
        env: { ...process.env, LC_ALL: 'C' },
    });
    if (result.error || result.status !== 0 || result.signal) {
        throw new Error(`could not observe process group ${group}: ${result.error?.message
            ?? result.signal ?? `ps exited ${result.status}: ${String(result.stderr).trim().slice(0, 300)}`}`);
    }
    const lines = String(result.stdout).trim().split('\n').filter((line) => line.trim());
    if (lines.length === 0)
        throw new Error(`could not observe process group ${group}: ps returned an empty table`);
    const members = [];
    for (const line of lines) {
        // Darwin can briefly report ?E for a process exiting after SIGKILL.
        // Unknown/exiting is still live: only a Z/X run state proves no writer.
        const match = /^\s*(\d+)\s+(\d+)\s+([A-Ztx?][+<>AELNSVWXls]*)\s*$/u.exec(line);
        if (!match)
            throw new Error(`could not observe process group ${group}: malformed ps row ${JSON.stringify(line)}`);
        const pid = Number(match[1]);
        const pgid = Number(match[2]);
        if (!Number.isSafeInteger(pid) || !Number.isSafeInteger(pgid)) {
            throw new Error(`could not observe process group ${group}: invalid ps identifiers`);
        }
        if (pgid === group)
            members.push({ pid, state: match[3] });
    }
    return members;
}
/**
 * SIGKILL delivery is not proof that a descendant's last filesystem syscall
 * finished. Observe the worker's POSIX group before unlinking its writable
 * tree. Zombies (Z) and dead processes (X) cannot write; kill(group, 0) still
 * sees them and would hang on Linux hosts whose init has not reaped them.
 * This is synchronous so the same bounded check also works in an exit hook.
 */
export function waitForProcessGroupQuiescence(group, { probe = readProcessGroup, now = () => performance.now(), pause = (milliseconds) => { Atomics.wait(PAUSE_WORD, 0, 0, milliseconds); }, timeoutMs = KILL_GRACE_MS, } = {}) {
    if (!Number.isSafeInteger(group) || group <= 1)
        throw new Error(`invalid supervised process group ${group}`);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > KILL_GRACE_MS) {
        throw new Error(`process-group observation timeout must be between 1 and ${KILL_GRACE_MS} ms`);
    }
    const deadline = now() + timeoutMs;
    let live = [];
    while (true) {
        const remaining = deadline - now();
        if (remaining <= 0) {
            throw new Error(`process group ${group} did not become quiescent within ${timeoutMs} ms; live members: ${live
                .map(({ pid, state }) => `${pid}:${state}`).join(', ') || 'not observed'}`);
        }
        live = probe(group, Math.min(remaining, 1_000))
            .filter(({ state }) => state[0] !== 'Z' && state[0] !== 'X');
        // An observation that completed after the deadline cannot prove bounded
        // cleanup, even if it eventually returned an empty group.
        if (now() >= deadline)
            continue;
        if (live.length === 0)
            return;
        pause(Math.min(GROUP_POLL_MS, deadline - now()));
    }
}
function isMissing(error) {
    return error?.code === 'ENOENT';
}
/**
 * Restore owner permissions throughout `target` and remove it. Directories need
 * owner write and search permission before their entries can be unlinked;
 * Windows additionally refuses to delete read-only files. Symlinks are removed
 * as links and never followed or chmodded. Entries that vanish concurrently
 * (another sweep, a dying writer) are tolerated.
 */
export function removeScratchTree(target) {
    const restore = (entry) => {
        let stat;
        try {
            stat = fs.lstatSync(entry);
            if (stat.isSymbolicLink())
                return;
            if (stat.isDirectory()) {
                if ((stat.mode & 0o700) !== 0o700)
                    fs.chmodSync(entry, 0o700);
                for (const name of fs.readdirSync(entry))
                    restore(path.join(entry, name));
            }
            else if (process.platform === 'win32' && (stat.mode & 0o200) === 0) {
                fs.chmodSync(entry, 0o600);
            }
        }
        catch (error) {
            if (!isMissing(error))
                throw error;
        }
    };
    restore(target);
    fs.rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
/**
 * Remove `<directory>/<prefix>XXXXXX` scratch directories (the exact mkdtemp
 * shape) that this user owns and that nothing has modified for `maxAgeMs`.
 * Symlinks, other users' directories and non-matching names are left alone.
 * Without POSIX ownership (Windows, `uid: null`) a directory is swept only when
 * it lies inside the user's own profile, as the default per-user %TEMP% does,
 * where no other user can create entries. Best effort: a directory that cannot
 * be removed now is retried by the next run. Returns the removed paths.
 */
export function sweepStaleScratchDirectories(prefix, { directory = os.tmpdir(), maxAgeMs = STALE_SCRATCH_AGE_MS, now = Date.now(), uid = process.getuid?.() ?? null, home = os.homedir(), } = {}) {
    if (uid === null) {
        const withinHome = path.relative(path.resolve(home), path.resolve(directory));
        if (!withinHome || withinHome.startsWith('..') || path.isAbsolute(withinHome))
            return [];
    }
    let names;
    try {
        names = fs.readdirSync(directory);
    }
    catch {
        return [];
    }
    const removed = [];
    for (const name of names) {
        if (!name.startsWith(prefix) || !MKDTEMP_SUFFIX.test(name.slice(prefix.length)))
            continue;
        const candidate = path.join(directory, name);
        try {
            const stat = fs.lstatSync(candidate);
            if (!stat.isDirectory() || (uid !== null && stat.uid !== uid))
                continue;
            if (now - Math.max(stat.mtimeMs, stat.ctimeMs) < maxAgeMs)
                continue;
            removeScratchTree(candidate);
            removed.push(candidate);
        }
        catch {
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
 * or SIGHUP (forwarded to the worker's process group first, escalating
 * to SIGKILL after a grace period, then re-raised so the caller sees the
 * signal), and on this process's own exit, including exits caused by uncaught
 * errors. Stale roots from earlier runs are swept before starting. The worker's
 * exit status becomes this process's exit status.
 *
 * Unknown or still-live group membership, or a failed unlink, retains the root
 * with a diagnostic and nonzero exit status instead of claiming signal success.
 * The returned promise settles once the worker has exited and cleanup has been
 * attempted, with process.exitCode already set. It never settles when a
 * forwarded signal is re-raised, since that ends this process. A CLI whose work runs at module
 * top level awaits it and exits, so the supervisor never runs that work itself.
 */
export function superviseScratchRoot(prefix, workerEnv, quiescenceOptions = {}) {
    const swept = sweepStaleScratchDirectories(prefix);
    if (swept.length > 0) {
        console.error(`removed ${swept.length} stale ${prefix}* scratch director${swept.length === 1 ? 'y' : 'ies'}`);
    }
    const root = path.resolve(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
    // A POSIX worker leads its own process group so one kill reaches spawnSync
    // descendants (npm, git, tar, package builds) remaining in that group.
    // Windows has no process groups or catchable SIGTERM; there the
    // worker's tree is force-terminated with taskkill /T while the worker is
    // alive, which is the only time its descendants can still be found.
    const ownGroup = process.platform !== 'win32';
    let removed = false;
    let received = null;
    const signalWorkers = (signal) => {
        if (worker.pid === undefined)
            return;
        try {
            if (ownGroup)
                process.kill(-worker.pid, signal);
            else if (worker.exitCode === null && worker.signalCode === null) {
                spawnSync('taskkill', ['/pid', String(worker.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
            }
        }
        catch {
            // ESRCH: nothing left to signal.
        }
    };
    const cleanup = () => {
        if (removed)
            return;
        // Stragglers must be gone before the tree is removed or they may recreate it.
        signalWorkers('SIGKILL');
        if (ownGroup && worker.pid !== undefined)
            waitForProcessGroupQuiescence(worker.pid, quiescenceOptions);
        removeScratchTree(root);
        removed = true;
    };
    const cleanupOrReport = () => {
        try {
            cleanup();
            return true;
        }
        catch (error) {
            console.error(`could not clean supervised scratch root ${root}; retained for a later sweep: ${error instanceof Error ? error.message : String(error)}`);
            process.exitCode = 1;
            return false;
        }
    };
    const onSignal = (signal) => {
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
    for (const signal of FORWARDED_SIGNALS)
        process.on(signal, onSignal);
    process.on('exit', () => { cleanupOrReport(); });
    return new Promise((resolve) => {
        worker.on('error', (error) => {
            console.error(`could not start supervised worker: ${error.message}`);
            cleanupOrReport();
            process.exitCode = 1;
            resolve();
        });
        worker.on('exit', (code, signal) => {
            if (!cleanupOrReport()) {
                resolve();
                return;
            }
            if (received) {
                for (const forwarded of FORWARDED_SIGNALS)
                    process.removeListener(forwarded, onSignal);
                process.kill(process.pid, received);
                return;
            }
            process.exitCode = code ?? 128 + (signal ? os.constants.signals[signal] : 0);
            resolve();
        });
    });
}
