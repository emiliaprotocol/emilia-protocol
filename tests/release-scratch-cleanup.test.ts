// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  removeScratchTree,
  sweepStaleScratchDirectories,
} from '../scripts/lib/scratch-directory.mjs';

const PREFIX = 'ep-repro-pack-';
const DAY_MS = 24 * 60 * 60 * 1000;
// Each killed run materializes a Git snapshot and starts a package build.
const FIXTURE_TIMEOUT_MS = 60_000;
const onWindows = process.platform === 'win32';

const created: string[] = [];
const running: ReturnType<typeof spawn>[] = [];
const tempDir = (label: string): string => {
  const directory = mkdtempSync(path.join(os.tmpdir(), `ep-scratch-test-${label}-`));
  created.push(directory);
  return directory;
};

// A read-only tree shaped like a verifier snapshot, with links that point out
// of the tree at read-only targets that must survive untouched.
const buildReadOnlyTree = (root: string, outside: string): void => {
  mkdirSync(path.join(root, 'reviewed-source', 'nested'), { recursive: true });
  writeFileSync(path.join(root, 'reviewed-source', 'nested', 'file.txt'), 'reviewed\n');
  writeFileSync(path.join(outside, 'target.txt'), 'outside\n');
  mkdirSync(path.join(outside, 'target-dir'));
  symlinkSync(path.join(outside, 'target.txt'), path.join(root, 'reviewed-source', 'file-link'));
  symlinkSync(path.join(outside, 'target-dir'), path.join(root, 'reviewed-source', 'dir-link'));
  chmodSync(path.join(outside, 'target.txt'), 0o444);
  chmodSync(path.join(outside, 'target-dir'), 0o555);
  chmodSync(path.join(root, 'reviewed-source', 'nested', 'file.txt'), 0o444);
  chmodSync(path.join(root, 'reviewed-source', 'nested'), 0o555);
  chmodSync(path.join(root, 'reviewed-source'), 0o555);
};

const scratchEntries = (directory: string): string[] =>
  readdirSync(directory).filter((name) => name.startsWith(PREFIX));

afterEach(async () => {
  // A failed assertion must not strand a supervised run.
  await Promise.all(running.splice(0).map((child) => new Promise<void>((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
  })));
  for (const directory of created.splice(0)) removeScratchTree(directory);
});

describe('reproducibility scratch cleanup', () => {
  it.skipIf(onWindows)('restores write permission and removes a read-only tree without following links', () => {
    const parent = tempDir('remove');
    const outside = tempDir('outside');
    const tree = path.join(parent, `${PREFIX}abc123`);
    mkdirSync(tree);
    buildReadOnlyTree(tree, outside);
    chmodSync(tree, 0o555);

    if (process.getuid?.() !== 0) {
      // The failure mode that stranded ~70 GB: plain rm cannot empty read-only directories.
      expect(() => execFileSync('rm', ['-rf', tree], { stdio: 'ignore' })).toThrow();
      expect(existsSync(path.join(tree, 'reviewed-source', 'nested', 'file.txt'))).toBe(true);
    }

    removeScratchTree(tree);

    expect(existsSync(tree)).toBe(false);
    expect(readFileSync(path.join(outside, 'target.txt'), 'utf8')).toBe('outside\n');
    expect(statSync(path.join(outside, 'target.txt')).mode & 0o777).toBe(0o444);
    expect(statSync(path.join(outside, 'target-dir')).mode & 0o777).toBe(0o555);
    expect(() => removeScratchTree(tree)).not.toThrow();
  });

  it.skipIf(onWindows)('sweeps only stale mkdtemp-shaped directories owned by this user', () => {
    const parent = tempDir('sweep');
    const outside = tempDir('sweep-outside');
    const stale = path.join(parent, `${PREFIX}Ab12Cd`);
    mkdirSync(stale);
    buildReadOnlyTree(stale, outside);
    const otherName = path.join(parent, `${PREFIX}toolong1`);
    const otherPrefix = path.join(parent, 'ep-other-pack-Ab12Cd');
    const plainFile = path.join(parent, `${PREFIX}file01`);
    const link = path.join(parent, `${PREFIX}link01`);
    mkdirSync(otherName);
    mkdirSync(otherPrefix);
    writeFileSync(plainFile, 'not a directory\n');
    symlinkSync(outside, link);

    // Everything here was just touched, so the real clock sweeps nothing.
    expect(sweepStaleScratchDirectories(PREFIX, { directory: parent })).toEqual([]);
    // Another user's directories are never swept.
    expect(sweepStaleScratchDirectories(PREFIX, {
      directory: parent,
      now: Date.now() + 2 * DAY_MS,
      uid: (process.getuid?.() ?? 0) + 1,
    })).toEqual([]);
    // Without an ownership model (Windows), only a per-user directory is swept.
    expect(sweepStaleScratchDirectories(PREFIX, {
      directory: parent,
      now: Date.now() + 2 * DAY_MS,
      uid: null,
      home: tempDir('other-home'),
    })).toEqual([]);
    expect(existsSync(stale)).toBe(true);
    expect(sweepStaleScratchDirectories(PREFIX, {
      directory: parent,
      now: Date.now() + 2 * DAY_MS,
      uid: null,
      home: path.dirname(parent),
    })).toEqual([stale]);
    expect(existsSync(stale)).toBe(false);

    const staleOwned = path.join(parent, `${PREFIX}Zz98Yx`);
    mkdirSync(staleOwned);
    chmodSync(staleOwned, 0o555);
    expect(sweepStaleScratchDirectories(PREFIX, {
      directory: parent,
      now: Date.now() + 2 * DAY_MS,
    })).toEqual([staleOwned]);
    expect(existsSync(staleOwned)).toBe(false);
    for (const survivor of [otherName, otherPrefix, plainFile, link]) {
      expect(existsSync(survivor)).toBe(true);
    }
    expect(existsSync(path.join(outside, 'target.txt'))).toBe(true);
  });

  describe('killed CLI runs', () => {
    // The real CLI, copied into a fixture repository so its repository root is
    // the fixture. The fixture's build announces itself and then blocks, so
    // every kill lands while the read-only reviewed snapshot exists and a
    // grandchild process is running inside the scratch tree.
    const startBlockedRun = ({
      nodeArgs = [],
      tmp = realpathSync(tempDir('tmpdir')),
    }: { nodeArgs?: string[]; tmp?: string } = {}): {
      child: ReturnType<typeof spawn>;
      tmp: string;
      marker: string;
      output: () => string;
    } => {
      const fixture = tempDir('fixture');
      const marker = path.join(tempDir('marker'), 'build.json');
      writeFileSync(path.join(fixture, 'package.json'), `${JSON.stringify({
        name: 'scratch-cleanup-fixture',
        version: '1.0.0',
        files: ['index.js'],
        scripts: { build: 'node build.cjs' },
      }, null, 2)}\n`);
      writeFileSync(path.join(fixture, 'index.js'), 'export const value = 1;\n');
      writeFileSync(path.join(fixture, 'build.cjs'), [
        "const fs = require('node:fs');",
        `fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ pid: process.pid }));`,
        // Blocks until killed; the timer only bounds a failed test's orphan.
        'setTimeout(() => {}, 60_000);',
        '',
      ].join('\n'));
      execFileSync('git', ['init', '-q'], { cwd: fixture });
      execFileSync('git', ['config', 'user.name', 'Release Fixture'], { cwd: fixture });
      execFileSync('git', ['config', 'user.email', 'release-fixture@example.test'], { cwd: fixture });
      execFileSync('git', ['add', 'package.json', 'index.js', 'build.cjs'], { cwd: fixture });
      execFileSync('git', ['commit', '-q', '-m', 'fixture'], { cwd: fixture });
      const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fixture, encoding: 'utf8' }).trim();
      mkdirSync(path.join(fixture, 'scripts', 'lib'), { recursive: true });
      copyFileSync('scripts/verify-reproducible-package.mjs', path.join(fixture, 'scripts', 'verify-reproducible-package.mjs'));
      copyFileSync('scripts/lib/scratch-directory.mjs', path.join(fixture, 'scripts', 'lib', 'scratch-directory.mjs'));
      symlinkSync(path.resolve('node_modules'), path.join(fixture, 'node_modules'));

      const environment: NodeJS.ProcessEnv = { ...process.env, TMPDIR: tmp, TMP: tmp, TEMP: tmp };
      delete environment.EP_REPRO_PACK_WORKER;
      const child = spawn(process.execPath, [
        ...nodeArgs,
        path.join(fixture, 'scripts', 'verify-reproducible-package.mjs'),
        '.',
        '--commit',
        commit,
      ], {
        cwd: fixture,
        env: environment,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      running.push(child);
      let captured = '';
      child.stdout?.on('data', (chunk) => { captured += chunk; });
      child.stderr?.on('data', (chunk) => { captured += chunk; });
      return { child, tmp, marker, output: () => captured };
    };

    const waitFor = async (condition: () => boolean, what: string, output: () => string): Promise<void> => {
      const deadline = Date.now() + 30_000;
      while (!condition()) {
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}:\n${output()}`);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    };

    const exited = (child: ReturnType<typeof spawn>): Promise<{ code: number | null; signal: NodeJS.Signals | null }> =>
      new Promise((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolve({ code: child.exitCode, signal: child.signalCode });
        } else {
          child.once('exit', (code, signal) => resolve({ code, signal }));
        }
      });

    const isAlive = (pid: number): boolean => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };

    for (const signal of ['SIGTERM', 'SIGINT'] as const) {
      it.skipIf(onWindows)(`removes the read-only scratch tree and its process tree on ${signal}`, async () => {
        const run = startBlockedRun();
        await waitFor(() => existsSync(run.marker), 'the fixture build to start', run.output);
        const { pid: buildPid } = JSON.parse(readFileSync(run.marker, 'utf8'));

        // Mid-run state: supervisor root > worker scratch > read-only snapshot.
        const [supervisorRoot] = scratchEntries(run.tmp);
        const [workerScratch] = scratchEntries(path.join(run.tmp, supervisorRoot));
        const snapshot = path.join(run.tmp, supervisorRoot, workerScratch, 'reviewed-source');
        expect(statSync(snapshot).mode & 0o222).toBe(0);
        expect(statSync(path.join(snapshot, 'package.json')).mode & 0o222).toBe(0);
        expect(isAlive(buildPid)).toBe(true);

        run.child.kill(signal);
        const result = await exited(run.child);

        expect(result.signal, run.output()).toBe(signal);
        expect(scratchEntries(run.tmp)).toEqual([]);
        await waitFor(() => !isAlive(buildPid), 'the fixture build to die', run.output);
      }, FIXTURE_TIMEOUT_MS);
    }

    it.skipIf(onWindows)('removes scratch state when the worker fails and reports its exit status', async () => {
      const run = startBlockedRun();
      await waitFor(() => existsSync(run.marker), 'the fixture build to start', run.output);
      const { pid: buildPid } = JSON.parse(readFileSync(run.marker, 'utf8'));

      // Killing the build fails the worker through its normal error path.
      process.kill(buildPid, 'SIGKILL');
      const result = await exited(run.child);

      expect(result).toEqual({ code: 1, signal: null });
      expect(run.output()).toContain('reproducibility check failed');
      expect(scratchEntries(run.tmp)).toEqual([]);
    }, FIXTURE_TIMEOUT_MS);

    it.skipIf(onWindows)('removes scratch state and stops the build when the worker itself is SIGKILLed', async () => {
      const run = startBlockedRun();
      await waitFor(() => existsSync(run.marker), 'the fixture build to start', run.output);
      const { pid: buildPid } = JSON.parse(readFileSync(run.marker, 'utf8'));
      // The worker is the supervisor's only child; the build runs below it.
      const workers = execFileSync('ps', ['-A', '-o', 'pid=', '-o', 'ppid='], { encoding: 'utf8' })
        .trim().split('\n')
        .map((line) => line.trim().split(/\s+/u).map(Number))
        .filter(([, ppid]) => ppid === run.child.pid)
        .map(([pid]) => pid);
      expect(workers).toHaveLength(1);

      // Nothing can catch SIGKILL in the worker, and its spawnSync grandchildren
      // outlive it unless the supervisor stops the whole group.
      process.kill(workers[0], 'SIGKILL');
      const result = await exited(run.child);

      expect(result, run.output()).toEqual({ code: 128 + os.constants.signals.SIGKILL, signal: null });
      expect(scratchEntries(run.tmp)).toEqual([]);
      await waitFor(() => !isAlive(buildPid), 'the fixture build to die', run.output);
    }, FIXTURE_TIMEOUT_MS);

    it.skipIf(onWindows)('sweeps a tree stranded by an earlier killed run when the CLI starts', async () => {
      const tmp = realpathSync(tempDir('tmpdir'));
      // What a SIGKILLed supervisor leaves behind: a root holding read-only source.
      const stranded = path.join(tmp, `${PREFIX}Kd9Xq2`);
      mkdirSync(stranded);
      buildReadOnlyTree(stranded, tempDir('stranded-outside'));
      chmodSync(stranded, 0o555);
      // utimes cannot age ctime, which the sweep also checks, so the CLI runs
      // with its clock two days ahead instead. The worker inherits execArgv.
      const clockAhead = path.join(tempDir('clock'), 'clock-ahead.mjs');
      writeFileSync(clockAhead, [
        'const realNow = Date.now;',
        `Date.now = () => realNow() + ${2 * DAY_MS};`,
        '',
      ].join('\n'));

      const run = startBlockedRun({ nodeArgs: ['--import', pathToFileURL(clockAhead).href], tmp });
      await waitFor(() => existsSync(run.marker), 'the fixture build to start', run.output);

      // Swept before the run created its own root, which is still in use.
      expect(existsSync(stranded)).toBe(false);
      expect(run.output()).toContain(`removed 1 stale ${PREFIX}* scratch directory`);
      expect(scratchEntries(run.tmp)).toHaveLength(1);

      run.child.kill('SIGTERM');
      expect((await exited(run.child)).signal, run.output()).toBe('SIGTERM');
      expect(scratchEntries(run.tmp)).toEqual([]);
    }, FIXTURE_TIMEOUT_MS);
  });
});
