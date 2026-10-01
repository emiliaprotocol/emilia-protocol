// SPDX-License-Identifier: Apache-2.0
// Kill tests for the two CLIs that tests/release-scratch-cleanup.test.ts does
// not reach: the security case, which calls verifyReproduciblePackage in
// process, and the Python wheel verifier. Both now run their work as a
// supervised worker (scripts/lib/scratch-directory) whose TMPDIR is a private
// root removed on every exit path.
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
  writeFileSync,
} from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { removeScratchTree } from '../scripts/lib/scratch-directory.mjs';

const ROOT = path.resolve(import.meta.dirname, '..');
const FIXTURE_TIMEOUT_MS = 60_000;
const onWindows = process.platform === 'win32';
const MKDTEMP_NAME = (prefix: string): RegExp => new RegExp(`^${prefix}[A-Za-z0-9]{6}$`, 'u');

const created: string[] = [];
const running: ReturnType<typeof spawn>[] = [];
const tempDir = (label: string): string => {
  const directory = mkdtempSync(path.join(os.tmpdir(), `ep-supervised-test-${label}-`));
  created.push(directory);
  return directory;
};

afterEach(async () => {
  // A failed assertion must not strand a supervised run.
  await Promise.all(running.splice(0).map((child) => new Promise<void>((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
  })));
  for (const directory of created.splice(0)) removeScratchTree(directory);
});

// A POSIX shell executable standing in for a real tool on PATH or in PYTHON.
// The Node scripts it hands off to record what they saw; a blocking one waits
// until killed, and its timer only bounds a failed test's orphan.
const writeTool = (file: string, body: string): void => {
  writeFileSync(file, `#!/bin/sh\n${body}\n`);
  chmodSync(file, 0o755);
};

const launch = (command: string[], cwd: string, env: NodeJS.ProcessEnv): {
  child: ReturnType<typeof spawn>;
  output: () => string;
} => {
  const child = spawn(process.execPath, command, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  running.push(child);
  let captured = '';
  child.stdout?.on('data', (chunk) => { captured += chunk; });
  child.stderr?.on('data', (chunk) => { captured += chunk; });
  return { child, output: () => captured };
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

const isolatedEnvironment = (tmp: string, extra: NodeJS.ProcessEnv): NodeJS.ProcessEnv => {
  const environment: NodeJS.ProcessEnv = { ...process.env, TMPDIR: tmp, TMP: tmp, TEMP: tmp, ...extra };
  // The security case runs evidence tests inside its own worker; this test
  // must still start a supervisor of its own.
  delete environment.EP_SECURITY_CASE_WORKER;
  delete environment.EP_WHEEL_REPRO_WORKER;
  delete environment.EP_REPRO_PACK_WORKER;
  return environment;
};

describe('security case scratch supervision', () => {
  // The real security case over the real claims, without --execute, so the
  // first subprocess it starts is the Git lookup at the top of
  // verifyReproduciblePackage for the first npm release artifact. A `git` shim
  // on PATH blocks exactly that call, after planting a read-only tree in the
  // package scratch directory in place of the reviewed snapshot the real run
  // would extract there; every other Git call passes through.
  const startBlockedCase = (): {
    child: ReturnType<typeof spawn>;
    tmp: string;
    marker: string;
    output: () => string;
  } => {
    const tmp = realpathSync(tempDir('tmpdir'));
    const bin = tempDir('bin');
    const marker = path.join(tempDir('marker'), 'git.json');
    const realGit = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
    const blocker = path.join(bin, 'block.cjs');
    writeFileSync(blocker, [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'const tmp = process.env.TMPDIR;',
      "const [scratch] = fs.readdirSync(tmp).filter((name) => name.startsWith('ep-repro-pack-'));",
      "const snapshot = path.join(tmp, scratch, 'reviewed-source');",
      "fs.mkdirSync(path.join(snapshot, 'nested'), { recursive: true });",
      "fs.writeFileSync(path.join(snapshot, 'nested', 'file.txt'), 'reviewed\\n');",
      "fs.chmodSync(path.join(snapshot, 'nested', 'file.txt'), 0o444);",
      "fs.chmodSync(path.join(snapshot, 'nested'), 0o555);",
      'fs.chmodSync(snapshot, 0o555);',
      `fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ pid: process.pid, tmp, scratch }));`,
      'setTimeout(() => {}, 60_000);',
      '',
    ].join('\n'));
    writeTool(path.join(bin, 'git'), [
      'if [ "$1" = rev-parse ] && [ "$2" = --show-object-format ]; then',
      `  exec ${JSON.stringify(process.execPath)} ${JSON.stringify(blocker)}`,
      'fi',
      `exec ${JSON.stringify(realGit)} "$@"`,
    ].join('\n'));

    const run = launch(
      ['--import', path.join(ROOT, 'scripts', 'ts-loader', 'register.mjs'), path.join(ROOT, 'scripts', 'verify-security-case.mjs')],
      ROOT,
      isolatedEnvironment(tmp, { PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` }),
    );
    return { ...run, tmp, marker };
  };

  it.skipIf(onWindows)('removes the private root, the package scratch tree and its process tree on SIGTERM', async () => {
    const run = startBlockedCase();
    await waitFor(() => existsSync(run.marker), 'the package verification to start', run.output);
    const blocked = JSON.parse(readFileSync(run.marker, 'utf8'));

    // Mid-run state: supervisor root > package scratch > read-only snapshot,
    // and the grandchild saw the private root as its TMPDIR.
    const entries = readdirSync(run.tmp);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatch(MKDTEMP_NAME('ep-security-case-'));
    const root = path.join(run.tmp, entries[0]);
    expect(blocked.tmp).toBe(root);
    expect(readdirSync(root)).toEqual([blocked.scratch]);
    expect(blocked.scratch).toMatch(MKDTEMP_NAME('ep-repro-pack-'));
    expect(statSync(path.join(root, blocked.scratch, 'reviewed-source')).mode & 0o222).toBe(0);
    expect(isAlive(blocked.pid)).toBe(true);

    run.child.kill('SIGTERM');
    const result = await exited(run.child);

    expect(result.signal).toBe('SIGTERM');
    expect(readdirSync(run.tmp)).toEqual([]);
    await waitFor(() => !isAlive(blocked.pid), 'the blocked Git call to die', run.output);
  }, FIXTURE_TIMEOUT_MS);

  it.skipIf(onWindows)('removes scratch state when the worker fails and reports its exit status', async () => {
    const run = startBlockedCase();
    await waitFor(() => existsSync(run.marker), 'the package verification to start', run.output);
    const blocked = JSON.parse(readFileSync(run.marker, 'utf8'));

    // Killing the Git call fails the worker through verifyReproduciblePackage.
    process.kill(blocked.pid, 'SIGKILL');
    const result = await exited(run.child);

    expect(result).toEqual({ code: 1, signal: null });
    expect(run.output()).toContain('git object-format lookup failed');
    expect(readdirSync(run.tmp)).toEqual([]);
  }, FIXTURE_TIMEOUT_MS);
});

describe('Python wheel scratch supervision', () => {
  // The real CLI copied into a fixture repository with one package directory.
  // PYTHON points at a stand-in build that logs each invocation, then either
  // writes a fixed wheel and sdist (so the CLI can pass) or blocks until killed.
  const startWheelRun = (mode: 'block' | 'succeed'): {
    child: ReturnType<typeof spawn>;
    tmp: string;
    log: string;
    builds: () => Array<{ pid: number; tmp: string; outdir: string }>;
    output: () => string;
  } => {
    const fixture = tempDir('wheel-fixture');
    const tmp = realpathSync(tempDir('tmpdir'));
    const log = path.join(tempDir('marker'), 'builds.jsonl');
    mkdirSync(path.join(fixture, 'scripts', 'lib'), { recursive: true });
    for (const relative of [
      'scripts/verify-reproducible-wheel.mjs',
      'scripts/python-artifact-integrity.mjs',
      'scripts/lib/scratch-directory.mjs',
    ]) {
      copyFileSync(path.join(ROOT, relative), path.join(fixture, relative));
    }
    mkdirSync(path.join(fixture, 'pkg'));
    writeFileSync(path.join(fixture, 'pkg', 'pyproject.toml'), '[project]\nname = "fixture"\nversion = "1.0"\n');
    const builder = path.join(fixture, 'build.cjs');
    writeFileSync(builder, [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const outdir = process.argv[process.argv.indexOf('--outdir') + 1];",
      `fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ pid: process.pid, tmp: process.env.TMPDIR, outdir }) + '\\n');`,
      mode === 'succeed'
        ? [
          "fs.writeFileSync(path.join(outdir, 'fixture-1.0-py3-none-any.whl'), 'wheel\\n');",
          "fs.writeFileSync(path.join(outdir, 'fixture-1.0.tar.gz'), 'sdist\\n');",
        ].join('\n')
        : 'setTimeout(() => {}, 60_000);',
      '',
    ].join('\n'));
    const python = path.join(fixture, 'python');
    writeTool(python, `exec ${JSON.stringify(process.execPath)} ${JSON.stringify(builder)} "$@"`);

    const run = launch(
      [path.join(fixture, 'scripts', 'verify-reproducible-wheel.mjs'), 'pkg'],
      fixture,
      isolatedEnvironment(tmp, { PYTHON: python, SOURCE_DATE_EPOCH: '1700000000' }),
    );
    const builds = (): Array<{ pid: number; tmp: string; outdir: string }> => (existsSync(log)
      ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
      : []);
    return { ...run, tmp, log, builds };
  };

  const expectBuildInsidePrivateRoot = (tmp: string, build: { tmp: string; outdir: string }): void => {
    const entries = readdirSync(tmp);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatch(MKDTEMP_NAME('ep-wheel-repro-'));
    const root = path.join(tmp, entries[0]);
    expect(build.tmp).toBe(root);
    const [scratch] = readdirSync(root);
    expect(scratch).toMatch(MKDTEMP_NAME('ep-wheel-repro-'));
    expect(build.outdir).toBe(path.join(root, scratch, 'first-0'));
  };

  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    it.skipIf(onWindows)(`removes the scratch directory and its process tree on ${signal}`, async () => {
      const run = startWheelRun('block');
      await waitFor(() => run.builds().length === 1, 'the first build to start', run.output);
      const [build] = run.builds();
      expectBuildInsidePrivateRoot(run.tmp, build);
      expect(isAlive(build.pid)).toBe(true);

      run.child.kill(signal);
      const result = await exited(run.child);

      expect(result.signal).toBe(signal);
      expect(readdirSync(run.tmp)).toEqual([]);
      await waitFor(() => !isAlive(build.pid), 'the build to die', run.output);
    }, FIXTURE_TIMEOUT_MS);
  }

  it.skipIf(onWindows)('removes scratch state when a build fails and reports the exit status', async () => {
    const run = startWheelRun('block');
    await waitFor(() => run.builds().length === 1, 'the first build to start', run.output);
    const [build] = run.builds();

    process.kill(build.pid, 'SIGKILL');
    const result = await exited(run.child);

    expect(result).toEqual({ code: 1, signal: null });
    expect(run.output()).toContain('Command failed');
    expect(readdirSync(run.tmp)).toEqual([]);
  }, FIXTURE_TIMEOUT_MS);

  it.skipIf(onWindows)('runs the builds once, in the worker, and leaves nothing behind on success', async () => {
    const run = startWheelRun('succeed');
    const result = await exited(run.child);

    expect(result).toEqual({ code: 0, signal: null });
    expect(run.output()).toContain('REPRODUCIBLE PYTHON: PASS (1 package(s), 2 artifacts;');
    const builds = run.builds();
    expect(builds.map((build) => path.basename(build.outdir))).toEqual(['first-0', 'second-0']);
    // Both builds saw the same private root, which is gone now.
    expect(new Set(builds.map((build) => build.tmp)).size).toBe(1);
    expect(path.dirname(builds[0].tmp)).toBe(run.tmp);
    expect(readdirSync(run.tmp)).toEqual([]);
  }, FIXTURE_TIMEOUT_MS);
});
