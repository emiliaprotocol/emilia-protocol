// SPDX-License-Identifier: Apache-2.0
import { spawn } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  acquireProofStatsRunLock,
  resolveProofStatsLockQueue,
} from '../scripts/generate-proof-stats.mjs';

const runtimeUrl = pathToFileURL(
  path.resolve('scripts/generate-proof-stats.mjs'),
).href;
const fixtures: string[] = [];
const children = new Set<ReturnType<typeof spawn>>();

function makeWorktreeFixture(): { root: string; peer: string } {
  const parent = mkdtempSync(path.join(os.tmpdir(), 'ep-proof-lock-test-'));
  const root = path.join(parent, 'repository');
  const peer = path.join(parent, 'peer');
  fixtures.push(parent);
  mkdirSync(root);
  writeFileSync(path.join(root, 'README.md'), 'fixture\n');
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['config', 'user.name', 'Proof Lock Test'], { cwd: root });
  execFileSync('git', ['config', 'user.email', 'proof-lock@example.test'], {
    cwd: root,
  });
  execFileSync('git', ['add', 'README.md'], { cwd: root });
  execFileSync('git', ['commit', '-q', '-m', 'fixture'], { cwd: root });
  execFileSync('git', ['worktree', 'add', '-q', '-b', 'peer', peer], {
    cwd: root,
  });
  return { root, peer };
}

function probeSource(
  cwd: string,
  {
    holdMs,
    timeoutMs,
    extraSignalListener = false,
  }: { holdMs: number; timeoutMs: number; extraSignalListener?: boolean },
): string {
  return [
    `import { acquireProofStatsRunLock } from ${JSON.stringify(runtimeUrl)};`,
    ...(extraSignalListener
      ? ['process.on("SIGTERM", () => process.stdout.write("OTHER SIGNAL LISTENER\\n"));']
      : []),
    `const lock = acquireProofStatsRunLock({ cwd: ${JSON.stringify(cwd)}, timeoutMs: ${timeoutMs}, pollMs: 10 });`,
    'process.stdout.write(`ACQUIRED ${Date.now()}\\n`);',
    `setTimeout(() => { lock.release(); process.stdout.write(\`RELEASED \${Date.now()}\\n\`); }, ${holdMs});`,
    '',
  ].join('\n');
}

function startProbe(
  cwd: string,
  options: {
    holdMs: number;
    timeoutMs: number;
    extraSignalListener?: boolean;
  },
): ReturnType<typeof spawn> {
  const child = spawn(
    process.execPath,
    ['--input-type=module', '-e', probeSource(cwd, options)],
    { cwd, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  children.add(child);
  child.once('exit', () => children.delete(child));
  return child;
}

function collect(child: ReturnType<typeof spawn>): Promise<{
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}> {
  let stdout = '';
  let stderr = '';
  child.stdout?.on('data', (chunk) => { stdout += chunk; });
  child.stderr?.on('data', (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (status, signal) => resolve({
      status,
      signal,
      stdout,
      stderr,
    }));
  });
}

function waitForLine(
  child: ReturnType<typeof spawn>,
  prefix: string,
  timeoutMs = 2_000,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error(
      `timed out waiting for ${prefix}; output=${JSON.stringify(output)}`,
    )), timeoutMs);
    child.stdout?.on('data', (chunk) => {
      output += chunk;
      const line = output.split('\n').find((entry) => entry.startsWith(prefix));
      if (line) {
        clearTimeout(timer);
        resolve(line);
      }
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('exit', (status, signal) => {
      if (!output.includes(prefix)) {
        clearTimeout(timer);
        reject(new Error(
          `process exited before ${prefix}: status=${status} signal=${signal}`,
        ));
      }
    });
  });
}

afterEach(() => {
  for (const child of children) child.kill('SIGKILL');
  children.clear();
  for (const fixture of fixtures.splice(0)) {
    rmSync(fixture, { recursive: true, force: true });
  }
});

describe('proof-stats run serialization', () => {
  it('resolves linked worktrees to one repository and host scoped queue', () => {
    const { root, peer } = makeWorktreeFixture();
    expect(resolveProofStatsLockQueue(root)).toBe(resolveProofStatsLockQueue(peer));
    expect(resolveProofStatsLockQueue(root)).toContain('proof-stats-run-v1');
  });

  it('serializes complete runs across linked worktrees', async () => {
    const { root, peer } = makeWorktreeFixture();
    const holder = startProbe(root, { holdMs: 350, timeoutMs: 2_000 });
    const holderDone = collect(holder);
    await waitForLine(holder, 'ACQUIRED ');

    const waiter = startProbe(peer, { holdMs: 0, timeoutMs: 2_000 });
    const [holderResult, waiterResult] = await Promise.all([
      holderDone,
      collect(waiter),
    ]);

    expect(holderResult.status).toBe(0);
    expect(waiterResult.status).toBe(0);
    const releasedAt = Number(holderResult.stdout.match(/RELEASED (\d+)/u)?.[1]);
    const acquiredAt = Number(waiterResult.stdout.match(/ACQUIRED (\d+)/u)?.[1]);
    expect(acquiredAt).toBeGreaterThanOrEqual(releasedAt);
  });

  it('serializes simultaneous first-use initialization', async () => {
    const { root, peer } = makeWorktreeFixture();
    const first = startProbe(root, { holdMs: 100, timeoutMs: 2_000 });
    const second = startProbe(peer, { holdMs: 100, timeoutMs: 2_000 });
    const [firstResult, secondResult] = await Promise.all([
      collect(first),
      collect(second),
    ]);

    expect(firstResult.status).toBe(0);
    expect(secondResult.status).toBe(0);
    const intervals = [firstResult, secondResult].map((result) => ({
      acquired: Number(result.stdout.match(/ACQUIRED (\d+)/u)?.[1]),
      released: Number(result.stdout.match(/RELEASED (\d+)/u)?.[1]),
    }));
    expect(
      intervals[0].released <= intervals[1].acquired ||
      intervals[1].released <= intervals[0].acquired,
    ).toBe(true);
    expect(readdirSync(resolveProofStatsLockQueue(root))).toEqual(['.version']);
  });

  it('times out clearly without stealing a live owner', async () => {
    const { root, peer } = makeWorktreeFixture();
    const holder = startProbe(root, { holdMs: 1_000, timeoutMs: 2_000 });
    await waitForLine(holder, 'ACQUIRED ');

    const waiter = await collect(startProbe(peer, {
      holdMs: 0,
      timeoutMs: 100,
    }));
    expect(waiter.status).toBe(1);
    expect(waiter.stderr).toMatch(/proof-stats run lock timed out after 100ms/u);
    expect(waiter.stderr).toMatch(/live owner/u);
    expect(holder.exitCode).toBeNull();
    const holderDone = collect(holder);
    holder.kill('SIGTERM');
    const holderResult = await holderDone;
    expect(holderResult.status).toBe(143);
    expect(holderResult.signal).toBeNull();
    expect(readdirSync(resolveProofStatsLockQueue(root))).toEqual(['.version']);
  });

  it('terminates after cleanup when another signal listener is present', async () => {
    const { root } = makeWorktreeFixture();
    const holder = startProbe(root, {
      holdMs: 60_000,
      timeoutMs: 2_000,
      extraSignalListener: true,
    });
    await waitForLine(holder, 'ACQUIRED ');

    const holderDone = collect(holder);
    holder.kill('SIGTERM');
    const result = await holderDone;
    expect(result.status).toBe(143);
    expect(result.signal).toBeNull();
    expect(result.stdout).toContain('OTHER SIGNAL LISTENER');
    expect(result.stdout).not.toContain('RELEASED');
    expect(readdirSync(resolveProofStatsLockQueue(root))).toEqual(['.version']);
  });

  it('recovers a dead owner entry but never needs a shared-path eviction', async () => {
    const { root, peer } = makeWorktreeFixture();
    const abandoned = startProbe(root, { holdMs: 60_000, timeoutMs: 2_000 });
    await waitForLine(abandoned, 'ACQUIRED ');
    abandoned.kill('SIGKILL');
    await collect(abandoned);

    const recovery = await collect(startProbe(peer, {
      holdMs: 0,
      timeoutMs: 2_000,
    }));
    expect(recovery.status).toBe(0);
    expect(recovery.stdout).toMatch(/^ACQUIRED \d+\nRELEASED \d+\n$/u);

    const queue = resolveProofStatsLockQueue(root);
    expect(readFileSync(path.join(queue, '.version'), 'utf8')).toBe('1\n');
  });

  it('acquires uncontended before consulting the timeout clock and releases its entry', () => {
    const { root } = makeWorktreeFixture();
    const start = 1_000_000_000n;
    const clock = vi.spyOn(process.hrtime, 'bigint')
      .mockReturnValueOnce(start)
      .mockReturnValue(start + 101_000_000n);
    let lock: ReturnType<typeof acquireProofStatsRunLock>;
    try {
      lock = acquireProofStatsRunLock({ cwd: root, timeoutMs: 100 });
      expect(clock).not.toHaveBeenCalled();
    } finally {
      clock.mockRestore();
    }
    let released = false;
    try {
      expect(lock.queuePath).toBe(resolveProofStatsLockQueue(root));
    } finally {
      released = lock.release();
    }
    expect(released).toBe(true);
    expect(lock.release()).toBe(false);
  });
});
