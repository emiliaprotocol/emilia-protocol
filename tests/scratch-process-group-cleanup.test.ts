// SPDX-License-Identifier: Apache-2.0
import { afterEach, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import {
  removeScratchTree, superviseScratchRoot, waitForProcessGroupQuiescence,
  type ProcessGroupQuiescenceOptions,
} from '../scripts/lib/scratch-directory.mjs';

const childProcess = vi.hoisted(() => ({ spawn: vi.fn(), spawnSync: vi.fn() }));
vi.mock('node:child_process', () => childProcess);

const created: string[] = [];
const originalExitCode = process.exitCode;
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  process.exitCode = originalExitCode;
  childProcess.spawn.mockReset();
  childProcess.spawnSync.mockReset();
  for (const root of created.splice(0)) removeScratchTree(root);
});

it.skipIf(process.platform === 'win32')('waits for a live descendant to become a zombie before unlinking its scratch root', async () => {
  const worker = Object.assign(new EventEmitter(), { pid: 43210, exitCode: 0, signalCode: null });
  childProcess.spawn.mockReturnValue(worker);
  // Intercept only this supervisor's listeners; do not leave global signal or
  // exit hooks around after the test, and never signal an actual process group.
  const on = vi.spyOn(process, 'on').mockReturnValue(process);
  const events: string[] = [];
  vi.spyOn(process, 'kill').mockImplementation((_pid, signal) => {
    events.push(String(signal));
    return true;
  });
  const realMkdtemp = fs.mkdtempSync;
  vi.spyOn(fs, 'mkdtempSync').mockImplementation((prefix, options) => {
    const root = realMkdtemp(prefix, options as { encoding: 'utf8' });
    created.push(String(root));
    return root;
  });
  const realRemove = fs.rmSync;
  vi.spyOn(fs, 'rmSync').mockImplementation((root, options) => {
    events.push('unlink');
    realRemove(root, options);
  });

  let state = 'R';
  let clock = 0;
  const options = {
    probe: (group: number) => {
      expect(group).toBe(worker.pid);
      events.push(`probe:${state}`);
      return [{ pid: 43211, state }];
    },
    now: () => clock,
    pause: (milliseconds: number) => {
      events.push('wait');
      clock += milliseconds;
      state = 'Z';
    },
  };
  // A controlled process-state seam, not a timing race: the descendant is live
  // until the cleanup loop observes it and waits. SIGKILL delivery alone must
  // not authorize unlink. A zombie can no longer write and must not hang it.
  const result = superviseScratchRoot('ep-group-quiescence-test-', 'EP_GROUP_QUIESCENCE_TEST_WORKER', options);
  on.mockRestore();
  worker.emit('exit', 0, null);
  await result;

  expect(events).toEqual(['SIGKILL', 'probe:R', 'wait', 'probe:Z', 'unlink']);
  expect(fs.existsSync(created[0])).toBe(false);
});

const psResult = (stdout: string) => ({ stdout, stderr: '', status: 0, signal: null });

it.skipIf(process.platform === 'win32')('observes exact PGID, ignores only dead run states, and bounds ps itself', () => {
  childProcess.spawnSync.mockReturnValue(psResult('1 1 Ss\n43211 43210 Z+\n43212 43210 X\n54321 432100 R\n'));
  const pause = vi.fn();
  waitForProcessGroupQuiescence(43210, { pause });
  expect(pause).not.toHaveBeenCalled();
  expect(childProcess.spawnSync).toHaveBeenCalledWith('/bin/ps', ['-A', '-o', 'pid=', '-o', 'pgid=', '-o', 'stat='],
    expect.objectContaining({ timeout: 1000, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024 }));
});

for (const state of ['R', 'D', 'T', 't', 'SX', 'x', '?E']) {
  it.skipIf(process.platform === 'win32')(`does not treat a ${state} member as quiescent even if SIGKILL was sent`, () => {
    childProcess.spawnSync.mockReturnValue(psResult(`1 1 Ss\n43211 43210 ${state}\n`));
    let clock = 0;
    expect(() => waitForProcessGroupQuiescence(43210, {
      timeoutMs: 50, now: () => clock, pause: (milliseconds) => { clock += milliseconds; },
    })).toThrow(`live members: 43211:${state}`);
    expect(clock).toBe(50);
    for (const [, , options] of childProcess.spawnSync.mock.calls) expect(options.timeout).toBeLessThanOrEqual(50);
  });
}

for (const [name, result] of [
  ['empty table', psResult('')],
  ['malformed table', psResult('not a process table')],
  ['malformed state', psResult('43211 43210 ZOMBIE')],
  ['unsafe identifier', psResult('9007199254740992 43210 R')],
  ['nonzero status', { ...psResult('1 1 Ss'), status: 1, stderr: 'unavailable' }],
  ['timeout', { ...psResult('1 1 Ss'), status: null, signal: 'SIGTERM', error: new Error('spawnSync ETIMEDOUT') }],
] as const) {
  it.skipIf(process.platform === 'win32')(`refuses ${name} as proof of group absence`, () => {
    childProcess.spawnSync.mockReturnValue(result);
    expect(() => waitForProcessGroupQuiescence(43210)).toThrow('could not observe process group 43210');
  });
}

it.skipIf(process.platform === 'win32')('rejects an empty observation returned after its monotonic deadline', () => {
  let clock = 0;
  expect(() => waitForProcessGroupQuiescence(43210, {
    timeoutMs: 50, now: () => clock,
    probe: () => { clock = 51; return []; },
  })).toThrow('did not become quiescent within 50 ms');
});

const fakeSupervisor = (options: ProcessGroupQuiescenceOptions = {}, pid: number | null = 43210) => {
  const worker = Object.assign(new EventEmitter(), { pid: pid ?? undefined, exitCode: 0, signalCode: null });
  childProcess.spawn.mockReturnValue(worker);
  const on = vi.spyOn(process, 'on').mockReturnValue(process);
  const kill = vi.spyOn(process, 'kill').mockReturnValue(true);
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  const realMkdtemp = fs.mkdtempSync;
  vi.spyOn(fs, 'mkdtempSync').mockImplementation((prefix, encoding) => {
    const root = realMkdtemp(prefix, encoding as { encoding: 'utf8' });
    created.push(String(root));
    return root;
  });
  const result = superviseScratchRoot('ep-group-failure-test-', 'EP_GROUP_FAILURE_TEST_WORKER', options);
  const exitHook = on.mock.calls.find(([event]) => event === 'exit')?.[1] as () => void;
  const signalHook = on.mock.calls.find(([event]) => event === 'SIGINT')?.[1] as (signal: NodeJS.Signals) => void;
  on.mockRestore();
  return { worker, result, kill, error, exitHook, signalHook, root: created.at(-1)! };
};

it.skipIf(process.platform === 'win32')('retains the root and reports failure instead of re-raising a signal when group state is unknown', async () => {
  vi.useFakeTimers();
  const run = fakeSupervisor({ probe: () => { throw new Error('ps unavailable'); } });
  run.signalHook('SIGINT');
  run.worker.emit('exit', null, 'SIGINT');
  await run.result;
  expect(process.exitCode).toBe(1);
  expect(fs.existsSync(run.root)).toBe(true);
  expect(run.kill).not.toHaveBeenCalledWith(process.pid, 'SIGINT');
  expect(run.error).toHaveBeenCalledWith(expect.stringContaining(`scratch root ${run.root}; retained for a later sweep: ps unavailable`));
});

it.skipIf(process.platform === 'win32')('retains the root on bounded live-group timeout', async () => {
  let clock = 0;
  const run = fakeSupervisor({
    timeoutMs: 50, now: () => clock, pause: (milliseconds) => { clock += milliseconds; },
    probe: () => [{ pid: 43211, state: 'D' }],
  });
  run.worker.emit('exit', 0, null);
  await run.result;
  expect(process.exitCode).toBe(1);
  expect(fs.existsSync(run.root)).toBe(true);
  expect(run.error).toHaveBeenCalledWith(expect.stringContaining('live members: 43211:D'));
});

it('cleans a failed spawn with no PID without signaling or probing an invalid group', async () => {
  const probe = vi.fn();
  const run = fakeSupervisor({ probe }, null);
  run.worker.emit('error', new Error('spawn failed'));
  await run.result;
  expect(process.exitCode).toBe(1);
  expect(run.kill).not.toHaveBeenCalled();
  expect(probe).not.toHaveBeenCalled();
  expect(fs.existsSync(run.root)).toBe(false);
});

it('does not mark a root removed when unlink fails, so the exit hook can retry', async () => {
  const run = fakeSupervisor({ probe: () => [] });
  vi.spyOn(fs, 'rmSync').mockImplementationOnce(() => { throw new Error('unlink failed'); });
  run.worker.emit('exit', 0, null);
  await run.result;
  expect(process.exitCode).toBe(1);
  expect(fs.existsSync(run.root)).toBe(true);
  run.exitHook();
  expect(fs.existsSync(run.root)).toBe(false);
  expect(run.error).toHaveBeenCalledWith(expect.stringContaining('unlink failed'));
});

it.skipIf(process.platform === 'win32')('escalates repeated signals and re-raises the original signal only after quiescence and unlink', async () => {
  vi.useFakeTimers();
  const run = fakeSupervisor({ probe: () => [{ pid: 43211, state: 'Z' }] });
  run.signalHook('SIGINT');
  run.signalHook('SIGTERM');
  expect(run.kill.mock.calls).toEqual([[-43210, 'SIGINT'], [-43210, 'SIGKILL']]);
  run.worker.emit('exit', null, 'SIGINT');
  expect(fs.existsSync(run.root)).toBe(false);
  expect(run.kill).toHaveBeenLastCalledWith(process.pid, 'SIGINT');
  // The real re-raised signal terminates the supervisor; this mocked one does
  // not, so its deliberately unsettled promise is not awaited.
});
