// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';

const source = readFileSync(new URL('../scripts/verify-security-case.mts', import.meta.url), 'utf8');

// Execute the actual observer functions with a fake process boundary. Never run
// the verifier's top-level claim execution, npm installs or release packing.
function observer({ status = 0, signal = null, report, rawOutput = '', reportBytes }: {
  status?: number | null; signal?: string | null; report?: unknown; rawOutput?: string; reportBytes?: number;
} = {}) {
  const spawnSync = vi.fn((_command: string, _args: string[], _options: { timeout: number }) => ({
    status, signal, stdout: rawOutput, stderr: rawOutput,
  }));
  let removed = false;
  const fs = {
    mkdtempSync: vi.fn(() => '/tmp/security-case-fixture'),
    existsSync: vi.fn(() => report !== undefined),
    statSync: vi.fn(() => ({ size: reportBytes ?? JSON.stringify(report)?.length ?? 0 })),
    readFileSync: vi.fn(() => {
      if (removed) throw new Error('Report was removed before it was read');
      return typeof report === 'string' ? report : JSON.stringify(report);
    }),
    rmSync: vi.fn(() => { removed = true; }),
  };
  const timeoutConstant = source.match(/const EXECUTION_TIMEOUT_MS[^;]+;/u)?.[0];
  const functions = source.slice(source.indexOf('function runChecked('), source.indexOf('function observeNodeTestFile('));
  const executable = ts.transpileModule(`${timeoutConstant}\n${functions}\nglobalThis.observe = observeVitestFile;`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
  }).outputText;
  const context = { spawnSync, fs, path, os: { tmpdir: () => '/tmp' }, process: { env: {} }, ROOT: '/repo', nonEmpty: (value: unknown) => typeof value === 'string' && value.trim().length > 0 };
  vm.runInNewContext(executable, context);
  return { run: (context as unknown as { observe: (file: string) => Map<string, string> }).observe, spawnSync, fs };
}

describe('security-case Vitest subprocess contract', () => {
  it('gives release reproducibility enough outer time for its 660-second test plus fixtures', () => {
    const runner = observer({ report: { testResults: [] } });
    runner.run('tests/release-reproducibility.test.ts');
    const [, args, options] = runner.spawnSync.mock.calls[0];
    expect(options.timeout).toBe(900_000);
    expect(args).toEqual(expect.arrayContaining(['--testTimeout', '60000', '--hookTimeout', '60000']));
    expect(args).not.toEqual(expect.arrayContaining(['--testNamePattern', '--exclude', '--passWithNoTests']));
    expect(runner.fs.rmSync).toHaveBeenCalledOnce();
  });

  it('retains the 600-second outer deadline and existing defaults for every other file', () => {
    for (const file of ['tests/other.test.ts', 'tests/release-reproducibility.test.ts.extra', 'other/release-reproducibility.test.ts']) {
      const runner = observer({ report: { testResults: [] } });
      runner.run(file);
      const [, args, options] = runner.spawnSync.mock.calls[0];
      expect(options.timeout).toBe(600_000);
      expect(args).not.toContain('--testTimeout');
      expect(args).not.toContain('--hookTimeout');
    }
  });

  it('retains the runner-reported exact test outcomes on a successful file', () => {
    const runner = observer({ report: { testResults: [{ assertionResults: [
      { title: 'exact evidence', fullName: 'suite exact evidence', status: 'passed' },
      { title: 'not executed', fullName: 'suite not executed', status: 'skipped' },
    ] }] } });
    const outcomes = runner.run('tests/other.test.ts');
    expect(outcomes.get('exact evidence')).toBe('passed');
    expect(outcomes.get('suite exact evidence')).toBe('passed');
    expect(outcomes.get('not executed')).toBe('skipped');
  });

  it('reads bounded failure reasons before cleanup without exposing assertion or process payloads', () => {
    const runner = observer({ status: 1, rawOutput: 'private child stdout token=DO_NOT_PRINT', report: { testResults: [{ assertionResults: [
      { title: 'inert lifecycle hooks', status: 'failed', duration: 5542.52, failureMessages: ['Error: STACK_TRACE_ERROR private-customer-payload'] },
      { title: 'locked installation', status: 'failed', duration: 900, failureMessages: ['locked dependency installation failed Authorization: Bearer private-token'] },
      { title: 'byte correspondence', status: 'failed', duration: 20, failureMessages: ['AssertionError: expected private-receipt to equal secret-reference'] },
    ] }] } });
    let message = '';
    try { runner.run('tests/release-reproducibility.test.ts'); } catch (error) { message = (error as Error).message; }
    expect(message).toContain('inert lifecycle hooks');
    expect(message).toContain('5543 ms');
    expect(message).toContain('TIMEOUT');
    expect(message).toContain('LOCKED_DEPENDENCY_INSTALL_FAILED');
    expect(message).toContain('ASSERTION_FAILED');
    expect(message).not.toMatch(/private-|DO_NOT_PRINT|Bearer|secret-reference/);
    expect(runner.fs.readFileSync).toHaveBeenCalled();
    expect(runner.fs.rmSync).toHaveBeenCalledOnce();
  });

  it('still fails closed if killed before producing JSON', () => {
    const runner = observer({ status: 143, signal: 'SIGTERM', rawOutput: 'private stdout' });
    expect(() => runner.run('tests/release-reproducibility.test.ts')).toThrow(/143[\s\S]*SIGTERM[\s\S]*900000/);
    expect(() => runner.run('tests/release-reproducibility.test.ts')).toThrow(/no machine-readable failure report/i);
    expect(runner.fs.readFileSync).not.toHaveBeenCalled();
  });

  it('bounds report reads and handles malformed reports without dumping their content', () => {
    const oversized = observer({ status: 1, report: { private: 'secret' }, reportBytes: 9 * 1024 * 1024 });
    expect(() => oversized.run('tests/other.test.ts')).toThrow(/too large/i);
    expect(oversized.fs.readFileSync).not.toHaveBeenCalled();
    const malformed = observer({ status: 1, report: '{private malformed payload' });
    expect(() => malformed.run('tests/other.test.ts')).toThrow(/unreadable/i);
    expect(malformed.fs.rmSync).toHaveBeenCalledOnce();
    const successWithBadReport = observer({ report: '{private malformed payload' });
    expect(() => successWithBadReport.run('tests/other.test.ts')).toThrow('report is unreadable; raw contents suppressed');
  });

  it('limits failure summaries and strips control characters from test titles', () => {
    const runner = observer({ status: 1, report: { testResults: [{ assertionResults: Array.from({ length: 30 }, (_, index) => ({
      title: `case-${index}\n\u202e${'x'.repeat(1000)}`,
      status: 'failed', duration: Infinity, failureMessages: ['private arbitrary payload'],
    })) }] } });
    let message = '';
    try { runner.run('tests/other.test.ts'); } catch (error) { message = (error as Error).message; }
    expect(message).toContain('first 20');
    expect(message).toContain('further failures omitted');
    expect(message).not.toContain('case-20');
    expect(message).not.toContain('\u202e');
    expect(message).not.toContain('private arbitrary payload');
    expect(message).toContain('duration unknown');
    expect(message.length).toBeLessThan(7000);
  });
});
