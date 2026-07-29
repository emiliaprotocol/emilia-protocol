// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const temporaryDirectories: string[] = [];

function runWithAuditReport(report: unknown, exitCode: number) {
  const directory = mkdtempSync(join(tmpdir(), 'emilia-audit-root-'));
  temporaryDirectories.push(directory);
  const npm = join(directory, 'npm');
  writeFileSync(
    npm,
    `#!/bin/sh\nprintf '%s\\n' '${JSON.stringify(report)}'\nexit ${exitCode}\n`,
    'utf8',
  );
  chmodSync(npm, 0o700);
  return spawnSync(process.execPath, ['scripts/audit-root.mjs'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, PATH: `${directory}${delimiter}${process.env.PATH ?? ''}` },
  });
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe('root audit report validation', () => {
  it('fails closed when npm returns a JSON error response', () => {
    const result = runWithAuditReport({ error: { code: 'EAI_AGAIN' } }, 1);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('npm audit returned an error report');
  });

  it('fails closed when npm omits the vulnerability map', () => {
    const result = runWithAuditReport({
      auditReportVersion: 2,
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
    }, 1);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('omitted the vulnerabilities map');
  });

  it('accepts a complete zero-vulnerability npm report', () => {
    const result = runWithAuditReport({
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
    }, 0);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no advisories observed');
  });
});
