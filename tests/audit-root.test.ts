// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const temporaryDirectories: string[] = [];

// Each stub invocation answers with the next entry, and every invocation past
// the end repeats the last one, so a single-entry sequence behaves like a stub
// that always returns the same payload.
function runWithAuditSequence(responses: Array<{ report: unknown; exitCode: number }>) {
  const directory = mkdtempSync(join(tmpdir(), 'emilia-audit-root-'));
  temporaryDirectories.push(directory);
  const npm = join(directory, 'npm');
  const counter = join(directory, 'invocations');
  const branches = responses
    .map(({ report, exitCode }, index) => {
      const guard = index === responses.length - 1 ? '*' : String(index + 1);
      return `  ${guard}) printf '%s\\n' '${JSON.stringify(report)}'; exit ${exitCode} ;;`;
    })
    .join('\n');
  writeFileSync(
    npm,
    [
      '#!/bin/sh',
      `attempt=$(cat '${counter}' 2>/dev/null || echo 0)`,
      'attempt=$((attempt+1))',
      `printf '%s' "$attempt" > '${counter}'`,
      'case "$attempt" in',
      branches,
      'esac',
      '',
    ].join('\n'),
    'utf8',
  );
  chmodSync(npm, 0o700);
  return spawnSync(process.execPath, ['scripts/audit-root.mjs'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${directory}${delimiter}${process.env.PATH ?? ''}`,
      EP_AUDIT_RETRY_DELAY_MS: '0',
    },
  });
}

function runWithAuditReport(report: unknown, exitCode: number) {
  return runWithAuditSequence([{ report, exitCode }]);
}

const CLEAN_REPORT = {
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
};

// The exact payload npm emits when the advisory endpoint is unreachable: the
// fetch error at the top level, and an exit-handler envelope with no advisory
// data. Reproduced from npm 10.8.2 and npm 11.17.0.
const ENDPOINT_FAILURE = {
  message: 'request to https://registry.npmjs.org/-/npm/v1/security/advisories/bulk failed, reason: socket hang up',
  error: { summary: '', detail: '' },
};

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
    const result = runWithAuditReport(CLEAN_REPORT, 0);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no advisories observed');
  });

  it('retries a transient advisory-endpoint failure and audits the report it finally gets', () => {
    const result = runWithAuditSequence([
      { report: ENDPOINT_FAILURE, exitCode: 1 },
      { report: CLEAN_REPORT, exitCode: 0 },
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no advisories observed');
    expect(result.stderr).toContain('advisory endpoint unreachable (attempt 1/3)');
  });

  it('fails closed when the advisory endpoint never answers, and does not call it a pass', () => {
    const result = runWithAuditSequence([{ report: ENDPOINT_FAILURE, exitCode: 1 }]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('could not reach the advisory endpoint after 3 attempts');
    expect(result.stderr).toContain('so no advisory data was obtained');
    expect(result.stdout).not.toContain('AUDIT: PASS');
  });

  it('reports an unreachable endpoint as a transport failure, not as an advisory finding', () => {
    const result = runWithAuditSequence([{ report: ENDPOINT_FAILURE, exitCode: 1 }]);
    // The old script threw "npm audit returned an error report" here, which
    // read as though npm had found something.
    expect(result.stderr).not.toContain('npm audit returned an error report');
    expect(result.stderr).toContain('socket hang up');
  });

  it('still fails closed on an npm error envelope that carries no advisory data', () => {
    const result = runWithAuditReport({ error: { code: 'EAUDITNOLOCK', summary: 'x', detail: 'y' } }, 1);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('npm audit returned an error report');
  });
});
