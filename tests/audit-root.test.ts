// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
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

// GHSA-vfj7-8cjw-p6xm (braces <=3.0.3) is accepted only for the pinned,
// dev-only lint copy. These cases run the real script against a fixture
// project root so every pin can be moved independently and shown to fail.
const BRACES_ADVISORY_URL = 'https://github.com/advisories/GHSA-vfj7-8cjw-p6xm';
const BRACES_INTEGRITY = 'sha512-yQbXgO/OSZVD2IsiLlro+7Hf6Q18EJrKSEsdoMzKePKXct3gvD8oLcOQdIzGupr5Fj+EDe8gO/lxc1BzfMpxvA==';
const AUDIT_SCRIPT = join(process.cwd(), 'scripts', 'audit-root.mjs');
const REAL_BRACES = join(process.cwd(), 'node_modules', 'braces');

type Vulnerabilities = Record<string, { via: unknown[]; nodes: string[] }>;

function bracesVulnerabilities(): Vulnerabilities {
  return {
    braces: {
      via: [{
        name: 'braces',
        dependency: 'braces',
        title: 'braces vulnerable to stack-exhaustion denial of service through deeply nested patterns',
        url: BRACES_ADVISORY_URL,
        severity: 'high',
        range: '<=3.0.3',
      }],
      nodes: ['node_modules/braces'],
    },
    micromatch: { via: ['braces'], nodes: ['node_modules/micromatch'] },
    'fast-glob': { via: ['micromatch'], nodes: ['node_modules/fast-glob'] },
    '@next/eslint-plugin-next': { via: ['fast-glob'], nodes: ['node_modules/@next/eslint-plugin-next'] },
    'eslint-config-next': { via: ['@next/eslint-plugin-next'], nodes: ['node_modules/eslint-config-next'] },
  };
}

function reportFor(vulnerabilities: Vulnerabilities) {
  const high = Object.keys(vulnerabilities).length;
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high, critical: 0, total: high } },
  };
}

type QueryNode = { name: string; version: string; location: string; dev: boolean };

const PINNED_QUERY: QueryNode[] = [
  { name: 'braces', version: '3.0.3', location: 'node_modules/braces', dev: true },
];

function pinnedLock(): Record<string, Record<string, unknown>> {
  return {
    '': { name: 'fixture' },
    'node_modules/braces': {
      version: '3.0.3',
      resolved: 'https://registry.npmjs.org/braces/-/braces-3.0.3.tgz',
      integrity: BRACES_INTEGRITY,
      dev: true,
    },
  };
}

type FakeBraces = { version?: string; source: string };

function runBracesFixture(options: {
  vulnerabilities?: Vulnerabilities;
  query?: QueryNode[];
  lockPackages?: Record<string, Record<string, unknown>>;
  fakeBraces?: FakeBraces;
  now?: string;
} = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'emilia-audit-braces-')));
  temporaryDirectories.push(root);
  const bin = join(root, '.bin-stub');
  mkdirSync(bin);
  mkdirSync(join(root, 'node_modules'));
  if (options.fakeBraces) {
    const directory = join(root, 'node_modules', 'braces');
    mkdirSync(directory);
    writeFileSync(join(directory, 'package.json'), JSON.stringify({
      name: 'braces',
      version: options.fakeBraces.version ?? '3.0.3',
      main: 'index.js',
    }));
    writeFileSync(join(directory, 'index.js'), options.fakeBraces.source);
  } else {
    symlinkSync(REAL_BRACES, join(root, 'node_modules', 'braces'), 'dir');
  }
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({
    name: 'fixture',
    lockfileVersion: 3,
    packages: options.lockPackages ?? pinnedLock(),
  }));
  const report = reportFor(options.vulnerabilities ?? bracesVulnerabilities());
  writeFileSync(join(bin, 'audit.json'), JSON.stringify(report));
  writeFileSync(join(bin, 'query.json'), JSON.stringify(options.query ?? PINNED_QUERY));
  const npm = join(bin, 'npm');
  writeFileSync(npm, [
    '#!/bin/sh',
    'case "$1" in',
    `  audit) cat '${join(bin, 'audit.json')}'; exit 1 ;;`,
    `  query) cat '${join(bin, 'query.json')}'; exit 0 ;;`,
    '  *) echo "unexpected npm invocation: $*" >&2; exit 97 ;;',
    'esac',
    '',
  ].join('\n'), 'utf8');
  chmodSync(npm, 0o700);

  const nodeArgs: string[] = [];
  if (options.now) {
    const clock = join(bin, 'clock.mjs');
    writeFileSync(clock, `const fixed = Date.parse(${JSON.stringify(options.now)}); Date.now = () => fixed;\n`);
    nodeArgs.push('--import', pathToFileURL(clock).href);
  }
  // A sync spawn cannot be interrupted by the vitest test timeout, so bound it
  // here: if the script ever lost its own probe bound, the case fails instead
  // of hanging the run.
  return spawnSync(process.execPath, [...nodeArgs, AUDIT_SCRIPT], {
    cwd: root,
    encoding: 'utf8',
    timeout: 20000,
    killSignal: 'SIGKILL',
    env: {
      ...process.env,
      PATH: `${bin}${delimiter}${process.env.PATH ?? ''}`,
      EP_AUDIT_RETRY_DELAY_MS: '0',
    },
  });
}

describe('braces GHSA-vfj7-8cjw-p6xm reviewed exception', () => {
  it('accepts the advisory for the single pinned dev-only copy that passes the probe', () => {
    const result = runBracesFixture();
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('braces finding constrained to the pinned dev-only lint copy until 2026-12-01');
  });

  it('rejects a second installed braces copy', () => {
    const result = runBracesFixture({
      query: [
        ...PINNED_QUERY,
        { name: 'braces', version: '3.0.3', location: 'node_modules/chokidar/node_modules/braces', dev: true },
      ],
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('unreviewed braces copies under advisory');
    expect(result.stdout).not.toContain('AUDIT: PASS');
  });

  it('rejects the copy when it moves to a different location', () => {
    const result = runBracesFixture({
      query: [{ name: 'braces', version: '3.0.3', location: 'node_modules/micromatch/node_modules/braces', dev: true }],
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('unreviewed braces copies under advisory');
  });

  it('rejects a different braces version at the pinned location', () => {
    const result = runBracesFixture({
      query: [{ name: 'braces', version: '3.0.2', location: 'node_modules/braces', dev: true }],
      fakeBraces: { version: '3.0.2', source: "module.exports = () => [];\n" },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('unreviewed braces version at node_modules/braces: 3.0.2');
  });

  it('rejects a lockfile integrity that differs from the reviewed tarball', () => {
    const lockPackages = pinnedLock();
    lockPackages['node_modules/braces'].integrity = 'sha512-AAAA';
    const result = runBracesFixture({ lockPackages });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('does not match the reviewed version and integrity');
  });

  it('rejects the copy once a production dependency pulls it in', () => {
    const lockPackages = pinnedLock();
    delete lockPackages['node_modules/braces'].dev;
    const lockResult = runBracesFixture({ lockPackages });
    expect(lockResult.status).not.toBe(0);
    expect(lockResult.stderr).toContain('is no longer dev-only');

    const queryResult = runBracesFixture({ query: [{ ...PINNED_QUERY[0], dev: false }] });
    expect(queryResult.status).not.toBe(0);
    expect(queryResult.stderr).toContain('is no longer dev-only');
  });

  it('rejects a lockfile that lists another braces copy', () => {
    const lockPackages = pinnedLock();
    lockPackages['node_modules/chokidar/node_modules/braces'] = {
      version: '3.0.3',
      integrity: BRACES_INTEGRITY,
      dev: true,
    };
    const result = runBracesFixture({ lockPackages });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('package-lock.json lists unreviewed braces copies');
  });

  it('rejects a new package reached through the advisory', () => {
    const vulnerabilities = bracesVulnerabilities();
    vulnerabilities.chokidar = { via: ['micromatch'], nodes: ['node_modules/chokidar'] };
    const result = runBracesFixture({ vulnerabilities });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('braces advisory reaches an unreviewed package set');
  });

  it('rejects a new install location for an already reviewed consumer', () => {
    const vulnerabilities = bracesVulnerabilities();
    vulnerabilities['fast-glob'].nodes.push('node_modules/globby/node_modules/fast-glob');
    const result = runBracesFixture({ vulnerabilities });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('braces advisory reaches an unreviewed package set');
  });

  it('rejects a reviewed consumer that disappears from the report', () => {
    const vulnerabilities = bracesVulnerabilities();
    delete vulnerabilities['eslint-config-next'];
    const result = runBracesFixture({ vulnerabilities });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('braces advisory reaches an unreviewed package set');
  });

  it('still rejects any other advisory reported next to it', () => {
    const vulnerabilities = bracesVulnerabilities();
    vulnerabilities.other = {
      via: [{ name: 'other', url: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx', severity: 'high', range: '*' }],
      nodes: ['node_modules/other'],
    };
    const result = runBracesFixture({ vulnerabilities });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('GHSA-xxxx-xxxx-xxxx');
  });

  it('stops accepting the advisory on its recheck date', () => {
    const result = runBracesFixture({ now: '2026-12-01T00:00:00Z' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('reached its recheck date (2026-12-01)');
    expect(result.stdout).not.toContain('AUDIT: PASS');
  });

  it('fails the probe when nested input raises anything other than a stack-exhaustion RangeError', () => {
    const result = runBracesFixture({
      fakeBraces: {
        source: [
          'module.exports = (pattern) => {',
          "  if (pattern.length > 10000) throw new SyntaxError('Input length exceeds max characters');",
          "  throw new TypeError('unexpected failure');",
          '};',
          '',
        ].join('\n'),
      },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('failed the resource-bounded nesting probe');
  });

  it('fails the probe when the input length cap is gone', () => {
    const result = runBracesFixture({ fakeBraces: { source: 'module.exports = () => [];\n' } });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('failed the resource-bounded nesting probe');
  });

  it('fails the probe, inside its time bound, when nested input never returns', () => {
    const started = Date.now();
    const result = runBracesFixture({ fakeBraces: { source: 'module.exports = () => { for (;;) {} };\n' } });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('failed the resource-bounded nesting probe');
    expect(Date.now() - started).toBeLessThan(15000);
  }, 30000);
});
