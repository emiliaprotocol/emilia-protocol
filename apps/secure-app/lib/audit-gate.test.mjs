/**
 * Audit-exception gate regression tests.
 *
 *   node --test apps/secure-app/lib/audit-gate.test.mjs
 *
 * The synthetic cases run against fixture reports and fixture exception files
 * written to a temporary directory. The real audit and the committed exception
 * file are never mutated to produce a failure.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AuditGateError,
  FAILURE,
  collectLiveAdvisories,
  evaluate,
  loadExceptions,
  parseExceptions,
} from '../../../scripts/audit-with-exceptions.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SECURE_APP = resolve(HERE, '..');
const REPO_ROOT = resolve(HERE, '../../..');
const GATE = join(REPO_ROOT, 'scripts/audit-with-exceptions.mjs');

const ICNS = 'https://github.com/advisories/GHSA-w3rx-r6r6-pgpr';
const OTHER = 'https://github.com/advisories/GHSA-0000-0000-0000';

const NOW = Date.parse('2026-09-01T00:00:00Z');

const REACHABILITY =
  'Build-machine only. The package is declared by the bundler alone and no application source file imports it, '
  + 'so the parser has no reachable input on a device.';
const TRIGGER = 'Remove this entry when the bundler chain drops the vulnerable package or a fixed version ships.';
const HOW_CHECKED = 'Queried the registry for every published version; the advisory range covers all of them.';
const WHY_REJECTED = 'The suggested remediation is a three-major downgrade of the framework, which is not a fix.';

/** Build an npm-audit-shaped report whose metadata reconciles. */
function auditReport(vulnerabilities) {
  const summary = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  for (const entry of Object.values(vulnerabilities)) {
    summary[entry.severity] += 1;
    summary.total += 1;
  }
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: summary } };
}

function advisoryCause({ url = ICNS, source = 1138808, severity = 'high', name = 'image-size' } = {}) {
  return {
    source,
    name,
    dependency: name,
    title: `${name}: denial of service through an infinite loop`,
    url,
    severity,
    cwe: ['CWE-835'],
    range: '<=2.0.2',
  };
}

/**
 * A bundler chain shaped like the real one, including the metro/metro-config
 * cycle, so the transitive walk is exercised rather than a straight line.
 */
function bundlerChainReport({ url = ICNS, severity = 'high', extraDependent = null } = {}) {
  const vulnerabilities = {
    'image-size': { name: 'image-size', severity, via: [advisoryCause({ url, severity })], effects: ['metro'] },
    metro: { name: 'metro', severity, via: ['image-size', 'metro-config'], effects: ['metro-config'] },
    'metro-config': { name: 'metro-config', severity, via: ['metro'], effects: ['metro'] },
  };
  if (extraDependent !== null) {
    vulnerabilities[extraDependent] = { name: extraDependent, severity, via: ['metro'], effects: [] };
  }
  return auditReport(vulnerabilities);
}

function exceptionEntry(overrides = {}) {
  return {
    advisory: ICNS,
    package: 'image-size',
    severity: 'high',
    affected_packages: ['image-size', 'metro', 'metro-config'],
    reachability: REACHABILITY,
    no_upstream_fix: {
      checked_on: '2026-08-07',
      advisory_range: '<=2.0.2',
      latest_published_version: '2.0.2',
      npm_suggested_fix: 'expo@53.0.27 (isSemVerMajor: true)',
      how_checked: HOW_CHECKED,
      why_suggested_fix_rejected: WHY_REJECTED,
    },
    accepted_by: 'EMILIA Protocol maintainers',
    accepted_on: '2026-08-07',
    expires_on: '2026-11-05',
    revisit_trigger: TRIGGER,
    ...overrides,
  };
}

function exceptionDocument(entries, overrides = {}) {
  return JSON.stringify({ version: 1, exceptions: entries, ...overrides });
}

/** Write a fixture exception file and return its path; cleaned up by the caller hook. */
function fixtureFile(t, contents) {
  const directory = mkdtempSync(join(tmpdir(), 'ep-audit-gate-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'audit-exceptions.json');
  writeFileSync(path, contents, 'utf8');
  return path;
}

function reasons(failures) {
  return failures.map((failure) => failure.reason).sort();
}

test('the transitive walk resolves the full blast radius through a dependency cycle', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport(), 'low');
  assert.equal(advisories.size, 1);
  const advisory = advisories.get(ICNS);
  assert.deepEqual([...advisory.affectedPackages].sort(), ['image-size', 'metro', 'metro-config']);
  assert.equal(advisory.severity, 'high');
  assert.deepEqual([...advisory.ids], [1138808]);
});

test('a live advisory with no exception fails as uncovered', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport(), 'low');
  const { failures, accepted } = evaluate({ advisories, exceptions: [], now: NOW });

  assert.deepEqual(reasons(failures), [FAILURE.UNCOVERED_ADVISORY]);
  assert.equal(accepted.length, 0);
  assert.match(failures[0].message, /not covered by any exception/);
  assert.match(failures[0].message, /image-size, metro, metro-config/);
});

test('a covered advisory passes and reports the days remaining', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport(), 'low');
  const exceptions = parseExceptions(exceptionDocument([exceptionEntry()]));
  const { failures, accepted } = evaluate({ advisories, exceptions, now: NOW });

  assert.deepEqual(failures, []);
  assert.equal(accepted.length, 1);
  assert.equal(accepted[0].advisory, ICNS);
  assert.equal(accepted[0].expiresOn, '2026-11-05');
  // 2026-09-01 to 2026-11-05 is 65 days.
  assert.equal(accepted[0].daysRemaining, 65);
  assert.equal(accepted[0].affectedPackageCount, 3);
});

test('an exception past its expires_on fails loudly and is not accepted', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport(), 'low');
  const exceptions = parseExceptions(exceptionDocument([exceptionEntry({ expires_on: '2026-08-20' })]));
  const { failures, accepted } = evaluate({ advisories, exceptions, now: NOW });

  assert.deepEqual(reasons(failures), [FAILURE.EXPIRED_EXCEPTION]);
  assert.equal(accepted.length, 0);
  assert.match(failures[0].message, /expired on 2026-08-20 \(12 day\(s\) ago\)/);
  assert.match(failures[0].message, /Revisit trigger/);
});

test('an exception expires at the start of its expires_on day, not the end', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport(), 'low');
  const exceptions = parseExceptions(exceptionDocument([exceptionEntry({ expires_on: '2026-09-01' })]));

  const onTheDay = evaluate({ advisories, exceptions, now: Date.parse('2026-09-01T00:00:00Z') });
  assert.deepEqual(reasons(onTheDay.failures), [FAILURE.EXPIRED_EXCEPTION]);

  const theDayBefore = evaluate({ advisories, exceptions, now: Date.parse('2026-08-31T23:59:59Z') });
  assert.deepEqual(theDayBefore.failures, []);
  assert.equal(theDayBefore.accepted.length, 1);
});

test('an exception matching nothing live fails as stale so the file self-cleans', () => {
  const advisories = collectLiveAdvisories(auditReport({}), 'low');
  const exceptions = parseExceptions(exceptionDocument([exceptionEntry()]));
  const { failures, accepted } = evaluate({ advisories, exceptions, now: NOW });

  assert.deepEqual(reasons(failures), [FAILURE.STALE_EXCEPTION]);
  assert.equal(accepted.length, 0);
  assert.match(failures[0].message, /no longer appears in npm audit/);
});

test('a stale exception is reported even while another exception is still live', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport(), 'low');
  const exceptions = parseExceptions(
    exceptionDocument([exceptionEntry(), exceptionEntry({ advisory: OTHER })]),
  );
  const { failures, accepted } = evaluate({ advisories, exceptions, now: NOW });

  assert.deepEqual(reasons(failures), [FAILURE.STALE_EXCEPTION]);
  assert.equal(failures[0].advisory, OTHER);
  assert.equal(accepted.length, 1);
});

test('an advisory reaching a package outside the reviewed set fails', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport({ extraDependent: 'some-runtime-package' }), 'low');
  const exceptions = parseExceptions(exceptionDocument([exceptionEntry()]));
  const { failures, accepted } = evaluate({ advisories, exceptions, now: NOW });

  assert.deepEqual(reasons(failures), [FAILURE.UNREVIEWED_AFFECTED_PACKAGE]);
  assert.equal(accepted.length, 0);
  assert.match(failures[0].message, /some-runtime-package/);
});

test('an advisory whose severity escalates past the accepted level fails', () => {
  const advisories = collectLiveAdvisories(bundlerChainReport({ severity: 'critical' }), 'low');
  const exceptions = parseExceptions(exceptionDocument([exceptionEntry({ severity: 'high' })]));
  const { failures, accepted } = evaluate({ advisories, exceptions, now: NOW });

  assert.deepEqual(reasons(failures), [FAILURE.SEVERITY_ESCALATED]);
  assert.equal(accepted.length, 0);
  assert.match(failures[0].message, /accepted at high but is now critical/);
});

test('a malformed exception file is rejected with a named reason', (t) => {
  const cases = [
    ['not valid JSON', '{ not json'],
    ['top level must be an object', '[]'],
    ['unsupported schema version', JSON.stringify({ version: 2, exceptions: [] })],
    ['exceptions must be an array', JSON.stringify({ version: 1, exceptions: {} })],
    ['advisory must be a GitHub advisory URL', exceptionDocument([exceptionEntry({ advisory: 'CVE-2026-1' })])],
    ['duplicate exception', exceptionDocument([exceptionEntry(), exceptionEntry()])],
    ['severity must be one of', exceptionDocument([exceptionEntry({ severity: 'spicy' })])],
    ['affected_packages must be a non-empty array', exceptionDocument([exceptionEntry({ affected_packages: [] })])],
    ['reachability is required', exceptionDocument([exceptionEntry({ reachability: undefined })])],
    ['reachability must be a real justification', exceptionDocument([exceptionEntry({ reachability: 'n/a' })])],
    ['revisit_trigger must be a real justification', exceptionDocument([exceptionEntry({ revisit_trigger: 'later' })])],
    ['accepted_by is required', exceptionDocument([exceptionEntry({ accepted_by: '' })])],
    ['no_upstream_fix must be an object', exceptionDocument([exceptionEntry({ no_upstream_fix: 'none' })])],
    ['expires_on must be a YYYY-MM-DD date', exceptionDocument([exceptionEntry({ expires_on: '11/05/2026' })])],
    ['expires_on is not a real calendar date', exceptionDocument([exceptionEntry({ expires_on: '2026-11-31' })])],
    ['must be after accepted_on', exceptionDocument([exceptionEntry({ expires_on: '2026-08-06' })])],
  ];

  for (const [expected, contents] of cases) {
    assert.throws(
      () => parseExceptions(contents, 'fixture'),
      (error) => {
        assert.ok(error instanceof AuditGateError, `${expected}: expected an AuditGateError`);
        assert.equal(error.reason, FAILURE.MALFORMED_EXCEPTIONS_FILE, `${expected}: wrong reason`);
        assert.match(error.message, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
        return true;
      },
      `expected a malformed-file failure for: ${expected}`,
    );
  }

  // A required no_upstream_fix subfield is checked one level down.
  const missingEvidence = exceptionEntry();
  delete missingEvidence.no_upstream_fix.how_checked;
  assert.throws(
    () => parseExceptions(exceptionDocument([missingEvidence]), 'fixture'),
    (error) => error.reason === FAILURE.MALFORMED_EXCEPTIONS_FILE && /how_checked is required/.test(error.message),
  );
});

test('a far-future expiry is rejected so the forcing function cannot be defeated', () => {
  assert.throws(
    () => parseExceptions(exceptionDocument([exceptionEntry({ expires_on: '2099-01-01' })]), 'fixture'),
    (error) => {
      assert.ok(error instanceof AuditGateError);
      assert.equal(error.reason, FAILURE.EXPIRY_WINDOW_TOO_LONG);
      assert.match(error.message, /exceeds the 180-day maximum/);
      return true;
    },
  );
});

test('a missing exception file is a named failure rather than a silent pass', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'ep-audit-gate-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  assert.throws(
    () => loadExceptions(join(directory, 'audit-exceptions.json')),
    (error) => {
      assert.ok(error instanceof AuditGateError);
      assert.equal(error.reason, FAILURE.MALFORMED_EXCEPTIONS_FILE);
      assert.match(error.message, /could not be read/);
      return true;
    },
  );
});

test('a malformed exception file on disk fails through the file-loading path', (t) => {
  const path = fixtureFile(t, '{"version": 1, "exceptions": [{"advisory": "nope"}]}');
  assert.throws(
    () => loadExceptions(path),
    (error) => error.reason === FAILURE.MALFORMED_EXCEPTIONS_FILE,
  );
});

test('an unusable npm audit report fails rather than reporting nothing live', () => {
  const cases = [
    null,
    [],
    { error: { code: 'ENETUNREACH' } },
    { auditReportVersion: 1, vulnerabilities: {}, metadata: { vulnerabilities: {} } },
    { auditReportVersion: 2, metadata: { vulnerabilities: {} } },
    { auditReportVersion: 2, vulnerabilities: {} },
    {
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 0 } },
    },
  ];
  for (const report of cases) {
    assert.throws(
      () => collectLiveAdvisories(report, 'low'),
      (error) => {
        assert.ok(error instanceof AuditGateError, `expected an AuditGateError for ${JSON.stringify(report)}`);
        assert.equal(error.reason, FAILURE.AUDIT_REPORT_INVALID);
        return true;
      },
      `expected an invalid-report failure for ${JSON.stringify(report)}`,
    );
  }
});

test('an unsupported severity floor is a usage failure, not a clean report', () => {
  assert.throws(
    () => collectLiveAdvisories(bundlerChainReport(), 'spicy'),
    (error) => {
      assert.ok(error instanceof AuditGateError);
      assert.equal(error.reason, FAILURE.INVALID_USAGE);
      return true;
    },
  );
});

test('the committed exception file satisfies the enforced schema', () => {
  const exceptions = loadExceptions(join(SECURE_APP, 'audit-exceptions.json'));
  assert.ok(exceptions.length > 0, 'the committed file should describe the accepted advisories');
  for (const exception of exceptions) {
    assert.ok(exception.expiresOn > exception.acceptedOn);
    assert.ok(exception.affectedPackages.size > 0);
  }
});

test('the gate passes against the real dependency tree', () => {
  const stdout = execFileSync('node', [GATE, '--prefix', SECURE_APP, '--audit-level=low'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  assert.match(stdout, /AUDIT GATE PASS/);
  assert.match(stdout, /day\(s\) remaining/);
});
