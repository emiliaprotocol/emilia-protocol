// SPDX-License-Identifier: Apache-2.0
//
// Expiring audit-exception gate.
//
// This gate keeps the detection floor where it is and requires every accepted
// advisory to be named in an exception file with a written reachability
// justification, evidence about the direct package and any parent-graph
// remediation, and an expiry date. It fails when an advisory is not covered,
// when an exception has expired, when an exception no longer matches anything
// live, or when the file is malformed.
//
// The expiry is the point. An exception is a decision with a date on it, and
// the build goes red when that date passes.
//
// Usage:
//   node scripts/audit-with-exceptions.mjs --prefix apps/secure-app --audit-level=low
//
// `--audit-level` is this gate's own detection floor. It is deliberately not
// forwarded to npm: `npm audit --json` reports every severity regardless, and
// the floor is applied here so the filtering is visible in one place.

import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { isAbsolute, join, resolve } from 'node:path';

const DAY_MS = 86_400_000;

// Longest window a single acceptance may run before it must be re-decided.
// Without this cap the forcing function is defeated by a far-future date.
const MAX_EXCEPTION_DAYS = 180;

// Accepted advisories inside this window still pass, but say so loudly.
const RENEWAL_WARNING_DAYS = 21;

const MIN_REACHABILITY_LENGTH = 80;
const MIN_JUSTIFICATION_LENGTH = 40;

const SEVERITY_RANK = new Map([
  ['info', 0],
  ['low', 1],
  ['moderate', 2],
  ['high', 3],
  ['critical', 4],
]);

export const FAILURE = {
  UNCOVERED_ADVISORY: 'uncovered_advisory',
  EXPIRED_EXCEPTION: 'expired_exception',
  STALE_EXCEPTION: 'stale_exception',
  MALFORMED_EXCEPTIONS_FILE: 'malformed_exceptions_file',
  EXPIRY_WINDOW_TOO_LONG: 'expiry_window_too_long',
  UNREVIEWED_AFFECTED_PACKAGE: 'unreviewed_affected_package',
  SEVERITY_ESCALATED: 'severity_escalated',
  AUDIT_REPORT_INVALID: 'audit_report_invalid',
  INVALID_USAGE: 'invalid_usage',
};

export class AuditGateError extends Error {
  constructor(reason, message) {
    super(message);
    this.name = 'AuditGateError';
    this.reason = reason;
  }
}

const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

function calendarDate(value, field, where) {
  if (typeof value !== 'string' || !DATE_PATTERN.test(value)) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${where}: ${field} must be a YYYY-MM-DD date, got ${JSON.stringify(value)}`,
    );
  }
  const ms = Date.parse(`${value}T00:00:00Z`);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 10) !== value) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${where}: ${field} is not a real calendar date: ${value}`,
    );
  }
  return ms;
}

function requireText(container, field, minimumLength, where) {
  const value = container[field];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${where}: ${field} is required and must be a non-empty string`,
    );
  }
  if (value.trim().length < minimumLength) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${where}: ${field} must be a real justification of at least ${minimumLength} characters, got ${value.trim().length}`,
    );
  }
  return value;
}

/**
 * Validate the exception document and normalise it into a list of entries.
 * Throws AuditGateError with a named reason on any schema problem.
 */
export function parseExceptions(raw, where = 'audit-exceptions.json') {
  let document;
  try {
    document = JSON.parse(raw);
  } catch (error) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${where}: not valid JSON: ${error.message}`,
    );
  }
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${where}: top level must be an object`);
  }
  if (document.version !== 1) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${where}: unsupported schema version ${JSON.stringify(document.version)}, expected 1`,
    );
  }
  if (!Array.isArray(document.exceptions)) {
    throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${where}: exceptions must be an array`);
  }

  const entries = [];
  const seen = new Set();
  document.exceptions.forEach((entry, index) => {
    const at = `${where}[${index}]`;
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${at}: each exception must be an object`);
    }

    const advisory = entry.advisory;
    if (typeof advisory !== 'string' || !/^https:\/\/github\.com\/advisories\/GHSA-/.test(advisory)) {
      throw new AuditGateError(
        FAILURE.MALFORMED_EXCEPTIONS_FILE,
        `${at}: advisory must be a GitHub advisory URL, got ${JSON.stringify(advisory)}`,
      );
    }
    if (seen.has(advisory)) {
      throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${at}: duplicate exception for ${advisory}`);
    }
    seen.add(advisory);

    if (typeof entry.package !== 'string' || entry.package.trim().length === 0) {
      throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${at}: package is required`);
    }
    if (!SEVERITY_RANK.has(entry.severity)) {
      throw new AuditGateError(
        FAILURE.MALFORMED_EXCEPTIONS_FILE,
        `${at}: severity must be one of ${[...SEVERITY_RANK.keys()].join(', ')}, got ${JSON.stringify(entry.severity)}`,
      );
    }
    if (
      !Array.isArray(entry.affected_packages)
      || entry.affected_packages.length === 0
      || entry.affected_packages.some((name) => typeof name !== 'string' || name.trim().length === 0)
    ) {
      throw new AuditGateError(
        FAILURE.MALFORMED_EXCEPTIONS_FILE,
        `${at}: affected_packages must be a non-empty array of package names`,
      );
    }

    requireText(entry, 'reachability', MIN_REACHABILITY_LENGTH, at);
    requireText(entry, 'revisit_trigger', MIN_JUSTIFICATION_LENGTH, at);
    if (typeof entry.accepted_by !== 'string' || entry.accepted_by.trim().length === 0) {
      throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${at}: accepted_by is required`);
    }

    const fix = entry.no_upstream_fix;
    if (fix === null || typeof fix !== 'object' || Array.isArray(fix)) {
      throw new AuditGateError(
        FAILURE.MALFORMED_EXCEPTIONS_FILE,
        `${at}: no_upstream_fix must be an object stating what was checked`,
      );
    }
    calendarDate(fix.checked_on, 'no_upstream_fix.checked_on', at);
    for (const field of ['advisory_range', 'latest_published_version', 'npm_suggested_fix']) {
      if (typeof fix[field] !== 'string' || fix[field].trim().length === 0) {
        throw new AuditGateError(FAILURE.MALFORMED_EXCEPTIONS_FILE, `${at}: no_upstream_fix.${field} is required`);
      }
    }
    requireText(fix, 'how_checked', MIN_JUSTIFICATION_LENGTH, `${at}.no_upstream_fix`);
    requireText(fix, 'why_suggested_fix_rejected', MIN_JUSTIFICATION_LENGTH, `${at}.no_upstream_fix`);

    const acceptedOn = calendarDate(entry.accepted_on, 'accepted_on', at);
    const expiresOn = calendarDate(entry.expires_on, 'expires_on', at);
    if (expiresOn <= acceptedOn) {
      throw new AuditGateError(
        FAILURE.MALFORMED_EXCEPTIONS_FILE,
        `${at}: expires_on (${entry.expires_on}) must be after accepted_on (${entry.accepted_on})`,
      );
    }
    const windowDays = Math.round((expiresOn - acceptedOn) / DAY_MS);
    if (windowDays > MAX_EXCEPTION_DAYS) {
      throw new AuditGateError(
        FAILURE.EXPIRY_WINDOW_TOO_LONG,
        `${at}: acceptance window is ${windowDays} days, which exceeds the ${MAX_EXCEPTION_DAYS}-day maximum`,
      );
    }

    entries.push({
      advisory,
      package: entry.package,
      severity: entry.severity,
      affectedPackages: new Set(entry.affected_packages),
      acceptedOn,
      expiresOn,
      acceptedOnText: entry.accepted_on,
      expiresOnText: entry.expires_on,
      reachability: entry.reachability,
      revisitTrigger: entry.revisit_trigger,
      acceptedBy: entry.accepted_by,
    });
  });

  return entries;
}

export function loadExceptions(filePath) {
  let raw;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (error) {
    throw new AuditGateError(
      FAILURE.MALFORMED_EXCEPTIONS_FILE,
      `${filePath}: exception file could not be read: ${error.message}`,
    );
  }
  return parseExceptions(raw, filePath);
}

function assertUsableReport(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new AuditGateError(FAILURE.AUDIT_REPORT_INVALID, 'npm audit did not return an object report');
  }
  if ('error' in report) {
    throw new AuditGateError(
      FAILURE.AUDIT_REPORT_INVALID,
      `npm audit returned an error report: ${JSON.stringify(report.error)}`,
    );
  }
  if (report.auditReportVersion !== 2) {
    throw new AuditGateError(
      FAILURE.AUDIT_REPORT_INVALID,
      `unsupported npm audit report version: ${String(report.auditReportVersion)}`,
    );
  }
  const vulnerabilities = report.vulnerabilities;
  if (vulnerabilities === null || typeof vulnerabilities !== 'object' || Array.isArray(vulnerabilities)) {
    throw new AuditGateError(FAILURE.AUDIT_REPORT_INVALID, 'npm audit report omitted the vulnerabilities map');
  }
  const summary = report.metadata?.vulnerabilities;
  if (summary === null || typeof summary !== 'object' || Array.isArray(summary)) {
    throw new AuditGateError(FAILURE.AUDIT_REPORT_INVALID, 'npm audit report omitted the vulnerability summary');
  }
  for (const field of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
    if (!Number.isSafeInteger(summary[field]) || summary[field] < 0) {
      throw new AuditGateError(FAILURE.AUDIT_REPORT_INVALID, `npm audit report has an invalid ${field} count`);
    }
  }
  const summed = summary.info + summary.low + summary.moderate + summary.high + summary.critical;
  if (summary.total !== summed) {
    throw new AuditGateError(FAILURE.AUDIT_REPORT_INVALID, 'npm audit report vulnerability counts do not reconcile');
  }
}

/**
 * Reduce an npm audit report to one record per advisory at or above the floor.
 *
 * npm reports 11 "vulnerabilities" for two advisories: one entry carries the
 * advisory objects and the rest name it transitively through `via` strings.
 * The security decision is per advisory, so the blast radius is resolved by
 * walking those `via` edges backwards. The graph contains cycles, so the walk
 * is a visited-set BFS rather than recursion.
 */
export function collectLiveAdvisories(report, minimumSeverity = 'low') {
  assertUsableReport(report);
  const minimumRank = SEVERITY_RANK.get(minimumSeverity);
  if (minimumRank === undefined) {
    throw new AuditGateError(
      FAILURE.INVALID_USAGE,
      `unsupported audit severity threshold: ${minimumSeverity}`,
    );
  }

  const advisories = new Map();
  const seeds = new Map();
  const dependents = new Map();

  for (const [name, vulnerability] of Object.entries(report.vulnerabilities)) {
    if (vulnerability === null || typeof vulnerability !== 'object') continue;
    for (const cause of vulnerability.via ?? []) {
      if (typeof cause === 'string') {
        if (!dependents.has(cause)) dependents.set(cause, new Set());
        dependents.get(cause).add(name);
        continue;
      }
      if (typeof cause !== 'object' || cause === null || typeof cause.url !== 'string') continue;
      if ((SEVERITY_RANK.get(cause.severity) ?? -1) < minimumRank) continue;

      let advisory = advisories.get(cause.url);
      if (advisory === undefined) {
        advisory = {
          url: cause.url,
          package: typeof cause.name === 'string' ? cause.name : name,
          severity: cause.severity,
          title: typeof cause.title === 'string' ? cause.title : '',
          range: typeof cause.range === 'string' ? cause.range : '',
          ids: new Set(),
          affectedPackages: new Set(),
        };
        advisories.set(cause.url, advisory);
      }
      if (Number.isSafeInteger(cause.source)) advisory.ids.add(cause.source);
      if ((SEVERITY_RANK.get(cause.severity) ?? -1) > (SEVERITY_RANK.get(advisory.severity) ?? -1)) {
        advisory.severity = cause.severity;
      }
      if (!seeds.has(cause.url)) seeds.set(cause.url, new Set());
      seeds.get(cause.url).add(name);
    }
  }

  for (const [url, advisory] of advisories) {
    const queue = [...(seeds.get(url) ?? [])];
    const visited = new Set(queue);
    while (queue.length > 0) {
      const name = queue.shift();
      advisory.affectedPackages.add(name);
      for (const dependent of dependents.get(name) ?? []) {
        if (visited.has(dependent)) continue;
        visited.add(dependent);
        queue.push(dependent);
      }
    }
  }

  return advisories;
}

/**
 * Compare live advisories against the accepted exceptions.
 * Returns named failures and the accepted set. Never throws for policy
 * outcomes; callers decide how to render them.
 */
export function evaluate({ advisories, exceptions, now }) {
  const failures = [];
  const accepted = [];
  const byAdvisory = new Map(exceptions.map((entry) => [entry.advisory, entry]));

  for (const [url, advisory] of advisories) {
    const exception = byAdvisory.get(url);
    if (exception === undefined) {
      failures.push({
        reason: FAILURE.UNCOVERED_ADVISORY,
        advisory: url,
        message:
          `${advisory.severity} advisory ${url} (${advisory.package}) is live and not covered by any exception. `
          + `Fix it, or add a dated exception with a reachability justification. `
          + `Affected packages: ${[...advisory.affectedPackages].sort().join(', ')}.`,
      });
      continue;
    }

    const liveRank = SEVERITY_RANK.get(advisory.severity) ?? -1;
    const acceptedRank = SEVERITY_RANK.get(exception.severity) ?? -1;
    if (liveRank > acceptedRank) {
      failures.push({
        reason: FAILURE.SEVERITY_ESCALATED,
        advisory: url,
        message:
          `${url} was accepted at ${exception.severity} but is now ${advisory.severity}. `
          + `The acceptance decision was made against a lower severity and must be re-made.`,
      });
      continue;
    }

    const unreviewed = [...advisory.affectedPackages]
      .filter((name) => !exception.affectedPackages.has(name))
      .sort();
    if (unreviewed.length > 0) {
      failures.push({
        reason: FAILURE.UNREVIEWED_AFFECTED_PACKAGE,
        advisory: url,
        message:
          `${url} now affects packages outside the reviewed set: ${unreviewed.join(', ')}. `
          + `The reachability justification was written against a different blast radius, so re-review it.`,
      });
      continue;
    }

    if (now >= exception.expiresOn) {
      const overdue = Math.max(1, Math.ceil((now - exception.expiresOn) / DAY_MS));
      failures.push({
        reason: FAILURE.EXPIRED_EXCEPTION,
        advisory: url,
        message:
          `${url} expired on ${exception.expiresOnText} (${overdue} day(s) ago). `
          + `Re-verify it and accept a new dated decision, or fix the advisory. `
          + `Revisit trigger: ${exception.revisitTrigger}`,
      });
      continue;
    }

    accepted.push({
      advisory: url,
      package: advisory.package,
      severity: advisory.severity,
      title: advisory.title,
      expiresOn: exception.expiresOnText,
      daysRemaining: Math.ceil((exception.expiresOn - now) / DAY_MS),
      reachability: exception.reachability,
      acceptedBy: exception.acceptedBy,
      affectedPackageCount: advisory.affectedPackages.size,
    });
  }

  for (const exception of exceptions) {
    if (advisories.has(exception.advisory)) continue;
    failures.push({
      reason: FAILURE.STALE_EXCEPTION,
      advisory: exception.advisory,
      message:
        `${exception.advisory} is accepted in the exception file but no longer appears in npm audit. `
        + `Delete the entry so the file only ever describes live, accepted risk.`,
    });
  }

  accepted.sort((a, b) => a.advisory.localeCompare(b.advisory));
  failures.sort((a, b) => a.reason.localeCompare(b.reason) || a.advisory.localeCompare(b.advisory));
  return { failures, accepted };
}

export function runAudit(prefix) {
  let stdout;
  try {
    stdout = execFileSync('npm', ['audit', '--json'], {
      cwd: prefix,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (error) {
    // npm audit exits non-zero whenever findings exist, so stdout is the report.
    stdout = error?.stdout;
    if (typeof stdout !== 'string' || stdout.length === 0) {
      throw new AuditGateError(
        FAILURE.AUDIT_REPORT_INVALID,
        `npm audit produced no report in ${prefix}: ${error?.message ?? 'unknown error'}`,
      );
    }
  }
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new AuditGateError(FAILURE.AUDIT_REPORT_INVALID, `npm audit did not return JSON: ${error.message}`);
  }
}

function parseArgv(argv) {
  const options = { prefix: process.cwd(), auditLevel: 'low', exceptions: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const [flag, inlineValue] = argument.startsWith('--') && argument.includes('=')
      ? [argument.slice(0, argument.indexOf('=')), argument.slice(argument.indexOf('=') + 1)]
      : [argument, null];
    const readValue = () => {
      if (inlineValue !== null) return inlineValue;
      index += 1;
      const next = argv[index];
      if (next === undefined) throw new AuditGateError(FAILURE.INVALID_USAGE, `${flag} requires a value`);
      return next;
    };
    switch (flag) {
      case '--prefix':
        options.prefix = readValue();
        break;
      case '--audit-level':
        options.auditLevel = readValue();
        break;
      case '--exceptions':
        options.exceptions = readValue();
        break;
      default:
        throw new AuditGateError(FAILURE.INVALID_USAGE, `unrecognised argument: ${argument}`);
    }
  }
  return options;
}

export function main(argv = process.argv.slice(2), now = Date.now()) {
  const options = parseArgv(argv);
  const prefix = isAbsolute(options.prefix) ? options.prefix : resolve(process.cwd(), options.prefix);
  const exceptionsPath = options.exceptions === null
    ? join(prefix, 'audit-exceptions.json')
    : resolve(process.cwd(), options.exceptions);

  try {
    if (!statSync(prefix).isDirectory()) {
      throw new AuditGateError(FAILURE.INVALID_USAGE, `--prefix is not a directory: ${prefix}`);
    }
  } catch (error) {
    if (error instanceof AuditGateError) throw error;
    throw new AuditGateError(FAILURE.INVALID_USAGE, `--prefix is not readable: ${prefix}`);
  }

  const exceptions = loadExceptions(exceptionsPath);
  const advisories = collectLiveAdvisories(runAudit(prefix), options.auditLevel);
  const { failures, accepted } = evaluate({ advisories, exceptions, now });

  const scope = options.prefix;
  if (failures.length > 0) {
    console.error(`AUDIT GATE FAILED for ${scope} at ${options.auditLevel}+ (${failures.length} problem(s)):`);
    for (const failure of failures) {
      console.error(`  [${failure.reason}] ${failure.message}`);
    }
    console.error(`\nException file: ${exceptionsPath}`);
    return 1;
  }

  if (accepted.length === 0) {
    console.log(`AUDIT GATE PASS for ${scope} at ${options.auditLevel}+: no advisories observed.`);
    return 0;
  }

  console.log(`AUDIT GATE PASS for ${scope} at ${options.auditLevel}+: ${accepted.length} accepted advisory(ies).`);
  for (const entry of accepted) {
    console.log(`\n  ${entry.advisory}`);
    console.log(`    package        ${entry.package} (${entry.severity})`);
    if (entry.title) console.log(`    title          ${entry.title}`);
    console.log(`    affects        ${entry.affectedPackageCount} package(s) in this tree`);
    console.log(`    accepted by    ${entry.acceptedBy}`);
    console.log(`    expires        ${entry.expiresOn} (${entry.daysRemaining} day(s) remaining)`);
    console.log(`    reason         ${entry.reachability}`);
    if (entry.daysRemaining <= RENEWAL_WARNING_DAYS) {
      console.log(`    WARNING        this exception expires in ${entry.daysRemaining} day(s) and will then fail the build`);
    }
  }
  return 0;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath !== null && invokedPath === resolve(fileURLToPath(import.meta.url))) {
  try {
    process.exitCode = main();
  } catch (error) {
    if (error instanceof AuditGateError) {
      console.error(`AUDIT GATE FAILED: [${error.reason}] ${error.message}`);
    } else {
      console.error(`AUDIT GATE FAILED: [unexpected_error] ${error?.stack ?? error}`);
    }
    process.exitCode = 1;
  }
}
