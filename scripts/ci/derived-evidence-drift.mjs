// SPDX-License-Identifier: Apache-2.0
/**
 * Field-level drift between the checked-in security case and a fresh
 * resolution, and the allowlist of the fields that may lag.
 *
 * scripts/verify-security-case.mts resolves security/security-case.json from
 * security/claims.v1.json. Most of the file restates what the claims say and
 * what the run executed. The rest (SECURITY_CASE_DERIVED_FIELDS) is digests
 * and counts of other files: the evidence bundle hash, the hash of each of
 * the ~264 pinned files, the release tarball hashes and every claim's copy of
 * those hashes. They change whenever any pinned file changes, so requiring
 * each pull request to commit them made every such merge conflict every other
 * open pull request.
 *
 * With --drift-report the writer fails on any difference outside that list
 * and records the rest; scripts/ci/volatile-evidence.mjs then decides by
 * event: advisory on pull_request and merge_group, strict everywhere else.
 * Without --drift-report (main's refresh, every release and publish workflow,
 * a local check) the writer still requires the checked-in file byte for byte.
 *
 * No I/O: the writer and the policy import the same list from here.
 */

import { isDeepStrictEqual } from 'node:util';

export const SECURITY_CASE = 'security/security-case.json';
/** The npm script whose output security/security-case.json is. */
export const SECURITY_CASE_WRITER = 'security-case:emit';
export const DRIFT_REPORT_VERSION = 'EP-VOLATILE-EVIDENCE-DRIFT-v1';

/**
 * Deny by default: the only security-case fields whose drift may be
 * advisory. `[]` stands for any array index and `*` for any one plain object
 * key; nothing else is a wildcard, and a field matches only a whole pattern.
 * `evidence_files` itself appears when the pinned file list grows or shrinks.
 * Everything not listed, including every claim field other than its copied
 * release-artifact hashes, the execution record, the claim count, each
 * artifact's kind and package name, and any key added or removed anywhere,
 * fails in every mode.
 */
export const SECURITY_CASE_DERIVED_FIELDS = Object.freeze([
  'evidence_bundle_sha256',
  'evidence_file_count',
  'evidence_files',
  'evidence_files[].path',
  'evidence_files[].sha256',
  'release_artifacts.*.sha256',
  'release_artifacts.*.file_count',
  'release_artifacts.*.version',
  'release_artifacts.*.filename',
  'claims[].release_artifact_hashes[].sha256',
]);

/** A key rendered as `.key`; any other key is rendered quoted and matches no wildcard. */
const PLAIN_KEY = /^[A-Za-z0-9_@-]+$/;

/**
 * @param {Array<string | number>} segments
 * @returns {string}
 */
export function renderPath(segments) {
  let out = '';
  for (const segment of segments) {
    if (typeof segment === 'number') out += `[${segment}]`;
    else if (PLAIN_KEY.test(segment)) out += out ? `.${segment}` : segment;
    else out += `[${JSON.stringify(segment)}]`;
  }
  return out || '(root)';
}

/**
 * @param {string} pattern
 * @returns {RegExp}
 */
function patternExpression(pattern) {
  const source = pattern
    .split(/(\[\]|\*)/)
    .map((part) => {
      if (part === '[]') return '\\[\\d+\\]';
      if (part === '*') return '[A-Za-z0-9_@-]+';
      return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('');
  return new RegExp(`^${source}$`);
}

/**
 * True when `field` matches one of `patterns` as a whole. A pattern without
 * wildcards matches only itself.
 *
 * @param {string} field
 * @param {readonly string[]} patterns
 * @returns {boolean}
 */
export function fieldAllowed(field, patterns) {
  return patterns.some((pattern) => patternExpression(pattern).test(field));
}

/**
 * Groups drifted fields by the pattern they match, for summaries: a change to
 * one pinned file drifts dozens of claim copies of the same bundle hash.
 *
 * @param {readonly string[]} fields
 * @param {readonly string[]} [patterns]
 * @returns {string[]}
 */
export function summarizeFields(fields, patterns = SECURITY_CASE_DERIVED_FIELDS) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const field of fields) {
    const name = patterns.find((pattern) => patternExpression(pattern).test(field)) ?? field;
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts].map(([name, count]) => (count > 1 ? `${name} (${count})` : name));
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function kind(value) {
  if (value === null) return 'null';
  return Array.isArray(value) ? 'array' : typeof value;
}

/**
 * @typedef {{ segments: Array<string | number>, shape: boolean }} DriftEntry
 */

/**
 * The leaves that differ between a recorded and a computed JSON value.
 * Objects are compared key by key and equal-length arrays index by index; an
 * array whose length changed is one entry. `shape` marks a key present on
 * only one side or a value whose JSON type changed: those are never advisory.
 *
 * @param {unknown} recorded
 * @param {unknown} computed
 * @param {Array<string | number>} [segments]
 * @param {DriftEntry[]} [out]
 * @returns {DriftEntry[]}
 */
export function driftEntries(recorded, computed, segments = [], out = []) {
  const type = kind(recorded);
  if (type !== kind(computed)) {
    out.push({ segments, shape: true });
    return out;
  }
  if (type === 'object') {
    const left = /** @type {Record<string, unknown>} */ (recorded);
    const right = /** @type {Record<string, unknown>} */ (computed);
    for (const key of new Set([...Object.keys(right), ...Object.keys(left)])) {
      if (!Object.hasOwn(left, key) || !Object.hasOwn(right, key)) {
        out.push({ segments: [...segments, key], shape: true });
      } else {
        driftEntries(left[key], right[key], [...segments, key], out);
      }
    }
  } else if (type === 'array') {
    const left = /** @type {unknown[]} */ (recorded);
    const right = /** @type {unknown[]} */ (computed);
    if (left.length !== right.length) out.push({ segments, shape: false });
    else left.forEach((item, index) => driftEntries(item, right[index], [...segments, index], out));
  } else if (!isDeepStrictEqual(recorded, computed)) {
    out.push({ segments, shape: false });
  }
  return out;
}

/**
 * @param {DriftEntry} entry
 * @returns {string}
 */
function entryField({ segments, shape }) {
  const path = renderPath(segments);
  return shape ? `${path} (key added, removed or retyped)` : path;
}

/**
 * @param {unknown} root
 * @param {Array<string | number>} segments
 * @returns {unknown}
 */
function valueAt(root, segments) {
  let value = root;
  for (const segment of segments) value = /** @type {any} */ (value)[segment];
  return value;
}

/**
 * @param {unknown} root
 * @param {Array<string | number>} segments
 * @param {unknown} value
 */
function setValueAt(root, segments, value) {
  const parent = valueAt(root, segments.slice(0, -1));
  /** @type {any} */ (parent)[segments[segments.length - 1]] = value;
}

/**
 * The writer's serialization of a resolved case.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function serializeSecurityCase(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/**
 * Compares the checked-in security case with a fresh resolution.
 *
 *   current  the file is byte for byte what the writer emits;
 *   fields   every drifted field, as dotted paths;
 *   denied   the drifted fields outside SECURITY_CASE_DERIVED_FIELDS.
 *
 * When only derived fields differ, the file must still be exactly the
 * writer's output with the recorded values in those fields (same keys, order
 * and formatting); anything else is denied as `(serialization)`. A file that
 * does not parse is denied as `(unparseable)`.
 *
 * @param {string} recordedText
 * @param {unknown} computed
 * @param {(text: string) => unknown} [parse] the writer passes its strict JSON parser
 * @returns {{ current: boolean, fields: string[], denied: string[] }}
 */
export function securityCaseDrift(recordedText, computed, parse = JSON.parse) {
  if (recordedText === serializeSecurityCase(computed)) return { current: true, fields: [], denied: [] };
  let recorded;
  try {
    recorded = parse(recordedText);
  } catch {
    return { current: false, fields: ['(unparseable)'], denied: ['(unparseable)'] };
  }
  const entries = driftEntries(recorded, computed);
  const fields = entries.map(entryField);
  const denied = fields.filter((field) => !fieldAllowed(field, SECURITY_CASE_DERIVED_FIELDS));
  if (denied.length === 0) {
    const patched = structuredClone(computed);
    for (const { segments } of entries) setValueAt(patched, segments, structuredClone(valueAt(recorded, segments)));
    if (serializeSecurityCase(patched) !== recordedText) {
      fields.push('(serialization)');
      denied.push('(serialization)');
    }
  }
  return { current: false, fields, denied };
}

/**
 * The writer's comparison step, shared so that tests exercise the exact
 * decision the writer makes.
 *
 *   - Without a drift report (`driftReport: false`: main's refresh, release
 *     and publish workflows, local checks) any difference fails, as it always
 *     has.
 *   - With one, the run fails only on denied drift and returns the report the
 *     policy step reads; derived-digest drift alone exits 0.
 *
 * @param {{ recordedText: string | null, computed: unknown, driftReport: boolean,
 *   parse?: (text: string) => unknown }} input
 *   `recordedText` is null when the checked-in file is missing.
 * @returns {{ exitCode: number, messages: string[], report: object | null }}
 */
export function checkSecurityCase({ recordedText, computed, driftReport, parse }) {
  const drift = recordedText === null
    ? { current: false, fields: ['(missing)'], denied: ['(missing)'] }
    : securityCaseDrift(recordedText, computed, parse);
  const report = driftReport
    ? {
      '@version': DRIFT_REPORT_VERSION,
      writer: SECURITY_CASE_WRITER,
      current: drift.current,
      stale: drift.current ? [] : [SECURITY_CASE],
      fields: drift.fields,
    }
    : null;
  if (drift.current) return { exitCode: 0, messages: [], report };
  if (!driftReport || drift.denied.length > 0) {
    const messages = [
      recordedText === null
        ? `SECURITY CASE: FAIL (${SECURITY_CASE} is missing; run npm run security-case:emit)`
        : `SECURITY CASE: FAIL (${SECURITY_CASE} is stale; run npm run security-case:emit)`,
    ];
    if (driftReport) {
      messages.push(
        `  drift outside the derived digests: ${drift.denied.slice(0, 50).join(', ')}${drift.denied.length > 50 ? `, and ${drift.denied.length - 50} more` : ''}`,
        '  Only the derived digests may lag, and only on pull requests. A change to a claim, the execution record or the file\'s',
        '  shape needs the regenerated case: commit your change, run `npm run sync:proof-stats -- --bootstrap-derived-evidence`',
        '  and `npm run sync:llm-context`, and commit the results.',
      );
    }
    return { exitCode: 1, messages, report };
  }
  return {
    exitCode: 0,
    messages: [
      `SECURITY CASE: DRIFT - only derived digests differ (${summarizeFields(drift.fields).join(', ')}); reported, not failed. `
        + 'scripts/ci/volatile-evidence.mjs decides: advisory on pull requests and merge groups, strict everywhere else.',
    ],
    report,
  };
}
