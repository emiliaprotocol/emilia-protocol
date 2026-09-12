// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildExecutionSessionV3,
  buildPostBuildChallengesV3,
  canonicalizeV3,
  loadPinnedKitV3,
  replayPostBuildChallengesV1,
  sha256V3,
  validateResultRowsV3,
  type V3ExecutionSession,
} from '../scripts/verify-clean-room-submission-v3.mts';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';

const kit = loadPinnedKitV3();
const seed = Buffer.alloc(32, 0x71);
const current = () => buildPostBuildChallengesV3(kit, { seed });
const hash = (value: string) => sha256V3(Buffer.from(value, 'utf8'));
type Canonicalizer = (value: any) => string;
type Row = { handle: string; result: { valid: boolean } };
type Input = { input_json: string; expected_digest: string };

function subset(session: V3ExecutionSession, predicate: (id: string) => boolean): V3ExecutionSession {
  const vectors = session.executionSuite.vectors.filter((vector: any) =>
    predicate(session.bindings.get(vector.handle)!.sourceId));
  const executionSuite = { ...session.executionSuite, vectors };
  return {
    executionSuite,
    executionBytes: Buffer.from(`${JSON.stringify(executionSuite)}\n`),
    bindings: new Map(vectors.map((vector: any) =>
      [vector.handle, session.bindings.get(vector.handle)!])),
  };
}

function rowsFor(session: V3ExecutionSession, evaluate: (input: Input) => boolean): Row[] {
  return session.executionSuite.vectors.map((vector: any) => ({
    handle: vector.handle,
    result: { valid: evaluate(vector.input.canonicalization) },
  }));
}

function computed(input: Input, canonicalize: Canonicalizer = canonicalizeV3): boolean {
  return hash(canonicalize(JSON.parse(input.input_json))) === input.expected_digest;
}

// Deliberately wrong: sorts Unicode scalar values instead of UTF-16 units.
function codePointCanonicalize(value: any): string {
  if (Array.isArray(value)) return `[${value.map(codePointCanonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const compare = (a: string, b: string): number => {
      const left = Array.from(a, (c) => c.codePointAt(0)!);
      const right = Array.from(b, (c) => c.codePointAt(0)!);
      for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
        if (left[i] !== right[i]) return left[i] - right[i];
      }
      return left.length - right.length;
    };
    return `{${Object.keys(value).sort(compare).map((key) =>
      `${JSON.stringify(key)}:${codePointCanonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function stringMutationCanonicalizer(encode: (value: string) => string): Canonicalizer {
  const visit: Canonicalizer = (value) => {
    if (Array.isArray(value)) return `[${value.map(visit).join(',')}]`;
    if (value !== null && typeof value === 'object') {
      return `{${Object.keys(value).sort().map((key) =>
        `${encode(key)}:${visit(value[key])}`).join(',')}}`;
    }
    return typeof value === 'string' ? encode(value) : JSON.stringify(value);
  };
  return visit;
}

function negativeZeroCanonicalize(value: any): string {
  if (Object.is(value, -0)) return '-0';
  if (Array.isArray(value)) return `[${value.map(negativeZeroCanonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${negativeZeroCanonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const stringMutants: Array<[string, Canonicalizer]> = [
  ['NFC normalization', stringMutationCanonicalizer(value => JSON.stringify(value.normalize('NFC')))],
  ['uppercase Unicode escapes', stringMutationCanonicalizer(value =>
    JSON.stringify(value).replace(/\\u([0-9a-f]{4})/g, (_match, digits: string) => `\\u${digits.toUpperCase()}`))],
  ['missing shorthand escapes', stringMutationCanonicalizer(value =>
    JSON.stringify(value).replace(/\\([bfnrt])/g, (_match, letter: string) => ({
      b: '\\u0008', f: '\\u000c', n: '\\u000a', r: '\\u000d', t: '\\u0009',
    })[letter]!))],
];

// Deliberately narrow numeric-profile model for the mutants below. The actual
// runner is exercised separately, including its real Unicode/depth predicate.
function safeScalars(value: any): boolean {
  if (typeof value === 'number') return Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(safeScalars);
  if (value !== null && typeof value === 'object') return Object.values(value).every(safeScalars);
  return value === null || typeof value === 'string' || typeof value === 'boolean';
}

const validRaw = [
  'negative-zero', 'negative-zero-decimal', 'integer-exponent', 'max-safe-integer',
  'depth-64', 'surrogate-pair', 'distinct-escaped-keys', 'zero-exponent',
];
const invalidRaw = [
  'unsafe-integer', 'fractional', 'large-exponent', 'depth-65',
  'lone-high-surrogate', 'lone-low-surrogate', 'duplicate-key', 'escaped-duplicate-key',
];

const parserMutants: Array<[string, string]> = [
  ['depth-65', 'nesting depth exceeds 64'],
  ['lone-high-surrogate', 'unpaired high surrogate escape'],
  ['lone-low-surrogate', 'unpaired low surrogate escape'],
  ['duplicate-key', 'duplicate object member name'],
  ['escaped-duplicate-key', 'duplicate object member name'],
];

describe('post-build canonicalization challenge hardening', () => {
  it('rejects a code-point-sorting canonicalizer that passed the old fresh challenge', () => {
    const old = replayPostBuildChallengesV1(kit, { seed });
    const oldRows = rowsFor(old, input => computed(input, codePointCanonicalize));
    expect(validateResultRowsV3(old, oldRows)).toHaveLength(64);

    // Restrict this mutant to the rich pairs, so a raw-profile refusal cannot
    // accidentally be the reason the canonicalization mutation is detected.
    const pairs = subset(current(), id => id.startsWith('post-build-canonical-pair-'));
    const rows = rowsFor(pairs, input => computed(input, codePointCanonicalize));
    expect(rows.filter(row => row.result.valid !== pairs.bindings.get(row.handle)!.expected.valid))
      .toHaveLength(32);
    expect(() => validateResultRowsV3(pairs, rows)).toThrow(/exact typed result differs/);
  });

  it('replays the exact historical v1 bytes without using v1 for current acceptance', () => {
    const old = replayPostBuildChallengesV1(kit, { seed });
    // Measured from the unmodified generated evaluator before the repair.
    expect(hash(old.executionBytes.toString('utf8')))
      .toBe('fb3a9e033f35c8069c37c307ab81783616d25b4a1d785b2aa5de7aa572be3037');
    expect(old.generator).toBe('EP-CLEAN-ROOM-CANONICALIZATION-CHALLENGE-v1');
    expect(current().generator).toBe('EP-CLEAN-ROOM-CANONICALIZATION-CHALLENGE-v2');
    expect(current().executionBytes).not.toEqual(old.executionBytes);
  });

  it.each(stringMutants)('detects %s on fresh pairs, not by unrelated parser failures', (_name, mutant) => {
    const pairs = subset(current(), id => id.startsWith('post-build-canonical-pair-'));
    const rows = rowsFor(pairs, input => computed(input, mutant));
    expect(rows.filter(row => row.result.valid !== pairs.bindings.get(row.handle)!.expected.valid))
      .toHaveLength(32);
    expect(() => validateResultRowsV3(pairs, rows)).toThrow(/exact typed result differs/);
  });

  it('rejects a published-canonicalization table with an incomplete fresh-input fallback', () => {
    const contract = kit.contracts.find(entry => entry.path.endsWith('/canonicalization.v1.json'))!;
    const published = buildExecutionSessionV3(contract);
    const table = new Map<string, boolean>(published.executionSuite.vectors.map((vector: any) => [
      JSON.stringify(vector.input), published.bindings.get(vector.handle)!.expected.valid,
    ]));
    const pairs = subset(current(), id => id.startsWith('post-build-canonical-pair-'));
    expect(pairs.executionSuite.vectors.every((vector: any) => !table.has(JSON.stringify(vector.input))))
      .toBe(true);
    const rows: Row[] = pairs.executionSuite.vectors.map((vector: any) => ({
      handle: vector.handle,
      result: { valid: table.get(JSON.stringify(vector.input))
        ?? computed(vector.input.canonicalization, codePointCanonicalize) },
    }));
    expect(() => validateResultRowsV3(pairs, rows)).toThrow(/exact typed result differs/);
  });

  it('the actual bundled reference runner passes all 80 fresh cases', () => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-challenge-v2-honest-'));
    try {
      const runner = path.join(temporary, 'honest.mjs');
      const input = path.join(temporary, 'challenge.json');
      const session = current();
      execFileSync(path.resolve('node_modules/.bin/esbuild'), [
        path.resolve('conformance/runners/run-js-v3.mts'), '--bundle', '--platform=node',
        '--format=esm', `--outfile=${runner}`,
      ], { timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] });
      fs.writeFileSync(input, session.executionBytes);
      const rows = JSON.parse(execFileSync(process.execPath, [runner, input], {
        encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024,
      }));
      expect(validateResultRowsV3(session, rows)).toHaveLength(80);
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  });

  it('keeps 32 exact-input digest pairs separate from 16 raw boundary cases', () => {
    const session = current();
    expect(session.bindings.size).toBe(80);
    const groups = new Map<string, Array<{ valid: boolean; digest: string }>>();
    for (const vector of session.executionSuite.vectors) {
      const binding = session.bindings.get(vector.handle)!;
      if (!binding.sourceId.startsWith('post-build-canonical-pair-')) continue;
      const input = vector.input.canonicalization;
      const entries = groups.get(input.input_json) ?? [];
      entries.push({ valid: binding.expected.valid, digest: input.expected_digest });
      groups.set(input.input_json, entries);
    }
    expect(groups.size).toBe(32);
    for (const [raw, entries] of groups) {
      expect(entries.map(entry => entry.valid).sort()).toEqual([false, true]);
      expect(entries.every(entry => /^[a-f0-9]{64}$/.test(entry.digest))).toBe(true);
      expect(entries[0].digest).not.toBe(entries[1].digest);
      expect(entries.find(entry => entry.valid)!.digest).toBe(hash(canonicalizeV3(JSON.parse(raw))));
    }
    const raw = subset(session, id => id.startsWith('post-build-canonical-raw-'));
    expect([...raw.bindings.values()].map(binding => binding.sourceId).sort())
      .toEqual([...validRaw, ...invalidRaw].map(name => `post-build-canonical-raw-${name}`).sort());
    for (const binding of raw.bindings.values()) {
      expect(binding.expected.valid)
        .toBe(validRaw.some(name => binding.sourceId === `post-build-canonical-raw-${name}`));
    }
  });

  it.each(invalidRaw)('makes raw %s a real refusal trap, not a digest-mismatch pass', name => {
    const session = subset(current(), id => id === `post-build-canonical-raw-${name}`);
    expect(session.bindings.size).toBe(1);
    const laxRows = rowsFor(session, input => computed(input));
    expect(laxRows[0].result.valid).toBe(true);
    expect([...session.bindings.values()][0].expected.valid).toBe(false);
    expect(() => validateResultRowsV3(session, laxRows)).toThrow(/exact typed result differs/);
  });

  it.each(parserMutants)('detects a parser that specifically overlooks %s', (name, refusedReason) => {
    const session = subset(current(), id => id === `post-build-canonical-raw-${name}`);
    const rows = rowsFor(session, (input) => {
      const gate = strictParseGate(input.input_json);
      expect(gate).toEqual({ ok: false, reason: refusedReason });
      const acceptedByMutant = gate.ok || gate.reason === refusedReason;
      return acceptedByMutant && safeScalars(JSON.parse(input.input_json)) && computed(input);
    });
    expect(rows[0].result.valid).toBe(true);
    expect(() => validateResultRowsV3(session, rows)).toThrow(/exact typed result differs/);
  });

  it.each(['unsafe-integer', 'fractional', 'large-exponent'])('detects missing EP numeric-profile enforcement for %s', name => {
    const session = subset(current(), id => id === `post-build-canonical-raw-${name}`);
    const rows = rowsFor(session, (input) => {
      expect(strictParseGate(input.input_json).ok).toBe(true);
      expect(safeScalars(JSON.parse(input.input_json))).toBe(false);
      return computed(input);
    });
    expect(rows[0].result.valid).toBe(true);
    expect(() => validateResultRowsV3(session, rows)).toThrow(/exact typed result differs/);
  });

  it.each(['negative-zero', 'negative-zero-decimal'])('preserves raw %s as valid canonical zero', name => {
    const session = subset(current(), id => id === `post-build-canonical-raw-${name}`);
    const input = session.executionSuite.vectors[0].input.canonicalization;
    expect(input.input_json).toContain(name === 'negative-zero' ? ':-0}' : ':-0.0}');
    expect(Object.is(JSON.parse(input.input_json).value, -0)).toBe(true);
    expect(canonicalizeV3(JSON.parse(input.input_json))).toContain(':0}');
    expect(validateResultRowsV3(session, rowsFor(session, value => computed(value)))).toHaveLength(1);
    const wrongRows = rowsFor(session, value => computed(value, negativeZeroCanonicalize));
    expect(wrongRows[0].result.valid).toBe(false);
    expect(() => validateResultRowsV3(session, wrongRows)).toThrow(/exact typed result differs/);
  });

  it('replays deterministically and changes every family input under a fresh seed', () => {
    const first = current();
    expect(current().executionBytes).toEqual(first.executionBytes);
    const next = buildPostBuildChallengesV3(kit, { seed: Buffer.alloc(32, 0x72) });
    const inputs = (session: V3ExecutionSession) => new Map<string, string>(
      session.executionSuite.vectors.map((vector: any) => [
        session.bindings.get(vector.handle)!.sourceId, vector.input.canonicalization.input_json,
      ]));
    const firstInputs = inputs(first);
    for (const [id, raw] of inputs(next)) expect(raw, id).not.toBe(firstInputs.get(id));
    expect([...next.bindings.keys()].some(handle => first.bindings.has(handle))).toBe(false);
  });

  it('does not expose expected answers or family labels in the execution envelope', () => {
    const session = current();
    const text = session.executionBytes.toString('utf8');
    expect(text).not.toMatch(/"(?:expect|expect_status|valid|sourceId|description|failure_class)"/);
    expect(text).not.toContain('post-build-canonical-');
    expect(new Set(session.executionSuite.vectors.map((vector: any) => vector.handle)).size).toBe(80);
    for (const vector of session.executionSuite.vectors) {
      expect(Object.keys(vector).sort()).toEqual(['handle', 'input']);
      expect(vector.handle).toMatch(/^cr3_[A-Za-z0-9_-]{32}$/);
      expect(Object.keys(vector.input)).toEqual(['canonicalization']);
      expect(Object.keys(vector.input.canonicalization).sort()).toEqual(['expected_digest', 'input_json']);
    }
  });
});
