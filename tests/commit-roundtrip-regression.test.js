// SPDX-License-Identifier: Apache-2.0
// Regression (surface audit P1, reproduced against the live prod DB): a commit
// signed at issue time failed verifyCommit because the canonical bytes diverged
// across the Postgres round-trip — timestamptz serialized "...Z" -> "...+00:00"
// and jsonb reordered nested keys, while buildCanonicalPayload only sorted
// top-level keys and embedded raw timestamps. The fix: normalizeInstant on both
// sides + recursive key sorting. This test reconstructs the exact divergence and
// asserts the signed bytes now match.
import { describe, it, expect } from 'vitest';
import { _internals } from '../lib/commit.js';

const { buildCanonicalPayload, normalizeInstant, signPayload, verifySignature } = _internals;

describe('audit regression: commit canonical bytes survive the Postgres round-trip', () => {
  it('normalizeInstant maps timestamptz "+00:00" and Date to the same "Z" instant', () => {
    const iso = '2026-07-08T15:17:33.789Z';
    expect(normalizeInstant(new Date(iso))).toBe(iso);          // sign side (Date)
    expect(normalizeInstant('2026-07-08T15:17:33.789+00:00')).toBe(iso); // verify side (PostgREST)
  });

  it('buildCanonicalPayload is identical for a value and its jsonb-reordered round-trip', () => {
    // Sign side: JS insertion order, Date timestamps.
    const signFields = {
      commit_id: 'c1',
      scope: { beta: 1, alpha: { zulu: true, apple: false } },
      context: { probe: 'x', b: 2, a: 1 },
      expires_at: normalizeInstant(new Date('2026-07-08T15:17:33.789Z')),
      created_at: normalizeInstant(new Date('2026-07-08T15:07:33.366Z')),
    };
    // Verify side: jsonb reordered nested keys, timestamptz "+00:00" form.
    const roundTripped = {
      commit_id: 'c1',
      scope: { alpha: { apple: false, zulu: true }, beta: 1 },
      context: { a: 1, b: 2, probe: 'x' },
      expires_at: normalizeInstant('2026-07-08T15:17:33.789+00:00'),
      created_at: normalizeInstant('2026-07-08T15:07:33.366+00:00'),
    };
    expect(buildCanonicalPayload(signFields)).toBe(buildCanonicalPayload(roundTripped));
  });

  it('a signature made at issue time verifies after the round-trip', () => {
    const signFields = {
      commit_id: 'c2',
      scope: { b: 1, a: { y: 2, x: 1 } },
      context: { z: 9, m: 8 },
      created_at: normalizeInstant(new Date('2026-07-08T12:34:56.789Z')),
    };
    const { signature, publicKeyBase64 } = signPayload(buildCanonicalPayload(signFields));
    const roundTripped = {
      commit_id: 'c2',
      scope: { a: { x: 1, y: 2 }, b: 1 },
      context: { m: 8, z: 9 },
      created_at: normalizeInstant('2026-07-08T12:34:56.789+00:00'),
    };
    expect(verifySignature(buildCanonicalPayload(roundTripped), signature, publicKeyBase64)).toBe(true);
  });
});
