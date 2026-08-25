// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { inspectAssuranceRecordIntegrity } from '../packages/verify/src/claim-assurance.js';

const ROOT = path.resolve(import.meta.dirname, '..');
const RECORD_ID = 'sha256:dbf1f303f1b6e58aec00b3fec1f782e2853fd9ab9601d9325c7e7014091f2985';
const RECORD_PATH = path.join(
  ROOT,
  'examples/claim-assurance-reference/assurance-record.json',
);

describe('synthetic Claim Assurance offline reference', () => {
  it('replays deterministically from pinned local inputs without a network', () => {
    const result = spawnSync(
      process.execPath,
      ['examples/claim-assurance-reference/generate.mjs', '--check'],
      { cwd: ROOT, encoding: 'utf8' },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`verified offline: ${RECORD_ID}`);
  });

  it('commits a synthetic, content-addressed, non-authorizing record', () => {
    const record = JSON.parse(readFileSync(RECORD_PATH, 'utf8'));
    expect(record.record_digest).toBe(RECORD_ID);
    expect(record.verdict).toBe('VERIFIED');
    expect(record.authorizes_action).toBe(false);
    expect(record.claim.value).toMatchObject({ synthetic_reference_only: true });
    expect(record.evidence_results).toHaveLength(2);
    expect(record.evidence_results.every(
      (item: { source_id?: string }) => item.source_id?.startsWith('synthetic:'),
    )).toBe(true);
    expect(inspectAssuranceRecordIntegrity(record, {
      expected_record_digest: RECORD_ID,
    })).toMatchObject({
      integrity_valid: true,
      semantics_valid: true,
      replay_digest_matches: true,
      digest_matches: true,
      expected_digest_matches: true,
      reperformed: false,
      record_digest: RECORD_ID,
      reason: null,
    });
  });

  it('refuses semantic or digest tampering without claiming re-performance', () => {
    const record = JSON.parse(readFileSync(RECORD_PATH, 'utf8'));
    const tampered = structuredClone(record);
    tampered.authorizes_action = true;

    expect(inspectAssuranceRecordIntegrity(tampered)).toMatchObject({
      integrity_valid: false,
      semantics_valid: false,
      reperformed: false,
      reason: 'record_must_not_authorize_action',
    });
  });
});
