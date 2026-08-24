// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'node:child_process';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { inspectAssuranceRecordIntegrity } from '@emilia-protocol/verify/claim-assurance';

import { GET } from '../app/api/v1/assurance/records/[recordId]/route';
import {
  CLAIM_ASSURANCE_REFERENCE_RECORD_ID,
  getClaimAssuranceReferenceRecord,
} from '../lib/assurance-reference';

const ROOT = path.resolve(__dirname, '..');

describe('synthetic Claim Assurance reference', () => {
  it('replays deterministically from pinned local inputs without a network', () => {
    const result = spawnSync(
      process.execPath,
      ['examples/claim-assurance-reference/generate.mjs', '--check'],
      { cwd: ROOT, encoding: 'utf8' },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`verified offline: ${CLAIM_ASSURANCE_REFERENCE_RECORD_ID}`);
  });

  it('is content-addressed, synthetic, and structurally unable to authorize', () => {
    const record = getClaimAssuranceReferenceRecord(CLAIM_ASSURANCE_REFERENCE_RECORD_ID);
    expect(record).not.toBeNull();
    expect(record?.record_digest).toBe(CLAIM_ASSURANCE_REFERENCE_RECORD_ID);
    expect(record?.verdict).toBe('VERIFIED');
    expect(record?.authorizes_action).toBe(false);
    expect(record?.claim.value).toMatchObject({ synthetic_reference_only: true });
    expect(record?.evidence_results).toHaveLength(2);
    expect(record?.evidence_results.every((item) => item.source_id?.startsWith('synthetic:'))).toBe(true);
    expect(inspectAssuranceRecordIntegrity(record, {
      expected_record_digest: CLAIM_ASSURANCE_REFERENCE_RECORD_ID,
    })).toMatchObject({
      integrity_valid: true,
      semantics_valid: true,
      replay_digest_matches: true,
      digest_matches: true,
      expected_digest_matches: true,
      reperformed: false,
      record_digest: CLAIM_ASSURANCE_REFERENCE_RECORD_ID,
      reason: null,
    });
  });

  it('resolves only the exact committed digest and returns no enumeration surface', async () => {
    const found = await GET(new Request(`https://example.test/api/v1/assurance/records/${encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID)}`), {
      params: Promise.resolve({ recordId: CLAIM_ASSURANCE_REFERENCE_RECORD_ID }),
    });
    expect(found.status).toBe(200);
    expect(found.headers.get('cache-control')).toContain('immutable');
    expect(found.headers.get('x-emilia-reference-only')).toBe('true');
    expect(await found.json()).toEqual(
      getClaimAssuranceReferenceRecord(CLAIM_ASSURANCE_REFERENCE_RECORD_ID),
    );

    const encoded = await GET(new Request(`https://example.test/api/v1/assurance/records/${encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID)}`), {
      params: { recordId: encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID) },
    });
    expect(encoded.status).toBe(200);

    const doubleEncoded = await GET(new Request(`https://example.test/api/v1/assurance/records/${encodeURIComponent(encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID))}`), {
      params: { recordId: encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID) },
    });
    expect(doubleEncoded.status).toBe(404);

    for (const recordId of [
      'sha256:'.concat('0'.repeat(64)),
      CLAIM_ASSURANCE_REFERENCE_RECORD_ID.toUpperCase(),
      'reference',
      '%ZZ',
      '',
    ]) {
      const missing = await GET(new Request('https://example.test'), {
        params: { recordId },
      });
      expect(missing.status).toBe(404);
      expect(missing.headers.get('cache-control')).toContain('no-store');
      expect(await missing.json()).toEqual({
        type: 'about:blank',
        title: 'Assurance Record not found',
        status: 404,
      });
    }
  });
});
