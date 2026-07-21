// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { GET as getEvidenceBundle } from './evidence-bundle/route';
import { GET as getFinalAgreement } from './final-agreement/route';
import { GET as getProjectRecord } from './project-record/route';

describe('Action Escrow downloads', () => {
  it('returns the shipped portable evidence package for both parties', async () => {
    const response = await getEvidenceBundle();
    const evidencePackage = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-disposition')).toContain('attachment;');
    expect(evidencePackage.version)
      .toBe('EP-ACTION-ESCROW-CONTRACTOR-EVIDENCE-PACKAGE-v1');
    expect(evidencePackage.package_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(evidencePackage.document_execution).toBeTruthy();
    expect(evidencePackage.agreement_acceptances).toHaveLength(2);
    expect(evidencePackage.release_approvals).toHaveLength(2);
    expect(evidencePackage.project_record).toMatchObject({
      media_type: 'application/json',
      provider: 'procore',
    });
    expect(evidencePackage.release.execution_record).toMatchObject({
      operation: 'release',
      code: 'release_committed',
      outcome: 'applied',
      ok: true,
    });
  });

  it('returns the exact final PDF as an optional attachment', async () => {
    const response = await getFinalAgreement(
      new Request('http://localhost/action-escrow/final-agreement?download=1'),
    );
    const bytes = Buffer.from(await response.arrayBuffer());

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/pdf');
    expect(response.headers.get('content-disposition')).toContain('attachment;');
    expect(bytes.subarray(0, 5).toString('ascii')).toBe('%PDF-');
  });

  it('returns the digest-bound project record as a non-authoritative companion', async () => {
    const bundleResponse = await getEvidenceBundle();
    const evidencePackage = await bundleResponse.json();
    const response = await getProjectRecord();
    const bytes = Buffer.from(await response.arrayBuffer());
    const record = JSON.parse(bytes.toString('utf8'));

    expect(response.status).toBe(200);
    expect(response.headers.get('content-disposition')).toContain('attachment;');
    expect(record).toMatchObject({
      '@version': 'EMILIA-EXTERNAL-PROJECT-RECORD-EVIDENCE-v1',
      provider: 'procore',
      change_order_id: '9001',
      authorizes_action: false,
      establishes_acceptance: false,
    });
    expect(record.snapshot_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(`sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`)
      .toBe(evidencePackage.project_record.digest);
    expect(bytes.length).toBe(evidencePackage.project_record.byte_length);
    expect(record.snapshot_digest)
      .toBe(evidencePackage.project_record.snapshot_digest);
  });
});
