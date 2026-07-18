// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import { GET as getEvidenceBundle } from './evidence-bundle/route';
import { GET as getFinalAgreement } from './final-agreement/route';

describe('Action Escrow downloads', () => {
  it('returns the shipped portable evidence package for both parties', async () => {
    const response = await getEvidenceBundle();
    const evidencePackage = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-disposition')).toContain('attachment;');
    expect(evidencePackage.version).toBe('EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1');
    expect(evidencePackage.package_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(evidencePackage.document_execution).toBeTruthy();
    expect(evidencePackage.agreement_acceptances).toHaveLength(2);
    expect(evidencePackage.release_approvals).toHaveLength(2);
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
});
