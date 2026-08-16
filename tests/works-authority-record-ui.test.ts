// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (file: string) => fs.readFileSync(path.join(process.cwd(), file), 'utf8');

describe('Authority Record consent-first UI contract', () => {
  it('keeps invitation and owner credentials out of query strings and persistent local storage', () => {
    const claim = read('app/works/claim/ClaimAuthorityRecord.tsx');
    expect(claim).toContain('window.location.hash');
    expect(claim).toContain('sessionStorage');
    expect(claim).not.toContain('localStorage');
    expect(claim).not.toContain('searchParams.get');
    expect(claim).not.toMatch(/href=.*owner_token/);
  });

  it('requires an explicit exact-digest approval and exposes correction and withdrawal controls', () => {
    const claim = read('app/works/claim/ClaimAuthorityRecord.tsx');
    expect(claim).toContain('record_digest');
    expect(claim).toContain('/approve');
    expect(claim).toContain('/withdraw');
    expect(claim).toMatch(/Approve exact record/i);
    expect(claim).toMatch(/Correct before publishing/i);
  });

  it('uses factual mapping language and never sells a favorable verdict', () => {
    const record = read('app/works/records/[recordId]/page.tsx');
    const badge = read('app/api/works/authority-records/[recordId]/badge/route.ts');
    const combined = `${record}\n${badge}`;
    expect(combined).toContain('Mapped by EMILIA');
    expect(combined).toContain('against commit');
    expect(combined).not.toMatch(/EMILIA Approved/i);
    expect(combined).not.toMatch(/trust score/i);
    expect(combined).not.toMatch(/certified safe/i);
  });

  it('collects independently verified requests and verifies tokens from a fragment', () => {
    const record = read('app/works/records/[recordId]/page.tsx');
    const request = read('app/works/records/[recordId]/RequestAuthorityRecord.tsx');
    const verify = read('app/works/request/verify/VerifyAuthorityRequest.tsx');
    expect(record).toContain('RequestAuthorityRecord');
    expect(request).toContain('Request this Authority Record');
    expect(request).toContain('/requests');
    expect(request).not.toMatch(/buyers|purchasers/i);
    expect(verify).toContain('window.location.hash');
    expect(verify).not.toContain('searchParams.get');
  });

  it('lets a returning owner manage the exact record and buy monitoring without buying a verdict', () => {
    const claim = read('app/works/claim/ClaimAuthorityRecord.tsx');
    expect(claim).toContain('Load claimed record');
    expect(claim).toContain('/billing/checkout');
    expect(claim).toContain('/billing/reconcile');
    expect(claim).toContain('$29/month');
    expect(claim).toMatch(/monitoring and freshness/i);
    expect(claim).toMatch(/never a favorable result/i);
    expect(claim).not.toMatch(/owner_token.*window\.location/i);
  });
});
