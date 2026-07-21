// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/cloud/signoffs/page.tsx'), 'utf8');

describe('/cloud/signoffs connected-console source contract', () => {
  it('contains no mock fixtures, placeholder domains, or browser credential persistence', () => {
    expect(page).not.toContain('MOCK_');
    expect(page).not.toContain('example.invalid');
    expect(page).not.toContain('localStorage');
    expect(page).not.toContain('sessionStorage');
    expect(page).not.toContain('document.cookie');
    expect(page).toContain("const [apiKey, setApiKey] = useState('')");
    expect(page).toContain('type="password"');
    expect(page).toContain('Cloud API key stays in React memory only');
  });

  it('calls the approval queue, create, one-time consume, and evidence endpoints', () => {
    expect(page).toContain("const APPROVALS_ENDPOINT = '/api/cloud/approvals'");
    expect(page).toContain("method: 'GET'");
    expect(page).toContain("method: 'POST'");
    expect(page).toContain(
      '`${APPROVALS_ENDPOINT}/${encodeURIComponent(approval.receipt_id)}/consume`',
    );
    expect(page).toContain(
      '`${APPROVALS_ENDPOINT}/${encodeURIComponent(approval.receipt_id)}/evidence`',
    );
    expect(page).toContain('authorization: `Bearer ${apiKey.trim()}`');
  });

  it('binds the payment fields and exposes the complete approval lifecycle', () => {
    for (const field of [
      'name="approver_id"',
      'name="amount"',
      'name="currency"',
      'name="counterparty_name"',
      'name="payment_reference"',
      'name="payment_destination_hash"',
    ]) {
      expect(page).toContain(field);
    }
    for (const status of ['pending', 'approved', 'rejected', 'expired', 'consumed']) {
      expect(page).toContain(status);
    }
    expect(page).toContain('Action hash');
    expect(page).toContain('Canonical action identifier');
    expect(page).toContain('`/signoff/${encodeURIComponent(approval.signoff_id)}`');
    expect(page).toContain('Copy link');
    expect(page).toContain('Export JSON evidence');
  });

  it('labels the prototype and limits consumption to approved requests', () => {
    expect(page).toContain('Implementation prototype');
    expect(page).toContain('WebAuthn/WYSIWYS review');
    expect(page).toContain("approval.status === 'approved' && (");
    expect(page).toContain('Consume once');
  });
});
