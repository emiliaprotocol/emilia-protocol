// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const page = readFileSync(resolve(ROOT, 'app/cloud/authority-inbox/page.tsx'), 'utf8');
const route = readFileSync(resolve(ROOT, 'app/api/cloud/approvals/route.ts'), 'utf8');

describe('/cloud/authority-inbox source contract', () => {
  it('uses the authenticated tenant endpoint without persisting the Cloud key', () => {
    expect(page).toContain("const ENDPOINT = '/api/cloud/approvals'");
    expect(page).toContain('authorization: `Bearer ${apiKey.trim()}`');
    expect(page).toContain("const [apiKey, setApiKey] = useState('')");
    expect(page).toContain('type="password"');
    expect(page).not.toContain('localStorage');
    expect(page).not.toContain('sessionStorage');
    expect(page).not.toContain('document.cookie');
  });

  it('does not let policy previews or notifications imply authorization', () => {
    expect(page).toContain('Non-authorizing preview');
    expect(page).toContain('authorizes=false · consumes_authority=false');
    expect(page).toContain('Creates no receipt, sends no message, and authorizes nothing.');
  });

  it('shows the prior indeterminate attempt before the governance details', () => {
    expect(page).toContain('blindRetryNotice(selected)');
    expect(page).toContain('Reconcile this attempt before issuing new authority');
    expect(page).toContain('retry-safe is false');
    expect(page.indexOf('Reconcile this attempt before issuing new authority'))
      .toBeLessThan(page.indexOf('<dl className={styles.facts}>'));
  });

  it('returns the evidence-derived projection and metrics from the tenant route', () => {
    expect(route).toContain('projectAuthorityInboxEntry');
    expect(route).toContain('authorityInboxMetrics');
    expect(route).toContain('authority_inbox: authorityInbox');
    expect(route).toContain('authority_notifications: authorityNotifications');
    expect(route).toContain("authority_inbox_profile: 'EP-AUTHORITY-INBOX-v1'");
  });
});
