// SPDX-License-Identifier: Apache-2.0
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import ProtectPage from './page';

describe('consumer Consequence Firewall page', () => {
  it('leads with the consequence and names every first protection choice', () => {
    const html = renderToStaticMarkup(<ProtectPage />);
    expect(html).toContain('Choose what AI must never do silently');
    for (const label of [
      'Spend money',
      'Delete files',
      'Change account access',
      'Publish or deploy code',
      'Send sensitive data',
      'Control machines',
    ]) expect(html).toContain(label);
  });

  it('does not represent selection as installed protection', () => {
    const html = renderToStaticMarkup(<ProtectPage />);
    expect(html).toContain('Choosing a protection creates configuration');
    expect(html).toContain('pin the rule');
    expect(html).toContain('active refusal test passes');
    expect(html).not.toContain('You are protected');
  });
});
