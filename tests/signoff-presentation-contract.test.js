// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');
const source = (path) => readFileSync(resolve(ROOT, path), 'utf8');

describe('web Class-A presentation contract', () => {
  it('renders the complete deterministic WYSIWYS line set and the canonical action', () => {
    const page = source('app/signoff/[signoffId]/page.js');

    expect(page).toContain('renderAction(action)');
    expect(page).toMatch(/rendered\.lines\.map/);
    expect(page).toContain('Complete signed action');
    expect(page).not.toContain('rolloutLines');
    expect(page).not.toContain('.toLocaleString(');
  });

  it('uses the intended approver from the signed request, not the query string', () => {
    const page = source('app/signoff/[signoffId]/page.js');

    expect(page).toContain('requestEvent.after_state.approver_id');
    expect(page).not.toContain("sp?.approver");
    expect(page).not.toContain('initialApproverId={approverId}');
  });

  it('validates returned challenge material before a separate passkey confirmation', () => {
    const signer = source('app/signoff/[signoffId]/signer.js');

    expect(signer).toContain('expectedActionHash');
    expect(signer).toContain('expectedDisplayHash');
    expect(signer).toContain('expectedRenderProfile');
    expect(signer).toContain('Signing context action hash does not match');
    expect(signer).toContain('Signing context display hash does not match');
    expect(signer).toContain('Signing render profile does not match');
    expect(signer).toContain('Confirm & use passkey');
    expect(signer).toContain('Review the signed challenge');
  });
});
