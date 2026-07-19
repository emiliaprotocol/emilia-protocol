// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

const source = fs.readFileSync(
  new URL('./ActionEscrowExperience.js', import.meta.url),
  'utf8',
);
const scenarioSource = fs.readFileSync(
  new URL('../../examples/action-escrow/scenario.mjs', import.meta.url),
  'utf8',
);

describe('Action Escrow public claims', () => {
  it('uses provider-neutral hero copy and confines Adobe to a simulated adapter claim', () => {
    expect(source).toContain(
      'Your e-sign provider proves the document was signed. EMILIA makes the system obey it.',
    );
    expect(source).not.toContain('Adobe proves the document was signed');
    expect(scenarioSource)
      .toContain('No Adobe partnership, endorsement, credential, or live API call');
    expect(scenarioSource)
      .toContain('No Procore partnership, endorsement, credential, or live API call');
  });

  it('states the document/payment authorization boundary directly', () => {
    expect(source).toContain('SIGNED DOCUMENT ≠ PAYMENT AUTHORIZATION');
  });

  it('describes the replay as a trace rather than a fresh verification', () => {
    expect(source).toContain('Replaying the recorded verification result for this layer.');
    expect(source).not.toContain('Re-performing the pinned evidence');
  });
});
