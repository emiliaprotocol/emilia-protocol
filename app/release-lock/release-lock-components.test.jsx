// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import ReleaseLockTerms from './ReleaseLockTerms';
import {
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  DEMO_RELEASE_LOCK,
} from './demo-fixture';

describe('ReleaseLockTerms', () => {
  it('renders the exact Round 1 terms without granting payment authority', () => {
    const markup = renderToStaticMarkup(
      React.createElement(ReleaseLockTerms, {
        lock: DEMO_RELEASE_LOCK,
        ceremony: CEREMONY_CO_ACCEPTANCE,
      }),
    );

    expect(markup).toContain('data-ceremony="co_acceptance"');
    expect(markup).toContain('MSKR-CO-02.pdf · final v1');
    expect(markup).toContain('approved pantry pull-out change order');
    expect(markup).toContain('$12,500.00');
    expect(markup).toContain('Adds 3 working days');
    expect(markup).toContain('CO_ACCEPTED is not payment authority.');
    expect(markup).toContain('CO_ACCEPTED action digest');
    expect(markup).not.toContain('Only DRAW_RELEASE can make');
  });

  it('renders the exact Round 2 draw, payees, and evidence separately', () => {
    const markup = renderToStaticMarkup(
      React.createElement(ReleaseLockTerms, {
        lock: DEMO_RELEASE_LOCK,
        ceremony: CEREMONY_DRAW_RELEASE,
      }),
    );

    expect(markup).toContain('data-ceremony="draw_release"');
    expect(markup).toContain('DRAW-04');
    expect(markup).toContain('Northline Kitchen &amp; Bath LLC · $10,800.00');
    expect(markup).toContain('Alder Millwork Supply Co. · $1,700.00');
    expect(markup).toContain('MSKR-M4-completion.zip · final');
    expect(markup).toContain('MSKR-DRAW-04-waivers.pdf · conditional');
    expect(markup).toContain('Only DRAW_RELEASE can make this custodian instruction eligible.');
    expect(markup).toContain('DRAW_RELEASE action digest');
    expect(markup).not.toContain('CO_ACCEPTED is not payment authority.');
  });
});
