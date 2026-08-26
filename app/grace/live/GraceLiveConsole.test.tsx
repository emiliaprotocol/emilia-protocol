// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import GraceLiveConsole from './GraceLiveConsole';

const consoleSource = readFileSync(new URL('./GraceLiveConsole.tsx', import.meta.url), 'utf8');

describe('/grace/live reference story', () => {
  it('leads with the curtailment problem and keeps the physical boundary explicit', () => {
    const markup = renderToStaticMarkup(<GraceLiveConsole />);

    expect(markup).toContain('The grid needs 18 MW back. Which agent is allowed to act?');
    expect(markup).toContain('Run the curtailment demo');
    expect(markup).toContain('No physical grid event is claimed.');
    expect(markup).toContain('Two roles approve');
    expect(markup).toContain('Adapter acknowledges');
    expect(markup).toContain('Settlement admission consumed');
  });

  it('waits for an explicit visitor action before running the reference flow', () => {
    expect(consoleSource).toContain('useEffect(() => clearTimers, [clearTimers])');
    expect(consoleSource.match(/useEffect\(/g)).toHaveLength(1);
  });
});
