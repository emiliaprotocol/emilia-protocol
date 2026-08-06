// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import AuthorityBrainExperience from '@/components/authority-brain/AuthorityBrainExperience';
import {
  AUTHORITY_ACTIONS,
  DEMO_STEPS,
  canRunSyntheticPath,
  filterAuthorityActions,
  nextDemoStep,
  visibleAuthorityActionCount,
} from '@/components/authority-brain/model';

const pageSource = readFileSync(new URL('./page.tsx', import.meta.url), 'utf8');
const experienceSource = readFileSync(
  new URL('../../components/authority-brain/AuthorityBrainExperience.tsx', import.meta.url),
  'utf8',
);

describe('/authority-brain public product route', () => {
  it('renders the canonical promise, local command, and explicit synthetic boundary', () => {
    const markup = renderToStaticMarkup(<AuthorityBrainExperience />);

    expect(markup).toContain('See where your AI can act. Put a human in control before it matters.');
    expect(markup).toContain('Discover → Map → Protect → Prove');
    expect(markup).toContain('SYNTHETIC LOCAL DEMO');
    expect(markup).toContain('has not scanned your device');
    expect(markup).toContain('production_enforcement');
    expect(markup).toContain('false');
    expect(markup).toContain('npx @emilia-protocol/scan brain ./tools.json');
    expect(markup).toContain('OpenAPI remains map-only; generated protection is MCP-only.');
    expect(markup).toContain('Only declared, supported actions count as visible.');
    expect(markup).not.toContain('supported configuration surfaces');
    expect(markup).toContain('href="/pilot"');
    expect(experienceSource).toContain('Clipboard unavailable. The command is selected.');
    expect(experienceSource).toContain('range.selectNodeContents(commandRef.current)');
  });

  it('publishes metadata for the Authority Brain route', () => {
    expect(pageSource).toContain("canonical: '/authority-brain'");
    expect(pageSource).toContain('Authority Brain — Map and Protect AI Agent Actions');
    expect(pageSource).toContain('https://www.emiliaprotocol.ai/authority-brain');
    expect(pageSource).toContain('generate a reviewed MCP protection scaffold');
  });

  it('models every required synthetic surface with review details and blind spots', () => {
    expect(AUTHORITY_ACTIONS.map((action) => action.id)).toEqual([
      'wire-transfer',
      'production-deploy',
      'delete-customer',
      'get-account-balance',
      'unknown-runtime',
    ]);

    for (const action of AUTHORITY_ACTIONS) {
      expect(action.authoritySource.length).toBeGreaterThan(0);
      expect(action.blindSpots.length).toBeGreaterThan(0);
      expect(action.confidence.length).toBeGreaterThan(0);
    }

    expect(filterAuthorityActions(AUTHORITY_ACTIONS, 'review')).toHaveLength(3);
    expect(filterAuthorityActions(AUTHORITY_ACTIONS, 'pass-through')).toHaveLength(1);
    expect(filterAuthorityActions(AUTHORITY_ACTIONS, 'blind-spot')).toHaveLength(5);
    expect(visibleAuthorityActionCount(AUTHORITY_ACTIONS)).toBe(4);
    for (const action of AUTHORITY_ACTIONS.filter((item) => item.disposition !== 'visibility_gap')) {
      expect(action.authoritySource).toBe('Not established by static scan — owner review required');
    }
    expect(AUTHORITY_ACTIONS.find((action) => action.id === 'wire-transfer')).toMatchObject({
      selector: 'releaseWire',
      category: 'money_movement.release',
      assurance: 'Proposed receipt · class_a',
      confidence: 'medium',
      exactFields: ['action_type', 'amount_usd', 'currency', 'payment_instruction_id', 'beneficiary_account_hash'],
    });
    expect(AUTHORITY_ACTIONS.find((action) => action.id === 'get-account-balance')).toMatchObject({
      selector: 'getAccountBalance',
      disposition: 'pass_through_proposal',
      confidence: 'low',
      exactFields: [],
    });
    expect(AUTHORITY_ACTIONS.find((action) => action.id === 'unknown-runtime')?.exactFields).toEqual([]);
  });

  it('keeps the synthetic proof path bounded to owner-reviewed consequential actions', () => {
    const wire = AUTHORITY_ACTIONS.find((action) => action.id === 'wire-transfer');
    const summary = AUTHORITY_ACTIONS.find((action) => action.id === 'get-account-balance');
    const unknown = AUTHORITY_ACTIONS.find((action) => action.id === 'unknown-runtime');

    expect(wire && canRunSyntheticPath(wire)).toBe(true);
    expect(summary && canRunSyntheticPath(summary)).toBe(false);
    expect(unknown && canRunSyntheticPath(unknown)).toBe(false);
    expect(DEMO_STEPS.map((step) => step.label)).toEqual([
      'Scan proposal',
      'Human review',
      'Synthetic refusal',
      'Exact-action approval',
      'One-time execution',
      'Portable evidence',
    ]);
    expect(nextDemoStep(DEMO_STEPS.length - 1)).toBe(DEMO_STEPS.length - 1);
  });
});
