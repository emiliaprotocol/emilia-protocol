// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { PRODUCT_STORIES, PRODUCT_STORY_SCENARIO } from '../lib/product-stories';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

describe('EMILIA product story system', () => {
  it('defines exactly five core surfaces with a complete job and claim boundary', () => {
    expect(PRODUCT_STORIES.map((story) => story.key)).toEqual([
      'authority-brain',
      'gate',
      'approver',
      'protocol',
      'assurance',
    ]);

    for (const story of PRODUCT_STORIES) {
      expect(story.job.length).toBeGreaterThan(30);
      expect(story.storyMoment.length).toBeGreaterThan(45);
      expect(story.customerReceives.length).toBeGreaterThan(30);
      expect(story.boundary.length).toBeGreaterThan(65);
      expect(story.primaryCta.href).toMatch(/^\//);
      expect(story.proofCta.href).toMatch(/^\//);
    }
  });

  it('uses one illustrative consequence without presenting it as customer traction', () => {
    expect(PRODUCT_STORY_SCENARIO.label).toBe('Illustrative workflow');
    expect(PRODUCT_STORY_SCENARIO.action).toBe('vendor.bank_account.update');
    const component = read('components/product-story/ProductStory.tsx');
    expect(component).toContain('Not a customer claim');
  });

  it('keeps each surface at its own factual boundary', () => {
    const byKey = Object.fromEntries(PRODUCT_STORIES.map((story) => [story.key, story]));
    expect(byKey['authority-brain'].boundary).toContain('does not');
    expect(byKey.gate.boundary).toContain('completely mediated');
    expect(byKey.gate.boundary).toContain('not exactly-once physical execution');
    expect(byKey.approver.boundary).toContain('does not prove perception');
    expect(byKey.protocol.boundary).toContain('does not create authority');
    expect(byKey.assurance.boundary).toContain('does not issue an audit opinion');
  });

  it('places the story-first hero on all non-bespoke core product pages', () => {
    const expected: Array<[string, string]> = [
      ['app/gate/page.tsx', 'product="gate"'],
      ['app/product/accountable-signoff/page.tsx', 'product="approver"'],
      ['app/protocol/page.tsx', 'product="protocol"'],
      ['app/assurance/page.tsx', 'product="assurance"'],
    ];

    for (const [path, product] of expected) {
      expect(read(path)).toContain('<ProductStoryHero');
      expect(read(path)).toContain(product);
    }

    const brain = read('components/authority-brain/AuthorityBrainExperience.tsx');
    expect(brain).toContain('<ProductStoryCallout product="authority-brain" />');
    expect(brain).toContain('<ProductJourney active="authority-brain" />');
  });

  it('keeps scoped review help visible without inventing a sixth product or active service', () => {
    const component = read('components/product-story/ProductStory.tsx');
    const assurance = PRODUCT_STORIES.find((story) => story.key === 'assurance');

    expect(component).toContain('Procedures and scoped help');
    expect(component).toContain('href="/trust-desk"');
    expect(component).toContain('Neither turns EMILIA into the customer&apos;s auditor.');
    expect(assurance?.lead).toContain('must be separately scoped');
    expect(assurance?.lead).not.toContain('paid managed layer');
  });
});
