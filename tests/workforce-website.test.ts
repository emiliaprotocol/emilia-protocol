// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  WorkforceIntroduction,
  WorkforceHandover,
  WorkforceResponsibilities,
  WorkforceFoundation,
  WorkforceReadiness,
  WorkforceNextStep,
} from '@/components/workforce/WorkforceStory';
import ContactPage from '@/app/contact/page';
import { ENTITY } from '@/lib/site-config';
import sitemap from '@/app/sitemap';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');
const sections = [WorkforceIntroduction, WorkforceHandover, WorkforceResponsibilities, WorkforceFoundation, WorkforceReadiness, WorkforceNextStep];
const markup = sections.map(section => renderToStaticMarkup(createElement(section))).join('\n');
const text = markup.replace(/<[^>]*>/g, ' ').replace(/&#x27;|&#39;|&apos;/g, "'").replace(/\s+/g, ' ');
afterEach(() => vi.unstubAllEnvs());

describe('workforce website story and public claim boundaries', () => {
  it('renders the human headline and job-first promise without a product-inventory lead', () => {
    const introduction = renderToStaticMarkup(createElement(WorkforceIntroduction));
    expect(introduction).toMatch(/<h1[^>]*>Build your<br\s*\/?\s*>AI workforce\.<\/h1>/);
    expect(introduction).toContain('Find specialized agents or bring your own. Give them a job, set their limits and see how they perform.');
    expect(introduction).toContain('href="#build-your-workforce"');
    expect(introduction).toContain('Build your workforce');
    expect(introduction).toContain('Bring your agent');
    expect(text).toContain('Help builders earn work, help companies delegate it, and make every completed assignment improve the next decision.');
    vi.stubEnv('WORKS_V0', '0');
    const disabled = renderToStaticMarkup(createElement(WorkforceIntroduction));
    expect(disabled).toContain('href="/scan#run-local"');
    expect(disabled).not.toContain('href="/works/scan"');
    vi.stubEnv('WORKS_V0', '1');
    expect(renderToStaticMarkup(createElement(WorkforceIntroduction))).toContain('href="/works/scan"');
    expect(introduction).not.toContain('universal authority toll booth');
  });

  it('shows the same synthetic $6,600 allowance before and after replacement', () => {
    const handover = renderToStaticMarkup(createElement(WorkforceHandover));
    expect(handover.match(/<strong>\$6,600<\/strong>/g)).toHaveLength(2);
    expect(handover).toContain('Before replacement · Dot v1');
    expect(handover).toContain('After replacement · Dot v2');
    expect(handover).toContain('$10,000');
    expect(handover).toContain('$3,000');
    expect(handover).toContain('$400');
    expect(handover).toContain('synthetic scenario');
    expect(handover).toContain('No customer funds or settlement claim.');
    expect(handover).toContain('Assumes no other reservations.');
    expect(handover).toContain('The unresolved $400 stays unavailable.');
    expect(handover).toContain('The retired assignment cannot start new covered work.');
  });

  it('keeps alpha, operational and commercial readiness limits beside the product', () => {
    expect(text).toContain('Workforce workspace: private local alpha. Evaluations by arrangement, not a hosted service.');
    expect(text).toContain('one trusted host with bounded local storage');
    expect(text).toContain('no high availability or rollback resistance');
    expect(text).toContain('not a multi-tenant hosted service or a customer deployment');
    expect(text).toContain('The external evaluation team and provider are not yet selected. Terms are not yet set.');
    expect(text).toContain('No customer savings or ROI are claimed.');
    expect(text).not.toMatch(/generally available|production.ready|proven ROI/i);
  });

  it('preserves mediation, retirement and business-review boundaries', () => {
    expect(text).toContain('Enforcement requires completely mediated paths through the credential-owning Gate.');
    expect(text).toContain('Alternate credentials and routes outside Gate remain outside its control.');
    expect(text).toContain('Removing an assignment stops new covered actions, not actions already underway.');
    expect(text).toContain('Keep what Gate permitted, what the provider reported and what a reviewer accepted as separate facts.');
    expect(text).toContain('A signed receipt does not prove the job was done well.');
    expect(text).toContain('The work record must name the assignment and agent version.');
    expect(text).toContain("a replacement does not inherit the old agent's score.");
    expect(text).toContain('agent self-review are refused');
    expect(text).toContain('certify legal compliance');
  });

  it('separates company, Gate and open Protocol without requiring a purchase for the protocol', () => {
    expect(text).toContain('EMILIA is the company.');
    expect(text).toContain('Gate applies your authority.');
    expect(text).toContain('The Protocol stays open.');
    expect(text).toContain('You can use the public protocol without buying from EMILIA.');
    expect(text).toContain('Agents are software. A person or institution remains accountable.');
  });

  it('keeps private fundraising assumptions and unsupported service promises out of workforce copy', () => {
    const surfaces = [
      'components/workforce/WorkforceStory.tsx', 'app/HomePageClient.tsx',
      'app/workforce/page.tsx', 'app/about/page.tsx', 'app/contact/page.tsx',
      'app/_social/SocialCard.tsx', '.agents/product-marketing-context.md',
    ].map(read).join('\n');
    expect(surfaces).not.toMatch(/\$(?:8\s*(?:M|million)|1\.1\s*M|25\s*K)|25_000|24.month runway/i);
    expect(surfaces).not.toMatch(/https?:\/\/(?:localhost|127\.0\.0\.1)/i);
    expect(surfaces).not.toMatch(/href=["']\/(?:signup|register|pilot)[?"']/i);
    expect(surfaces).not.toMatch(/insured by EMILIA|certified compliant|guaranteed savings/i);
  });

  it('publishes a canonical workforce route linked from the homepage, navigation and sitemap', () => {
    const route = read('app/workforce/page.tsx');
    const home = read('app/HomePageClient.tsx');
    expect(route).toContain("alternates: { canonical: '/workforce' }");
    expect(route).toContain('activePage="workforce"');
    expect(route).toContain('<main>');
    expect(home).toContain('href="/workforce"');
    expect(home).toContain('<WorkforceIntroduction />');
    expect(home).toContain('<WorkforceNextStep />');
    expect(read('components/SiteNav.tsx')).toContain("['/workforce', 'Workforce']");
    expect(sitemap().some(entry => new URL(entry.url).pathname === '/workforce')).toBe(true);
  });

  it('lands workflow interest on a real contact anchor and mailto, with no fake signup', () => {
    const contact = renderToStaticMarkup(createElement(ContactPage));
    expect(contact).toContain('id="workforce"');
    expect(contact).toContain(`href="mailto:${ENTITY.email}?subject=EMILIA%20workforce%20evaluation"`);
    expect(contact).toContain('Email us about your workflow');
    expect(contact).toContain('not a hosted signup');
    expect(contact).not.toContain('<form');
    expect(markup).toContain('href="/scan#run-local"');
    expect(markup).toContain('it does not activate enforcement');
  });
});
