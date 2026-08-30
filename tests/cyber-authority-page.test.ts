// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');

const page = read('app/cyber-authority/page.tsx');
const drill = read('app/cyber-authority/CyberAuthorityDrill.tsx');
const style = read('app/cyber-authority/cyber-authority.module.css');
const openGraph = read('app/cyber-authority/opengraph-image.tsx');
const useCases = read('app/use-cases/page.tsx');
const footer = read('components/SiteFooter.tsx');
const sitemap = read('app/sitemap.ts');
const article = read('app/blog/ai-defenders-need-action-authority/page.tsx');
const articleLayout = read('app/blog/ai-defenders-need-action-authority/layout.tsx');
const incidentArticle = read('app/blog/credentials-are-not-action-authorization/page.tsx');
const contextSource = read('docs/ai/context-source.v1.json');
const llmsIndex = read('public/llms.txt');
const llmsFull = read('public/llms-full.txt');
const machineContext = read('public/.well-known/emilia-context.json');

describe('Authority for AI Defenders public campaign', () => {
  it('publishes an indexable audience page with dedicated share metadata', () => {
    expect(page).toContain("alternates: { canonical: '/cyber-authority' }");
    expect(page).toContain('Let AI defend the system. Keep the authority to change it.');
    expect(page).toContain("url: '/cyber-authority/opengraph-image'");
    expect(page).toContain('robots: { index: true, follow: true }');
    expect(openGraph).toContain('export const size = { width: 1200, height: 630 }');
    expect(sitemap).toContain("{ path: '/cyber-authority'");
    expect(useCases).toContain("href: '/cyber-authority'");
    expect(footer).toContain("['/cyber-authority', 'AI Defender Authority']");
  });

  it('shows the exact-action control story without becoming a threat detector', () => {
    expect(page).toContain('Your security product detects the threat and proposes the response.');
    expect(page).toContain('at the credential-owning boundary');
    expect(page).toContain('Inside the mandate: one attempt. Outside it: refuse.');
    expect(page).toContain('It is not a threat detector.');
    expect(page).toContain('EMILIA controls covered consequences. It does not decide what the threat is.');
    expect(page).not.toContain('EMILIA stops cyberattacks');
    expect(page).not.toMatch(/EMILIA prevents ransomware|EMILIA protects every/i);
  });

  it('keeps the prevention and outcome claims inside the covered boundary', () => {
    expect(page).toContain('Gate prevents only on completely mediated covered paths.');
    expect(page).toContain('Alternate credentials, direct provider calls, unprotected tools');
    expect(page).toContain('Physical effect or provider success without authenticated outcome evidence.');
    expect(page).toContain('Production activation is');
    expect(page).toContain('separately scoped after acceptance.');
    expect(page).toContain('PROTECTED_WORKFLOW_PILOT.shortPriceLabel');
    expect(page).toContain('It is not a threat detector.');
    expect(page).not.toMatch(/guaranteed|universal firewall|certified safe/i);
  });

  it('ships a browser-only drill over four distinct control states', () => {
    expect(drill).toContain("verdict: 'ADMITTED'");
    expect(drill.match(/verdict: 'REFUSED'/g)).toHaveLength(2);
    expect(drill).toContain("verdict: 'INDETERMINATE'");
    expect(drill).toContain("target: 'tenant:*'");
    expect(drill).toContain('Already consumed');
    expect(drill).toContain('NO EXTERNAL ACTION');
    expect(drill).toContain('aria-pressed={selected.id === scenario.id}');
    expect(drill).toContain('aria-live="polite"');
    expect(style).toContain(".scenarioButton[data-selected='true']");
  });

  it('publishes visible FAQ content and source-backed structured data safely', () => {
    expect(page).toContain("'@type': 'WebPage'");
    expect(page).toContain("'@type': 'Service'");
    expect(page).toContain("'@type': 'BreadcrumbList'");
    expect(page).toContain("'@type': 'FAQPage'");
    expect(page).toContain('{FAQ.map(({ question, answer }) => (');
    expect(page).toContain(".replace(/</g, '\\\\u003c')");
    expect(page).toContain('dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}');
    expect(page).toContain('https://openai.com/collective-cyberdefense/');
    expect(page).toContain('https://www.ncsc.gov.uk/news/the-ai-shift-in-cyber-risk-why-leaders-must-act-now');
  });

  it('publishes a sober, source-linked field note with the campaign handoff', () => {
    expect(articleLayout).toContain("canonical: '/blog/ai-defenders-need-action-authority'");
    expect(article).toContain('AI defenders need action authority, not just credentials.');
    expect(article).toContain('Detection and authority answer different questions');
    expect(article).toContain('EMILIA does not detect threats');
    expect(article).toContain('href="/cyber-authority#authority-drill"');
    expect(incidentArticle).toContain('href="/cyber-authority#authority-drill"');
    expect(sitemap).toContain("{ path: '/blog/ai-defenders-need-action-authority'");
  });

  it('keeps the new security solution synchronized across LLM discovery surfaces', () => {
    expect(contextSource).toContain('https://www.emiliaprotocol.ai/cyber-authority');
    expect(contextSource).toContain('EMILIA does not detect or stop cyberattacks.');
    expect(llmsIndex).toContain('[Authority for AI Defenders](https://www.emiliaprotocol.ai/cyber-authority)');
    expect(llmsFull).toContain('EMILIA does not detect or stop cyberattacks.');
    expect(machineContext).toContain('https://www.emiliaprotocol.ai/cyber-authority');
  });
});
