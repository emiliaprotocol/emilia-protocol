// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import { headers } from 'next/headers';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import PortfolioActionRiskLab from './PortfolioActionRiskLab';
import css from './private-equity.module.css';

const PAGE_URL = 'https://www.emiliaprotocol.ai/private-equity';
const PAGE_TITLE = 'Agentic AI Risk Controls for Private Equity Portfolios';
const PAGE_DESCRIPTION =
  'Design a customer-owned exact-action authority boundary for one portfolio-company finance workflow. '
  + 'Start with a nonproduction 90-day, $25K EMILIA Gate pilot for a vendor bank-detail change or payment release.';

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: '/private-equity' },
  keywords: [
    'agentic AI risk controls private equity',
    'private equity portfolio AI governance',
    'portfolio company AI risk management',
    'AI agent payment controls',
    'vendor bank detail change control',
    'autonomous agent authorization',
    'private equity operating partner technology',
  ],
  openGraph: {
    type: 'website',
    url: PAGE_URL,
    title: 'Put a hard authority boundary around one capital-exposing agent action',
    description: PAGE_DESCRIPTION,
    images: [
      {
        url: '/private-equity/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'An agent action crossing a customer-owned EMILIA Gate before a finance provider',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Put a hard authority boundary around one capital-exposing agent action',
    description: PAGE_DESCRIPTION,
    images: ['/private-equity/opengraph-image'],
  },
  robots: { index: true, follow: true },
};

const FAQ = [
  {
    question: 'Does EMILIA make a private equity investment safe?',
    answer:
      'No. EMILIA does not cover every agent risk or make an investment safe. Gate controls one bounded class of action risk at a configured boundary when every covered path to the consequential system crosses the control and the customer configures the authority and evidence rules. Source truth, bypass paths, fraud absence, provider outcome, legality, and business wisdom remain outside the claim.',
  },
  {
    question: 'Does the sponsor control each portfolio company\'s keys or approvals?',
    answer:
      'No. The deployment model keeps credentials, trust roots, authority rules, and detailed action evidence with the portfolio company. A sponsor can fund a common control pattern and receive only the buyer-agreed, payload-minimized implementation evidence.',
  },
  {
    question: 'What does complete mediation mean?',
    answer:
      'Every path capable of producing the covered effect must cross Gate at the executor or system-of-record boundary. A sidecar, prompt filter, or voluntary agent call cannot constrain an alternate path that bypasses the deployed control.',
  },
  {
    question: 'Does the Portfolio Action Risk Lab move or block money?',
    answer:
      'No. It provisions a throwaway observe-only sandbox key and evaluates fictional finance-action metadata. It does not connect to an ERP, change vendor data, release a payment, authorize production use, or provide production protection.',
  },
  {
    question: 'What is included in the first pilot?',
    answer:
      'One buyer-selected vendor bank-detail change or payment-release workflow, 90 days, and a fixed $25K scope. The pilot is synthetic, read-only, sandbox, or shadow only. It ends with a production decision packet and draft implementation SOW. Any production activation is a separately scoped Gate Implementation after the buyer accepts the boundary, trust inputs, operating procedure, and complete-mediation design.',
  },
] as const;

const STRUCTURED_DATA = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebPage',
      '@id': `${PAGE_URL}#webpage`,
      url: PAGE_URL,
      name: PAGE_TITLE,
      description: PAGE_DESCRIPTION,
      isPartOf: { '@id': 'https://www.emiliaprotocol.ai/#website' },
      about: [
        { '@type': 'Thing', name: 'Private equity portfolio operations' },
        { '@type': 'Thing', name: 'AI agent authorization controls' },
        { '@type': 'Thing', name: 'Finance operations controls' },
      ],
    },
    {
      '@type': 'FAQPage',
      '@id': `${PAGE_URL}#faq`,
      mainEntity: FAQ.map(({ question, answer }) => ({
        '@type': 'Question',
        name: question,
        acceptedAnswer: { '@type': 'Answer', text: answer },
      })),
    },
  ],
};

// JSON-LD is data, not markup. Escaping '<' prevents a future copy change from
// terminating the script element while preserving valid JSON for crawlers.
const STRUCTURED_DATA_JSON = JSON.stringify(STRUCTURED_DATA).replace(/</g, '\\u003c');

const PILOT_PHASES = [
  {
    number: '01',
    window: 'Days 1-30',
    title: 'Name the boundary',
    body: 'Map one vendor bank-detail change or payment-release path, including every credential and alternate route capable of reaching the provider.',
  },
  {
    number: '02',
    window: 'Days 31-60',
    title: 'Observe before enforcing',
    body: 'Run synthetic and buyer-approved read-only validation. Measure what the configured authority rule would hold, refuse, or allow without changing production behavior.',
  },
  {
    number: '03',
    window: 'Days 61-90',
    title: 'Make a buyer-owned production decision',
    body: 'Deliver the boundary design, acceptance evidence, limitations, operating procedure, and draft implementation SOW. The pilot does not activate production; any production enforcement is a separately scoped Gate Implementation after explicit buyer acceptance.',
  },
] as const;

const CONTROL_LAYERS = [
  {
    label: 'Sponsor',
    title: 'Funds a repeatable control pattern',
    body: 'Select a portfolio-company workflow and define the minimum evidence needed for implementation oversight. The sponsor does not become the company\'s trust root.',
  },
  {
    label: 'Portfolio company',
    title: 'Keeps authority local',
    body: 'Own credentials, approvers, policies, trust roots, retention, and detailed action evidence. Decide which actions Gate may admit at the covered boundary.',
  },
  {
    label: 'EMILIA Gate',
    title: 'Controls the exact action',
    body: 'At a completely mediated executor path, require accepted exact-action authority and required evidence before provider entry, then preserve an action-bound record.',
  },
] as const;

export default async function PrivateEquityPage(): Promise<React.ReactElement> {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <div className={css.shell}>
      <script
        type="application/ld+json"
        nonce={nonce}
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}
      />
      <SiteNav />
      <main className={css.page}>
        <section className={css.hero} aria-labelledby="pe-hero-title">
          <div className={css.heroCopy}>
            <p className={css.eyebrow}>For private equity operating partners and portfolio finance leaders</p>
            <h1 id="pe-hero-title">Put a hard authority boundary around one capital-exposing agent action.</h1>
            <p className={css.heroLead}>
              Agents are moving from advice to action. EMILIA Gate puts a customer-owned authority
              tollgate at the systems where they change vendor bank details or release payments.
            </p>
            <p className={css.boundaryStatement}>
              On completely mediated covered paths, no accepted exact-action authority and required
              evidence means no provider entry.
            </p>
            <div className={css.heroActions}>
              <a className={css.primaryButton} href="/pilot?v=fin">Scope one portfolio pilot</a>
              <a className={css.textLink} href="#risk-lab">Run the observe-only risk lab <span aria-hidden="true">↓</span></a>
            </div>
            <dl className={css.offerStrip} aria-label="Pilot terms">
              <div><dt>Scope</dt><dd>{PROTECTED_WORKFLOW_PILOT.workflowLabel}</dd></div>
              <div><dt>Duration</dt><dd>{PROTECTED_WORKFLOW_PILOT.durationLabel}</dd></div>
              <div><dt>Fixed fee</dt><dd>{PROTECTED_WORKFLOW_PILOT.shortPriceLabel}</dd></div>
              <div><dt>Start</dt><dd>Observe first</dd></div>
            </dl>
          </div>

          <div className={css.heroVisual} aria-label="Covered action path diagram">
            <div className={css.diagramHeader}>
              <span>Covered finance path</span>
              <span className={css.statusDot}>Complete mediation required</span>
            </div>
            <div className={css.actionCard}>
              <span className={css.actionLabel}>Agent proposes</span>
              <strong>Release $82,000</strong>
              <code>payment.release / vendor_014</code>
            </div>
            <div className={css.flowLine} aria-hidden="true"><span /></div>
            <div className={css.gateCard}>
              <div className={css.gateMark}>GATE</div>
              <div>
                <span className={css.actionLabel}>Customer-owned check</span>
                <strong>Exact action + authority + evidence</strong>
              </div>
              <span className={css.gateState}>HOLD</span>
            </div>
            <div className={css.flowLine} aria-hidden="true"><span /></div>
            <div className={css.providerCard}>
              <span className={css.actionLabel}>Finance provider</span>
              <strong>Not entered without accepted evidence</strong>
            </div>
            <p className={css.diagramNote}>
              Gate controls admission on the covered path. It does not prove that bank details are
              correct, that fraud is absent, or that the provider succeeds.
            </p>
          </div>
        </section>

        <section className={css.introBand} aria-labelledby="why-portfolio-heading">
          <p className={css.sectionKicker}>The portfolio opportunity</p>
          <div>
            <h2 id="why-portfolio-heading">One control pattern. Company-owned authority.</h2>
            <p>
              A sponsor can fund the same consequence-control discipline across companies without
              centralizing their keys, approvals, or operational records. Start with one company and
              one finance boundary. Repeat only after the control works under that company&apos;s systems,
              people, and risk rules.
            </p>
          </div>
        </section>

        <section className={css.controlSection} aria-labelledby="control-model-heading">
          <div className={css.sectionHeading}>
            <p className={css.sectionKicker}>Control model</p>
            <h2 id="control-model-heading">Portfolio visibility without portfolio custody.</h2>
            <p>
              The sponsor can underwrite the rollout. The portfolio company remains the authority
              owner. Gate sits where the consequence becomes real.
            </p>
          </div>
          <div className={css.controlGrid}>
            {CONTROL_LAYERS.map((layer, index) => (
              <article className={css.controlCard} key={layer.label}>
                <div className={css.cardIndex}>{String(index + 1).padStart(2, '0')}</div>
                <p className={css.cardLabel}>{layer.label}</p>
                <h3>{layer.title}</h3>
                <p>{layer.body}</p>
              </article>
            ))}
          </div>
          <div className={css.ownershipRail}>
            <div>
              <span>Sponsor may receive</span>
              <strong>Buyer-agreed coverage and implementation evidence</strong>
            </div>
            <div>
              <span>Portfolio company retains</span>
              <strong>Keys, policy, approvals, credentials, and detailed records</strong>
            </div>
          </div>
        </section>

        <section id="risk-lab" className={css.labSection} aria-labelledby="risk-lab-heading">
          <div className={css.labIntro}>
            <p className={css.sectionKicker}>Portfolio Action Risk Lab</p>
            <h2 id="risk-lab-heading">See the finance precheck before you discuss production.</h2>
            <p>
              Provision one throwaway observe-only key for Northstar Components, a fictional company
              consenting to this synthetic exercise. Then evaluate a vendor bank-detail change and a
              payment release against the existing finance prechecks.
            </p>
            <ul>
              <li>No ERP connection</li>
              <li>No real account or vendor data</li>
              <li>No money moved or blocked</li>
              <li>No production protection implied</li>
            </ul>
          </div>
          <PortfolioActionRiskLab />
        </section>

        <section className={css.pilotSection} aria-labelledby="pilot-heading">
          <div className={css.sectionHeading}>
            <p className={css.sectionKicker}>The first engagement</p>
            <h2 id="pilot-heading">One finance workflow. 90 days. $25K.</h2>
            <p>
              A fixed scope creates a real decision point: accept a completely mediated Gate design,
              keep observing, or stop. It does not require a portfolio-wide platform commitment.
            </p>
          </div>
          <div className={css.phaseGrid}>
            {PILOT_PHASES.map((phase) => (
              <article key={phase.number} className={css.phaseCard}>
                <div className={css.phaseTop}><span>{phase.number}</span><time>{phase.window}</time></div>
                <h3>{phase.title}</h3>
                <p>{phase.body}</p>
              </article>
            ))}
          </div>
          <div className={css.deliverables}>
            <div>
              <p className={css.cardLabel}>Buyer receives</p>
              <h3>A bounded implementation decision, not a promise of universal safety.</h3>
            </div>
            <ul>
              <li>One protected-workflow definition and path map</li>
              <li>Customer-pinned authority and evidence rule</li>
              <li>Observe-mode precheck findings and limitations</li>
              <li>Boundary acceptance plan and operating procedure</li>
            </ul>
          </div>
        </section>

        <section className={css.proofBoundary} aria-labelledby="proof-boundary-heading">
          <div>
            <p className={css.sectionKicker}>The claim boundary</p>
            <h2 id="proof-boundary-heading">Control the crossing. Keep the conclusion honest.</h2>
          </div>
          <div className={css.boundaryGrid}>
            <article>
              <span className={css.yesMark}>Gate can enforce</span>
              <h3>The customer&apos;s rule at a covered action boundary</h3>
              <p>
                Exact action, finite authority, required evidence, refusal, one-time admission state,
                and an action-bound record under the customer&apos;s pinned trust inputs.
              </p>
            </article>
            <article>
              <span className={css.noMark}>Gate does not establish</span>
              <h3>Truth, wisdom, legality, or a successful effect</h3>
              <p>
                Bank-detail correctness, payee identity, fraud absence, provider success, unmediated
                paths, investment performance, and legal or audit conclusions require separate evidence.
              </p>
            </article>
          </div>
          <a className={css.textLink} href="/security">Inspect the engineering and security boundary <span aria-hidden="true">→</span></a>
        </section>

        <section className={css.faqSection} aria-labelledby="faq-heading">
          <div className={css.sectionHeading}>
            <p className={css.sectionKicker}>Questions operating partners ask</p>
            <h2 id="faq-heading">What the portfolio model does and does not mean.</h2>
          </div>
          <div className={css.faqList}>
            {FAQ.map(({ question, answer }) => (
              <details key={question}>
                <summary>{question}</summary>
                <p>{answer}</p>
              </details>
            ))}
          </div>
        </section>

        <section className={css.finalCta} aria-labelledby="final-cta-heading">
          <p className={css.sectionKicker}>Start with a real boundary</p>
          <h2 id="final-cta-heading">Assess and design one portfolio-company finance boundary.</h2>
          <p>
            Bring the workflow, owner, executor path, current approval rule, and known bypasses. We will
            scope the smallest pilot that can produce a defensible yes or no.
          </p>
          <div className={css.heroActions}>
            <a className={css.primaryButtonLight} href="/pilot?v=fin">Scope the 90-day pilot</a>
            <a className={css.textLinkLight} href="mailto:team@emiliaprotocol.ai?subject=Portfolio%20finance%20workflow">Email the team</a>
          </div>
          <small>
            Customer deployment path only. EMILIA is not an insurer, auditor, investment adviser, or
            accredited certifier and does not make investment-safety claims.
          </small>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
