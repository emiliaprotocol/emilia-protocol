// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import { headers } from 'next/headers';
import Image from 'next/image';
import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import CyberAuthorityDrill from './CyberAuthorityDrill';
import css from './cyber-authority.module.css';

const PAGE_URL = 'https://www.emiliaprotocol.ai/cyber-authority';
const PAGE_TITLE = 'Authority Controls for AI Security Actions | EMILIA';
const PAGE_DESCRIPTION =
  'On completely mediated credential-owning paths, EMILIA controls exact administrative actions proposed by AI defenders, refusing wider or replayed requests and preserving explicit uncertainty.';

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: '/cyber-authority' },
  keywords: [
    'AI security action authorization',
    'automated remediation controls',
    'AI SOC governance',
    'AI agent cybersecurity',
    'SOAR action authorization',
    'MSSP AI governance',
    'critical infrastructure AI security',
    'exact action authorization',
    'AI defender authority',
  ],
  openGraph: {
    type: 'website',
    url: PAGE_URL,
    title: 'Let AI defend the system. Keep the authority to change it.',
    description: PAGE_DESCRIPTION,
    images: [
      {
        url: '/cyber-authority/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'An AI defender crossing an EMILIA exact-action authority boundary before an administrative system',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Authority for AI Defenders | EMILIA',
    description: PAGE_DESCRIPTION,
    images: ['/cyber-authority/opengraph-image'],
  },
  robots: { index: true, follow: true },
};

const FAQ = [
  {
    question: 'Does EMILIA detect or stop cyberattacks?',
    answer:
      'No. EMILIA is not an EDR, SIEM, SOAR, vulnerability scanner, or threat-detection model. It controls selected consequential actions on completely mediated paths after a defender or security product proposes them.',
  },
  {
    question: 'What security actions can EMILIA control?',
    answer:
      'A pilot starts with one customer-selected administrative mutation, such as disabling one identity, isolating one endpoint, terminating one privileged session, or applying one bounded network rule. Each action and executor requires a separately reviewed boundary.',
  },
  {
    question: 'What happens when a provider result is uncertain?',
    answer:
      'If the provider may have received an admitted action but its effect cannot be established, Gate treats the outcome as INDETERMINATE, keeps the authority consumed, and refuses blind retry until authenticated action-bound reconciliation.',
  },
  {
    question: 'Can an agent bypass EMILIA Gate?',
    answer:
      'Gate prevents only on completely mediated covered paths. Alternate credentials, direct provider calls, unprotected tools, and other executor routes remain outside coverage until they are removed or separately mediated.',
  },
  {
    question: 'Who is the initial target buyer for this solution?',
    answer:
      'We are inviting cybersecurity vendors, MSSPs, SOAR or EDR platforms, and critical-infrastructure integrators already deploying automated remediation. EMILIA adds a customer-owned exact-action authority boundary; it does not replace the customer\'s security product.',
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
      mainEntity: { '@id': `${PAGE_URL}#service` },
    },
    {
      '@type': 'Service',
      '@id': `${PAGE_URL}#service`,
      name: 'EMILIA Authority for AI Defenders',
      serviceType: 'Exact-action authority control for automated security remediation',
      provider: { '@id': 'https://www.emiliaprotocol.ai/#organization' },
      audience: {
        '@type': 'BusinessAudience',
        audienceType: 'Cybersecurity vendors, MSSPs, security operations platforms, and critical-infrastructure integrators',
      },
      description: PAGE_DESCRIPTION,
      areaServed: 'Worldwide',
    },
    {
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://www.emiliaprotocol.ai/' },
        { '@type': 'ListItem', position: 2, name: 'Solutions', item: 'https://www.emiliaprotocol.ai/use-cases' },
        { '@type': 'ListItem', position: 3, name: 'Authority for AI Defenders', item: PAGE_URL },
      ],
    },
    {
      '@type': 'FAQPage',
      mainEntity: FAQ.map(({ question, answer }) => ({
        '@type': 'Question',
        name: question,
        acceptedAnswer: { '@type': 'Answer', text: answer },
      })),
    },
  ],
};

const STRUCTURED_DATA_JSON = JSON.stringify(STRUCTURED_DATA).replace(/</g, '\\u003c');

const BUYERS = [
  {
    label: 'Security products',
    title: 'SOAR, EDR, identity, and cloud-security vendors',
    body: 'Keep autonomous remediation inside the customer mandate while your product detects, investigates, and proposes the response.',
  },
  {
    label: 'Security operators',
    title: 'MSSPs and agentic SOC teams',
    body: 'Let an AI defender act at machine speed without turning a standing credential into open-ended authority.',
  },
  {
    label: 'Delivery channels',
    title: 'OT and critical-infrastructure integrators',
    body: 'Add a bounded, customer-owned consequence control to existing defensive deployments without replacing the security or safety stack.',
  },
] as const;

const SECTOR_ACTIONS = [
  {
    sector: 'Enterprise security',
    action: 'Disable one compromised service identity',
    outside: 'Not threat detection or incident attribution',
  },
  {
    sector: 'Hospitals',
    action: 'Terminate one privileged administrative session',
    outside: 'Not a clinical decision or care-system safety claim',
  },
  {
    sector: 'Public power',
    action: 'Revoke one remote IT access path',
    outside: 'Not grid switching or operational reliability',
  },
  {
    sector: 'Water systems',
    action: 'Apply one bounded defensive network rule',
    outside: 'Not chemical dosing or safety-instrumented control',
  },
] as const;

const STEPS = [
  {
    number: '01',
    title: 'Map one action surface',
    body: 'Use the local scanner and operator interviews to identify the mutating API, credential owner, alternate paths, and evidence blind spots.',
  },
  {
    number: '02',
    title: 'Pin the customer mandate',
    body: 'The customer defines the exact operation, target, limits, evidence, expiry, and exception path. Gate refuses a wider action on the covered path.',
  },
  {
    number: '03',
    title: 'Place Gate beside the credential',
    body: 'The agent proposes the action without holding the provider credential. Gate checks the frozen action before the adapter enters the provider.',
  },
  {
    number: '04',
    title: 'Pressure-test refusal',
    body: 'Demonstrate exact admission, target substitution refusal, one-time replay refusal, and indeterminate outcome handling.',
  },
  {
    number: '05',
    title: 'Deliver re-performable evidence',
    body: 'Return the path map, accepted boundary, limitations, test record, and action-bound evidence package for buyer review.',
  },
] as const;

export default async function CyberAuthorityPage(): Promise<React.ReactElement> {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <div className={css.page}>
      <script
        type="application/ld+json"
        nonce={nonce}
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}
      />
      <SiteNav activePage="solutions" />

      <main>
        <section className={css.hero} aria-labelledby="cyber-authority-title">
          <div className={css.shell}>
            <div className={css.heroGrid}>
              <div className={css.heroCopy}>
                <p className={css.eyebrow}>EMILIA Gate for automated security actions</p>
                <h1 id="cyber-authority-title">Let AI defend the system. Keep the authority to change it.</h1>
                <p className={css.heroLead}>
                  Your security product detects the threat and proposes the response. EMILIA controls
                  the exact administrative action at the credential-owning boundary before it can
                  change the customer&apos;s system.
                </p>
                <p className={css.heroRule}>
                  On a completely mediated credential path: one covered provider attempt per accepted
                  authorization. Outside the mandate: refuse. Outcome unknown: stop and reconcile.
                </p>
                <div className={css.heroActions}>
                  <a className={css.primaryButton} href="#authority-drill">Run the authority drill</a>
                  <Link className={css.secondaryButton} href="/pilot?v=other">Scope one protected action</Link>
                </div>
                <p className={css.heroNote}>
                  Built for security vendors, MSSPs, SOC platforms, and integrators. It is not a threat detector.
                </p>
              </div>

              <figure className={css.storyGraphic}>
                <p className={css.storyConcept}>Concept illustration · completely mediated credential path</p>
                <div className={css.storyImageFrame}>
                  <Image
                    src="/cyber-authority/authority-for-ai-defenders.webp"
                    width={2720}
                    height={1536}
                    sizes="(max-width: 980px) 90vw, 48vw"
                    alt="A friendly AI brings a permission card to EMILIA Gate before one action reaches a server, where a receipt records the decision"
                    loading="eager"
                  />
                </div>
                <figcaption>
                  <div className={css.storySteps}>
                    <div>
                      <span>1</span>
                      <p><strong>AI asks</strong><small>Disable this one work account.</small></p>
                    </div>
                    <div>
                      <span>2</span>
                      <p><strong>EMILIA checks</strong><small>Exact action. Exact target. One permission.</small></p>
                    </div>
                    <div>
                      <span>3</span>
                      <p><strong>The door answers</strong><small>Admit, refuse, or stop and check.</small></p>
                    </div>
                  </div>
                  <p className={css.storyReceipt}>
                    <span>Decision receipt</span>
                    What was asked. What EMILIA decided. What is actually known.
                  </p>
                </figcaption>
              </figure>
            </div>
          </div>
        </section>

        <section className={css.context} aria-labelledby="context-title">
          <div className={`${css.shell} ${css.contextGrid}`}>
            <div>
              <p className={css.eyebrow}>The missing control</p>
              <h2 id="context-title">A valid credential does not mean this exact response was authorized.</h2>
            </div>
            <div className={css.contextCopy}>
              <p>
                Cyber-capable AI is being asked to investigate and remediate at machine speed. The
                hard question arrives after detection: may this agent disable this identity, isolate
                this host, or change this rule now?
              </p>
              <p>
                IAM identifies the workload. Security products decide what to propose. EMILIA gives
                the customer a separate consequence boundary where finite authority survives outside
                the agent process and wider work fails closed.
              </p>
              <div className={css.sourceLinks}>
                <a href="https://openai.com/collective-cyberdefense/" target="_blank" rel="noopener noreferrer">OpenAI: Collective Cyber Defense ↗</a>
                <a href="https://www.ncsc.gov.uk/news/the-ai-shift-in-cyber-risk-why-leaders-must-act-now" target="_blank" rel="noopener noreferrer">Five Eyes agencies: the AI shift in cyber risk ↗</a>
              </div>
            </div>
          </div>
        </section>

        <section className={css.buyers} aria-labelledby="buyers-title">
          <div className={css.shell}>
            <div className={css.sectionHeading}>
              <p className={css.eyebrow}>Who we are inviting</p>
              <h2 id="buyers-title">Start with teams already putting AI defenders into customer environments.</h2>
              <p>EMILIA is an authority component inside their deployment, not a replacement SOC or security platform.</p>
            </div>
            <div className={css.buyerGrid}>
              {BUYERS.map((buyer) => (
                <article key={buyer.label} className={css.buyerCard}>
                  <span>{buyer.label}</span>
                  <h3>{buyer.title}</h3>
                  <p>{buyer.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="authority-drill" className={css.drillSection} aria-labelledby="drill-title">
          <div className={css.shell}>
            <div className={css.sectionHeading}>
              <p className={css.eyebrow}>Interactive product story</p>
              <h2 id="drill-title">Pressure-test one defensive action before it reaches the provider.</h2>
              <p>
                This browser-only simulation changes no system. It shows the four control states a
                real pilot must demonstrate at a completely mediated credential boundary.
              </p>
            </div>
            <CyberAuthorityDrill />
          </div>
        </section>

        <section className={css.sectors} aria-labelledby="sectors-title">
          <div className={css.shell}>
            <div className={css.sectionHeading}>
              <p className={css.eyebrow}>Start narrow in every sector</p>
              <h2 id="sectors-title">Protect an administrative action before touching a safety-critical one.</h2>
              <p>Each row is a separate deployment profile, with its own customer mandate, executor, and bypass review.</p>
            </div>
            <div className={css.sectorTable} role="table" aria-label="Example first actions and excluded claims by sector">
              <div className={css.sectorHead} role="row">
                <span role="columnheader">Environment</span>
                <span role="columnheader">Credible first action</span>
                <span role="columnheader">Outside the claim</span>
              </div>
              {SECTOR_ACTIONS.map((item) => (
                <div className={css.sectorRow} role="row" key={item.sector}>
                  <strong role="cell">{item.sector}</strong>
                  <span role="cell">{item.action}</span>
                  <small role="cell">{item.outside}</small>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className={css.method} aria-labelledby="method-title">
          <div className={css.shell}>
            <div className={css.methodIntro}>
              <p className={css.eyebrow}>One Consequential Action Drill</p>
              <h2 id="method-title">One action. One executor. Four hostile conditions. One honest boundary report.</h2>
              <p>
                Begin with a free 45-minute Authority Boundary Review. If the path is suitable, the
                existing {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} protected-workflow pilot turns it
                into a buyer-reviewed control design and evidence package. Production activation is
                separately scoped after acceptance.
              </p>
              <div className={css.heroActions}>
                <Link className={css.primaryButton} href="/pilot?v=other">Request the boundary review</Link>
                <Link className={css.secondaryButton} href="/host">See the local Gate deployment</Link>
              </div>
            </div>
            <ol className={css.steps}>
              {STEPS.map((step) => (
                <li key={step.number}>
                  <span>{step.number}</span>
                  <div><strong>{step.title}</strong><p>{step.body}</p></div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className={css.boundary} aria-labelledby="boundary-title">
          <div className={css.shell}>
            <div className={css.boundaryGrid}>
              <div>
                <p className={css.eyebrow}>The honest boundary</p>
                <h2 id="boundary-title">EMILIA controls covered consequences. It does not decide what the threat is.</h2>
              </div>
              <div className={css.boundaryLists}>
                <div>
                  <strong>What Gate can establish</strong>
                  <ul>
                    <li>The exact proposed action matched accepted customer authority.</li>
                    <li>The admitted authority was reserved and consumed once.</li>
                    <li>A wider, stale, missing, or replayed action was refused before provider entry.</li>
                    <li>An uncertain provider result remained explicit instead of triggering blind retry.</li>
                  </ul>
                </div>
                <div>
                  <strong>What remains outside</strong>
                  <ul>
                    <li>Threat detection, attribution, exploit prevention, or incident correctness.</li>
                    <li>Any credential or executor path that bypasses the deployed boundary.</li>
                    <li>Whether an authorized response was wise, safe, lawful, or clinically correct.</li>
                    <li>Physical effect or provider success without authenticated outcome evidence.</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className={css.faq} aria-labelledby="faq-title">
          <div className={css.shell}>
            <div className={css.sectionHeading}>
              <p className={css.eyebrow}>Buyer questions</p>
              <h2 id="faq-title">Scope before slogans.</h2>
            </div>
            <div className={css.faqGrid}>
              {FAQ.map(({ question, answer }) => (
                <details key={question}>
                  <summary>{question}</summary>
                  <p>{answer}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        <section className={css.finalCta} aria-labelledby="final-cta-title">
          <div className={css.shell}>
            <p className={css.eyebrow}>Bring one real action</p>
            <h2 id="final-cta-title">Your AI defender can move fast without receiving open-ended authority.</h2>
            <p>We will map the boundary, name the bypasses, and pressure-test the refusal path before production reliance.</p>
            <Link className={css.lightButton} href="/pilot?v=other">Scope one protected action</Link>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
