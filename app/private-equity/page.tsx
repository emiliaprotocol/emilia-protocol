// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import { headers } from 'next/headers';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import PortfolioActionRiskLab from './PortfolioActionRiskLab';
import PortfolioTrackedLink from './PortfolioTrackedLink';
import css from './private-equity.module.css';

const PAGE_URL = 'https://www.emiliaprotocol.ai/private-equity';
const PAGE_TITLE = 'Portfolio Authority Scan for Private Equity';
const PAGE_DESCRIPTION =
  'Map where AI can move money, change systems, expose data, or make other consequential moves '
  + 'inside a portfolio company, then choose the first action boundary to protect.';

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: '/private-equity' },
  keywords: [
    'agentic AI risk controls private equity',
    'portfolio authority control',
    'private equity portfolio AI governance',
    'portfolio company AI risk management',
    'AI agent payment controls',
    'vendor bank detail change control',
    'autonomous agent authorization',
    'private equity operating partner technology',
    'AI action inventory private equity',
    'portfolio company AI assessment',
    'high consequence AI actions',
  ],
  openGraph: {
    type: 'website',
    url: PAGE_URL,
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    images: [
      {
        url: '/private-equity/opengraph-image',
        width: 1200,
        height: 630,
        alt: 'An illustrative EMILIA Portfolio Authority Scan mapping consequential AI actions',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: PAGE_TITLE,
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
    question: 'What can a sponsor standardize across the portfolio?',
    answer:
      'A sponsor can standardize the boundary review, minimum control contract, evidence fields, rollout criteria, and payload-minimized reporting format. Each portfolio company still decides its authority rules and retains its keys, credentials, detailed approvals, and action records.',
  },
  {
    question: 'Does EMILIA issue a certificate for a portfolio company?',
    answer:
      'No. EMILIA can produce scoped verification results, conformance records, deployment assessments, assurance packages, and workpapers whose inputs and limitations travel with them. These are not an audit opinion, accredited certification, or proof that an organization or investment is safe.',
  },
  {
    question: 'What can an independent reviewer reproduce?',
    answer:
      'A reviewer can re-run supplied evidence packages under independently pinned keys, profiles, clocks, and input digests, then compare the result with the runtime claim. Re-performance can expose missing or inadmissible evidence and drift; it cannot recover live state that was never recorded or establish source truth.',
  },
  {
    question: 'What do we bring to a Portfolio Authority Scan?',
    answer:
      'Start with materials the company already has: repository or action inventories, MCP and OpenAPI manifests, workflow and approval documents, and governed system exports. We agree the intake, handling, supported formats, and company owner before materials move. This page is not a public file-upload portal.',
  },
  {
    question: 'What does the Portfolio Authority Scan return?',
    answer:
      'It returns a customer-reviewable, source-linked action register, owner questions, explicit blind spots, and a draft protection plan with one recommended Gate boundary to investigate first. It does not authorize an action, activate Gate, certify a deployment, or prove that every effect path is mediated. Buyer acceptance and a separately scoped Gate implementation are still required.',
  },
  {
    question: 'What does complete mediation mean?',
    answer:
      'Every path capable of producing the covered effect must cross Gate at the executor or system-of-record boundary. A sidecar, prompt filter, or voluntary agent call cannot constrain an alternate path that bypasses the deployed control.',
  },
  {
    question: 'Does the Portfolio Action Risk Lab move or block money?',
    answer:
      'No. It provisions a scoped observe-only sandbox key and evaluates fictional finance-action metadata. It does not connect to an ERP, change vendor data, release a payment, authorize production use, or provide production protection.',
  },
  {
    question: 'What is included in the first pilot?',
    answer:
      'One buyer-selected vendor bank-detail change or payment-release workflow, 90 days, and a fixed $25K scope. Work remains synthetic and read-only. The pilot ends with a buyer-owned go or no-go decision; any production Gate implementation is separately scoped after buyer acceptance.',
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
      about: [
        { '@type': 'Thing', name: 'Private equity portfolio operations' },
        { '@type': 'Thing', name: 'AI agent authorization controls' },
        { '@type': 'Thing', name: 'Finance operations controls' },
      ],
    },
    {
      '@type': 'Service',
      '@id': `${PAGE_URL}#service`,
      name: 'EMILIA Portfolio Authority Desk',
      serviceType: 'Portfolio-company action discovery, authority control, and technical assurance',
      url: PAGE_URL,
      provider: {
        '@type': 'Organization',
        name: 'EMILIA Protocol',
        url: 'https://www.emiliaprotocol.ai',
      },
      audience: {
        '@type': 'BusinessAudience',
        audienceType: 'Private equity operating partners and portfolio company technology, risk, finance, and operations leaders',
      },
      description: PAGE_DESCRIPTION,
      areaServed: 'Worldwide',
    },
    {
      '@type': 'BreadcrumbList',
      '@id': `${PAGE_URL}#breadcrumb`,
      itemListElement: [
        {
          '@type': 'ListItem',
          position: 1,
          name: 'Home',
          item: 'https://www.emiliaprotocol.ai/',
        },
        {
          '@type': 'ListItem',
          position: 2,
          name: 'Private Equity',
          item: PAGE_URL,
        },
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
    title: 'Map the company, choose the action',
    body: 'Run the Portfolio Authority Scan, review source-linked candidates with company owners, then select one vendor bank-detail change or payment-release path for the fixed pilot.',
  },
  {
    number: '02',
    window: 'Days 31-60',
    title: 'Prepare, then observe',
    body: 'Use Scan to prepare the customer-reviewable draft package, then run synthetic and buyer-approved read-only validation without changing production behavior.',
  },
  {
    number: '03',
    window: 'Days 61-90',
    title: 'Make a buyer-owned decision',
    body: 'Deliver the boundary design, acceptance evidence, limitations, and operating procedure. End with a buyer-owned go or no-go decision; any production Gate implementation is separately scoped.',
  },
] as const;

const SCAN_OUTPUTS = [
  {
    label: 'Action register',
    title: 'See where consequences can happen',
    body: 'A source-linked inventory groups candidate actions by consequence, affected system, current owner, and available evidence.',
  },
  {
    label: 'Owner questions',
    title: 'Give owners a short list, not a binder',
    body: 'Named company owners confirm, correct, or reject candidates. Missing sources, unknown paths, and unsupported formats stay visible as blind spots.',
  },
  {
    label: 'Draft protection plan',
    title: 'Know what to protect next',
    body: 'The reviewed register recommends one bounded action for Gate design, with its executor path, authority owner, evidence needs, and unresolved blockers.',
  },
] as const;

const SCAN_MATERIALS = [
  'Repository and action inventories',
  'MCP and OpenAPI manifests',
  'Workflow and approval documents',
  'Governed system exports',
] as const;

const CONSEQUENCE_LANES = [
  { label: 'Money and assets', detail: 'Payments, disbursements, and vendor banking changes' },
  { label: 'Identity and privilege', detail: 'Access, credentials, roles, and account changes' },
  { label: 'Systems and code', detail: 'Cloud, infrastructure, deployments, and production operations' },
  { label: 'Data and privacy', detail: 'Disclosure, export, sharing, and protected information' },
  { label: 'Regulated decisions', detail: 'Records, determinations, approvals, and case outcomes' },
  { label: 'External commitments', detail: 'Contracts, notices, submissions, and business promises' },
  { label: 'Physical operations', detail: 'Devices, logistics, facilities, and real-world actions' },
] as const;

const ENTRY_PATHS = [
  {
    number: '01',
    status: 'First step · scoped intake',
    name: 'Portfolio Authority Scan',
    audience: 'For one sponsor and one consenting portfolio company',
    body: 'Set up a buyer-approved company workspace, bring the materials already on hand, and map candidate high-consequence actions across seven operating lanes.',
    output: 'A source-linked action register, owner questions, explicit blind spots, and a draft protection plan with one recommended Gate boundary. No authority is created.',
    href: '/pilot?v=fin&source=private_equity',
    cta: 'Add and map a portfolio company',
    eventDetail: {
      event: 'pilot_scope_started',
      location: 'engagement_ladder',
      surface: 'protected_workflow_pilot',
    } as const,
  },
  {
    number: '02',
    status: `${PROTECTED_WORKFLOW_PILOT.workflowLabel} · ${PROTECTED_WORKFLOW_PILOT.durationLabel} · ${PROTECTED_WORKFLOW_PILOT.shortPriceLabel}`,
    name: 'Portfolio Authority Pilot',
    audience: 'For one sponsor and one consenting portfolio company',
    body: 'Take one reviewed finance action from the Scan, validate it in synthetic and buyer-approved read-only modes, and design the completely mediated customer-owned Gate boundary.',
    output: 'A path map, draft control package, authority and evidence rule, acceptance plan, limitations, and buyer-owned go or no-go decision.',
    href: '/pilot?v=fin&source=private_equity',
    cta: 'Protect one portfolio boundary',
    eventDetail: {
      event: 'pilot_scope_started',
      location: 'engagement_ladder',
      surface: 'protected_workflow_pilot',
    } as const,
  },
  {
    number: '03',
    status: 'Scoped after boundary acceptance',
    name: 'Portfolio Authority Program',
    audience: 'For a sponsor funding a repeatable rollout pattern',
    body: 'Deploy company-owned Gates by consenting portfolio company, operate the accepted boundaries, and add scoped assurance services without centralizing company keys, credentials, or raw action evidence.',
    output: 'Buyer-agreed coverage and control-operation evidence. It is explicitly not an investment-safety certificate.',
    href: 'mailto:team@emiliaprotocol.ai?subject=Portfolio%20Authority%20Program',
    cta: 'Discuss a portfolio rollout',
    eventDetail: {
      event: 'assurance_surface_opened',
      location: 'engagement_ladder',
      surface: 'portfolio_authority_program',
    } as const,
  },
] as const;

const ASSURANCE_MODULES = [
  {
    name: 'Open verification',
    status: 'Self-directed',
    body: 'Re-perform a supplied assurance package under your own pinned inputs with the open ep-assure procedure.',
    boundary: 'Tests what the supplied evidence supports. It does not establish source truth or deployment coverage.',
    href: '/assurance#open-verification',
    cta: 'Run the open procedure',
    surface: 'open_verification',
  },
  {
    name: 'Deployment Assurance',
    status: 'Scoped service',
    body: 'Review complete mediation, bypass routes, trust pins, replay state, failure behavior, retention, and active refusal probes for named boundaries.',
    boundary: 'A vendor or customer deployment assessment, not independent certification.',
    href: '/assurance',
    cta: 'Inspect Deployment Assurance',
    surface: 'deployment_assurance',
  },
  {
    name: 'Continuous Assurance',
    status: 'Scoped service',
    body: 'Build content-addressed evidence packages on an agreed cadence and re-perform claimed verdicts to name drift, refusals, and missing evidence.',
    boundary: 'The workpaper leaves an auditor or assurer conclusion blank by construction.',
    href: '/assurance',
    cta: 'Inspect Continuous Assurance',
    surface: 'continuous_assurance',
  },
  {
    name: 'Warranted Gate',
    status: 'Separate contract after baseline',
    body: 'A separately negotiated warranty may cover named Gate behavior at named enforcement points, for a named period and contractual limit.',
    boundary: 'It does not warrant investment performance, legal compliance, wisdom, source truth, or bypassing actions.',
    href: '/assurance',
    cta: 'Read the warranty boundary',
    surface: 'warranted_gate',
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
            <p className={css.eyebrow}>Portfolio Authority Scan</p>
            <h1 id="pe-hero-title">
              See what AI can change before it changes the company.
            </h1>
            <p className={css.heroLead}>
              Invite one consenting portfolio company and bring its existing materials. EMILIA maps
              where AI can move money, change access or infrastructure, expose data, alter regulated
              decisions, commit the business, or affect physical operations. The company chooses what
              to control.
            </p>
            <p className={css.boundaryStatement}>
              Scan prepares the decision; it does not grant authority or activate Gate. The company
              keeps its keys, approvals, and detailed evidence.
            </p>
            <div className={css.heroActions}>
              <PortfolioTrackedLink
                className={css.primaryButton}
                href="/pilot?v=fin&source=private_equity"
                eventDetail={{
                  event: 'pilot_scope_started',
                  location: 'hero',
                  surface: 'protected_workflow_pilot',
                }}
              >
                Map a portfolio company
              </PortfolioTrackedLink>
              <a className={css.textLink} href="#scan-workspace">
                See what the assessment returns <span aria-hidden="true">↓</span>
              </a>
            </div>
            <dl className={css.offerStrip} aria-label="Portfolio Authority Scan summary">
              <div><dt>Start</dt><dd>One company</dd></div>
              <div><dt>Coverage</dt><dd>Seven action lanes</dd></div>
              <div><dt>Output</dt><dd>Source-linked map</dd></div>
              <div><dt>Next move</dt><dd>One Gate boundary</dd></div>
            </dl>
          </div>

          <div className={css.heroVisual} aria-label="Illustrative Portfolio Authority Scan workspace">
            <div className={css.diagramHeader}>
              <span>Illustrative company workspace</span>
              <span className={css.statusDot}>No files submitted here</span>
            </div>
            <div className={css.scanCompany}>
              <div>
                <span className={css.actionLabel}>Portfolio company</span>
                <strong>Northstar Components</strong>
              </div>
              <span>Example only</span>
            </div>
            <div className={css.scanFindings}>
              <article>
                <span>Money</span>
                <div>
                  <strong>Change vendor bank details</strong>
                  <small>AP workflow · payments API</small>
                </div>
                <b>Review</b>
              </article>
              <article>
                <span>Identity</span>
                <div>
                  <strong>Grant production administrator access</strong>
                  <small>Access policy · cloud action inventory</small>
                </div>
                <b>Review</b>
              </article>
              <article>
                <span>Data</span>
                <div>
                  <strong>Export customer records</strong>
                  <small>Runbook · OpenAPI operation</small>
                </div>
                <b>Review</b>
              </article>
            </div>
            <div className={css.recommendedBoundary}>
              <span className={css.actionLabel}>Recommended first boundary</span>
              <div>
                <strong>Vendor bank-detail change</strong>
                <small>Owner confirmation and bypass review required</small>
              </div>
            </div>
            <p className={css.diagramNote}>
              Every candidate stays linked to its source. Unknown paths and missing evidence remain
              visible instead of being converted into a confident score.
            </p>
          </div>
        </section>

        <section className={css.introBand} aria-labelledby="why-portfolio-heading">
          <p className={css.sectionKicker}>One company in. One decision out.</p>
          <div>
            <h2 id="why-portfolio-heading">Stop asking portfolio teams to inventory AI risk from memory.</h2>
            <p>
              The Scan turns existing technical and operating materials into a review queue that a CFO,
              CTO, security leader, or business owner can correct. The result is not another broad risk
              score. It is a practical map from evidence to action to the first control decision.
            </p>
          </div>
        </section>

        <section id="scan-workspace" className={css.controlSection} aria-labelledby="control-model-heading">
          <div className={css.sectionHeading}>
            <p className={css.sectionKicker}>Portfolio Authority Desk</p>
            <h2 id="control-model-heading">Bring the materials already sitting inside the company.</h2>
            <p>
              We agree a buyer-approved intake and handling plan with the portfolio company before any
              material moves. No public file upload happens on this page, and we do not pretend every
              arbitrary format is already supported.
            </p>
          </div>
          <div className={css.materialPanel}>
            <div className={css.materialLead}>
              <p className={css.cardLabel}>Starting inputs</p>
              <h3>No blank-page questionnaire.</h3>
              <p>Start with supported, governed evidence the company already knows how to produce.</p>
            </div>
            <ul>
              {SCAN_MATERIALS.map((material) => <li key={material}>{material}</li>)}
            </ul>
          </div>
          <div className={css.laneMap}>
            <div className={css.laneHeading}>
              <p className={css.cardLabel}>Company-wide consequence map</p>
              <h3>Look across the business, not just the finance stack.</h3>
            </div>
            <div className={css.laneGrid}>
              {CONSEQUENCE_LANES.map((lane) => (
                <article key={lane.label}>
                  <span>{lane.label}</span>
                  <p>{lane.detail}</p>
                </article>
              ))}
            </div>
          </div>
          <div className={css.controlGrid}>
            {SCAN_OUTPUTS.map((output, index) => (
              <article className={css.controlCard} key={output.label}>
                <div className={css.cardIndex}>{String(index + 1).padStart(2, '0')}</div>
                <p className={css.cardLabel}>{output.label}</p>
                <h3>{output.title}</h3>
                <p>{output.body}</p>
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

        <section className={css.entrySection} aria-labelledby="entry-heading">
          <div className={css.sectionHeading}>
            <p className={css.sectionKicker}>The engagement path</p>
            <h2 id="entry-heading">Scan the company. Protect one boundary. Then earn the rollout.</h2>
            <p>
              The assessment makes the first control decision easier. The pilot has one fixed public
              finance scope. A portfolio program begins only after a consenting company accepts its
              boundary and operating model.
            </p>
          </div>
          <div className={css.entryGrid}>
            {ENTRY_PATHS.map((entry) => (
              <article className={css.entryCard} key={entry.number}>
                <div className={css.entryTop}>
                  <span>{entry.number}</span>
                  <span>{entry.status}</span>
                </div>
                <p className={css.cardLabel}>{entry.audience}</p>
                <h3>{entry.name}</h3>
                <p>{entry.body}</p>
                <div className={css.outputBox}>
                  <span>Evidence output</span>
                  <p>{entry.output}</p>
                </div>
                <PortfolioTrackedLink
                  className={css.entryLink}
                  href={entry.href}
                  eventDetail={entry.eventDetail}
                >
                  {entry.cta} <span aria-hidden="true">→</span>
                </PortfolioTrackedLink>
              </article>
            ))}
          </div>
        </section>

        <section className={css.assuranceSection} aria-labelledby="assurance-ladder-heading">
          <div className={css.assuranceIntro}>
            <p className={css.sectionKicker}>Control plus assurance</p>
            <h2 id="assurance-ladder-heading">Every evidence surface, without a black-box certificate.</h2>
            <p>
              Gate controls the crossing. The Assurance Plane can verify, assess, re-perform, and package
              the resulting evidence. A customer-appointed auditor, underwriter, regulator, or other
              authorized reviewer keeps its own conclusion.
            </p>
            <p className={css.evidenceDistinction}>
              Posture and coverage evidence are not action admission. Admission evidence is not provider
              outcome or real-world effect proof. Each claim keeps its own evidence boundary.
            </p>
            <div className={css.assuranceActions}>
              <a
                className={css.primaryButton}
                href="/examples/portfolio-authority/payment-release-boundary.example.json"
                download
              >
                Download the boundary example
              </a>
              <a
                className={css.textLink}
                href="/schemas/portfolio-authority-boundary-example.v1.schema.json"
              >
                View the v1 schema
              </a>
              <a className={css.textLink} href="/assurance">Inspect the Assurance Plane</a>
            </div>
            <p className={css.artifactMeta}>
              Schema v1 · canonical SHA-256 digest · covered and example uncovered paths · fail-closed
              unknown-ID requirements. The file is illustrative and non-authoritative.
            </p>
          </div>
          <div className={css.assuranceModules}>
            {ASSURANCE_MODULES.map((module) => (
              <article key={module.name}>
                <div className={css.moduleTop}>
                  <h3>{module.name}</h3>
                  <span>{module.status}</span>
                </div>
                <p>{module.body}</p>
                <small>{module.boundary}</small>
                <PortfolioTrackedLink
                  href={module.href}
                  eventDetail={{
                    event: 'assurance_surface_opened',
                    location: 'engagement_ladder',
                    surface: module.surface,
                  }}
                >
                  {module.cta} <span aria-hidden="true">→</span>
                </PortfolioTrackedLink>
              </article>
            ))}
          </div>
          <div className={css.certificateBoundary} role="note">
            <strong>Evidence, not a certificate.</strong>
            <span>
              EMILIA does not currently operate a public certification scheme and does not issue an audit
              opinion, accredited certification, insurance conclusion, or investment-safety rating.
            </span>
          </div>
        </section>

        <section id="risk-lab" className={css.labSection} aria-labelledby="risk-lab-heading">
          <div className={css.labIntro}>
            <p className={css.sectionKicker}>Synthetic proof, not company intake</p>
            <h2 id="risk-lab-heading">See one finance precheck after you understand the Scan.</h2>
            <p>
              The Portfolio Action Risk Lab is a public demonstration, not the assessment. Provision one
              scoped observe-only key for Northstar Components, a fictional company consenting to this
              synthetic exercise. Keep one payment-release boundary fixed, then compare a single-signoff
              result, a dual-signoff result, and a hard refusal.
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
              <li>Payload-minimized sponsor evidence design</li>
            </ul>
          </div>
        </section>

        <section className={css.proofBoundary} aria-labelledby="proof-boundary-heading">
          <div>
            <p className={css.sectionKicker}>The claim boundary</p>
            <h2 id="proof-boundary-heading">Control the crossing. Keep the conclusion honest.</h2>
            <p className={css.proofLead}>
              On completely mediated covered paths, the exact action must arrive with accepted
              authority and required evidence before it can enter the consequential provider.
            </p>
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
          <div className={css.resourceRail} aria-label="Supporting evidence routes">
            <a href="/assurance"><span>Assurance Plane</span><strong>Re-performance and scoped evidence</strong></a>
            <a href="/auditors"><span>Auditor surface</span><strong>Reproducible workpapers</strong></a>
            <a href="/protocol"><span>Open Protocol</span><strong>Formats, verification, and conformance</strong></a>
            <a href="/pricing"><span>Commercial path</span><strong>Public pilot and deployment scope</strong></a>
          </div>
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
          <p className={css.sectionKicker}>Start with one portfolio company</p>
          <h2 id="final-cta-heading">Turn scattered company evidence into the first control decision.</h2>
          <p>
            Tell us which consenting company you want to assess. We will agree the workspace, supported
            materials, company owner, and the smallest scan-to-pilot scope that can produce a defensible
            next step.
          </p>
          <div className={css.heroActions}>
            <PortfolioTrackedLink
              className={css.primaryButtonLight}
              href="/pilot?v=fin&source=private_equity"
              eventDetail={{
                event: 'pilot_scope_started',
                location: 'final_cta',
                surface: 'protected_workflow_pilot',
              }}
            >
              Start a Portfolio Authority Scan
            </PortfolioTrackedLink>
            <PortfolioTrackedLink
              className={css.textLinkLight}
              href="mailto:team@emiliaprotocol.ai?subject=Portfolio%20Authority%20Scan"
              eventDetail={{ event: 'team_email_started', location: 'final_cta' }}
            >
              Email the team
            </PortfolioTrackedLink>
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
