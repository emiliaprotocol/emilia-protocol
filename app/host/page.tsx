// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import { headers } from 'next/headers';
import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import styles from './host.module.css';

export const metadata: Metadata = {
  title: 'AI Agent Firewall at the Credential Boundary | EMILIA',
  description:
    'EMILIA Host puts exact-action authority checks beside provider credentials, protecting activated HTTP and MCP paths with EMILIA Gate before provider entry.',
  alternates: { canonical: '/host' },
  keywords: [
    'AI agent firewall',
    'consequence firewall',
    'AI agent authorization',
    'MCP security',
    'HTTP agent security',
    'credential boundary',
  ],
  openGraph: {
    title: 'Put the consequence firewall where the credentials live.',
    description:
      'EMILIA Host is the local deployment form of Gate for activated HTTP and MCP paths at the credential-owning provider boundary.',
    url: 'https://www.emiliaprotocol.ai/host',
    type: 'website',
    images: ['/og-sequence.jpg'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Host: Gate beside the provider credentials',
    description:
      'Verify exact customer authority before a covered agent action can enter the provider path.',
    images: ['/og-sequence.jpg'],
  },
};

const FAQ = [
  {
    q: 'What is EMILIA Host?',
    a: 'EMILIA Host is the private, local deployment form of EMILIA Gate. It places Gate beside the credentials and adapters that can enter a provider path, then requires exact customer authority for each activated covered action.',
  },
  {
    q: 'Is EMILIA Host an AI agent firewall?',
    a: 'It is a consequence firewall for AI agents, but it is not a prompt or model classifier. Host verifies exact customer authority at the credential-owning provider boundary. It does not score whether a prompt looks risky.',
  },
  {
    q: 'Does Host protect every action on a machine?',
    a: 'No. The prevention claim applies only to activated covered paths that must pass through Host. Alternate credentials, direct provider calls, and unmediated executors remain outside the boundary until they are separately removed or mediated.',
  },
  {
    q: 'What happens when authority is missing or the provider result is uncertain?',
    a: 'Before provider entry, missing or mismatched authority returns a structured refusal such as EMILIA_AUTHORITY_REQUIRED. If provider entry occurred but the outcome cannot be established, Host records INDETERMINATE and refuses blind retry until authenticated reconciliation.',
  },
  {
    q: 'Can Scan configure Host automatically?',
    a: 'No. Scan can propose visible action boundaries and blind spots. The customer must review that proposal, define the authority, and approve the activated Host deployment. Scan does not automatically activate Host.',
  },
] as const;

const PRODUCT_JSONLD = {
  '@context': 'https://schema.org',
  '@type': ['SoftwareApplication', 'Product'],
  '@id': 'https://www.emiliaprotocol.ai/host#product',
  name: 'EMILIA Host',
  alternateName: 'EMILIA Gate local consequence firewall',
  url: 'https://www.emiliaprotocol.ai/host',
  applicationCategory: 'SecurityApplication',
  applicationSubCategory: 'AI agent consequence firewall',
  operatingSystem: 'Customer-controlled local environment',
  description:
    'The private local deployment form of EMILIA Gate for activated covered HTTP and MCP paths at a credential-owning provider boundary. Current availability is an HTTP local service alpha, HTTP and MCP SDK protection, and governed pilots.',
  brand: { '@type': 'Brand', name: 'EMILIA' },
  manufacturer: {
    '@type': 'Organization',
    name: 'EMILIA Protocol, Inc.',
    url: 'https://www.emiliaprotocol.ai',
  },
  isRelatedTo: {
    '@type': 'SoftwareApplication',
    name: 'EMILIA Gate',
    url: 'https://www.emiliaprotocol.ai/gate',
  },
  featureList: [
    'Exact-action authority checks before covered provider entry',
    'Local HTTP service alpha over an owner-permissioned Unix socket',
    'HTTP and MCP SDK protection',
    'Structured refusal when authority is absent or mismatched',
    'Blind-retry refusal after an indeterminate provider outcome',
    'Customer-pinned deployment configuration for governed pilots',
  ],
  releaseNotes:
    'Private alpha for governed pilots. This page does not represent general availability, an appliance, or complete mediation of unconfigured paths.',
};

const FAQ_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map(({ q, a }) => ({
    '@type': 'Question',
    name: q,
    acceptedAnswer: { '@type': 'Answer', text: a },
  })),
};

const STRUCTURED_DATA_JSON = JSON.stringify({
  '@context': 'https://schema.org',
  '@graph': [PRODUCT_JSONLD, FAQ_JSONLD],
}).replace(/</g, '\\u003c');

const OUTCOMES = [
  {
    state: 'REFUSED',
    tone: 'red',
    title: 'No accepted authority',
    body: 'Host returns a structured challenge or refusal before the covered provider adapter is entered.',
    proof: 'Provider entry: no',
  },
  {
    state: 'ADMITTED',
    tone: 'green',
    title: 'Exact authority accepted',
    body: 'Gate reserves the accepted authority, then permits one covered provider attempt for that operation.',
    proof: 'Provider success: not implied',
  },
  {
    state: 'INDETERMINATE',
    tone: 'gold',
    title: 'Provider outcome unknown',
    body: 'The authority remains consumed and blind retry stays closed until authenticated, action-bound reconciliation.',
    proof: 'External effect: unresolved',
  },
] as const;

const DEPLOYMENT_FORMS = [
  {
    label: 'HTTP local service alpha',
    detail:
      'HTTP over an owner-permissioned Unix socket for one governed local boundary. It is not a general HTTP reverse proxy; only the Host-side adapter holds the provider credential.',
    status: 'Private alpha',
  },
  {
    label: 'HTTP and MCP SDK protection',
    detail:
      'Wrap a credential-owning handler or MCP tool so exact request fields are frozen and checked before the real executor is entered.',
    status: 'Private alpha',
  },
  {
    label: 'Governed pilots',
    detail:
      'Customer-reviewed activation, bounded action coverage, explicit bypass review, durable state, and deployment evidence for one selected consequence path.',
    status: 'Available to scope',
  },
] as const;

export default async function HostPage(): Promise<React.ReactElement> {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <div className={styles.page}>
      <script
        type="application/ld+json"
        nonce={nonce}
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: STRUCTURED_DATA_JSON }}
      />
      <SiteNav activePage="host" />

      <main>
        <section className={styles.hero} aria-labelledby="host-title">
          <div className={styles.shell}>
            <div className={styles.heroGrid}>
              <div className={styles.heroCopy}>
                <div className={styles.eyebrow}>EMILIA Gate / local deployment / private alpha</div>
                <h1 id="host-title">Put the consequence firewall where the credentials live.</h1>
                <p className={styles.heroLead}>
                  Your agent can propose the work. EMILIA Host keeps the provider credential beside
                  Gate and checks the customer&apos;s exact authority before an activated covered HTTP
                  or MCP action can enter the provider path.
                </p>
                <p className={styles.heroPlain}>
                  In the Host deployment pattern, the agent never receives the provider credential.
                  No accepted authority and required evidence, no covered provider entry.
                </p>
                <div className={styles.actions}>
                  <Link className={styles.primary} href="/pilot?v=host">Scope a Host pilot</Link>
                  <Link className={styles.secondary} href="/gate">See EMILIA Gate</Link>
                </div>
                <p className={styles.availability}>
                  Current surface: HTTP local service alpha, HTTP and MCP SDK protection, and governed pilots.
                </p>
              </div>

              <div className={styles.heroVisual} aria-label="Agent request reaches EMILIA Host before the credential-owning provider adapter">
                <div className={styles.visualHeader}>
                  <span>Credential boundary</span>
                  <span className={styles.alphaDot}>Private alpha</span>
                </div>
                <div className={styles.visualBody}>
                  <div className={styles.agentNode}>
                    <span>Agent</span>
                    <strong>POST /vendor/change</strong>
                    <small>No provider credential</small>
                  </div>
                  <div className={styles.arrow} aria-hidden="true">↓</div>
                  <div className={styles.hostNode}>
                    <div className={styles.hostNodeTop}>
                      <span>EMILIA HOST</span>
                      <strong>GATE INSIDE</strong>
                    </div>
                    <div className={styles.checkLine}><span>01</span> Freeze exact action</div>
                    <div className={styles.checkLine}><span>02</span> Verify customer authority</div>
                    <div className={styles.checkLine}><span>03</span> Reserve before provider entry</div>
                    <div className={styles.refusalLine}>
                      <code>EMILIA_AUTHORITY_REQUIRED</code>
                      <span>or one admitted attempt</span>
                    </div>
                  </div>
                  <div className={styles.arrow} aria-hidden="true">↓</div>
                  <div className={styles.providerNode}>
                    <span>Credential-owning adapter</span>
                    <strong>Provider / system of record</strong>
                    <small>Entered only after Gate admits the exact action</small>
                  </div>
                </div>
              </div>
            </div>

            <ul className={styles.statusStrip} aria-label="EMILIA Host current posture">
              <li><strong>LOCAL</strong><span>Runs beside the credential</span></li>
              <li><strong>EXACT</strong><span>Checks action-bound authority</span></li>
              <li><strong>CLOSED</strong><span>Refuses missing or mismatched authority</span></li>
              <li><strong>BOUNDED</strong><span>Only activated covered paths</span></li>
            </ul>
          </div>
        </section>

        <section className={styles.problem} aria-labelledby="problem-title">
          <div className={`${styles.shell} ${styles.twoColumn}`}>
            <div>
              <div className={styles.eyebrow}>The security gap</div>
              <h2 id="problem-title">The agent&apos;s credential can outlive the decision that justified its work.</h2>
            </div>
            <div className={styles.problemCopy}>
              <p>
                IAM can show which workload has access. A prompt filter can flag suspicious text.
                Neither establishes that this exact bank-detail change, production deploy, data
                export, or permission grant fits the owner&apos;s finite mandate now.
              </p>
              <p>
                Host is an AI agent firewall at the consequence boundary. It is not a prompt or model classifier.
                It verifies exact customer authority at the credential-owning provider boundary,
                immediately before the covered adapter can act.
              </p>
            </div>
          </div>
        </section>

        <section className={styles.flowSection} aria-labelledby="flow-title">
          <div className={styles.shell}>
            <div className={styles.sectionHeading}>
              <div className={styles.eyebrow}>One local crossing</div>
              <h2 id="flow-title">The request is easy to understand. The boundary is hard to fake.</h2>
              <p>
                Host keeps proposal, authority, provider entry, and reported outcome separate. That
                makes refusal useful and prevents a successful API response from being mislabeled as proof of an external effect.
              </p>
            </div>

            <ol className={styles.flow} aria-label="EMILIA Host action flow">
              <li>
                <span className={styles.flowNumber}>01</span>
                <div><strong>Agent proposes</strong><p>HTTP request or MCP tool call, without the provider credential.</p></div>
              </li>
              <li>
                <span className={styles.flowNumber}>02</span>
                <div><strong>Host freezes</strong><p>The exact action and activated deployment binding are fixed before asynchronous checks.</p></div>
              </li>
              <li>
                <span className={styles.flowNumber}>03</span>
                <div><strong>Gate decides</strong><p>Customer-pinned authority and required evidence either fit this action or they do not.</p></div>
              </li>
              <li>
                <span className={styles.flowNumber}>04</span>
                <div><strong>One provider attempt may enter</strong><p>Only an admitted operation can reach the credential-owning provider path.</p></div>
              </li>
              <li>
                <span className={styles.flowNumber}>05</span>
                <div><strong>Outcome stays honest</strong><p>Refused, returned, or indeterminate are recorded without inventing effect certainty.</p></div>
              </li>
            </ol>
          </div>
        </section>

        <section className={styles.outcomeSection} aria-labelledby="outcomes-title">
          <div className={styles.shell}>
            <div className={styles.sectionHeading}>
              <div className={styles.eyebrow}>State means something</div>
              <h2 id="outcomes-title">A refusal is not an execution. A response is not proof of effect.</h2>
            </div>
            <div className={styles.outcomes}>
              {OUTCOMES.map((outcome) => (
                <article key={outcome.state} className={styles.outcome} data-tone={outcome.tone}>
                  <div className={styles.outcomeState}>{outcome.state}</div>
                  <h3>{outcome.title}</h3>
                  <p>{outcome.body}</p>
                  <div className={styles.outcomeProof}>{outcome.proof}</div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.deploySection} aria-labelledby="deploy-title">
          <div className={`${styles.shell} ${styles.deployGrid}`}>
            <div className={styles.deployIntro}>
              <div className={styles.eyebrow}>What exists now</div>
              <h2 id="deploy-title">Start with the boundary you actually own.</h2>
              <p>
                Host is the local deployment form of EMILIA Gate, not a new protocol or a sixth
                product. A governed pilot begins with one consequence path and the credential that makes it real.
              </p>
              <Link className={styles.textLink} href="/pilot?v=host">Choose the first boundary <span aria-hidden="true">→</span></Link>
            </div>
            <div className={styles.deployments}>
              {DEPLOYMENT_FORMS.map((form) => (
                <article key={form.label}>
                  <div className={styles.deploymentTitle}>
                    <h3>{form.label}</h3>
                    <span>{form.status}</span>
                  </div>
                  <p>{form.detail}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.boundarySection} aria-labelledby="boundary-title">
          <div className={styles.shell}>
            <div className={styles.boundaryCard}>
              <div>
                <div className={styles.eyebrow}>The honest boundary</div>
                <h2 id="boundary-title">Host protects what the customer actually routes through it.</h2>
              </div>
              <div className={styles.boundaryCopy}>
                <p>
                  Host&apos;s prevention claim is limited to activated covered paths. It does not establish complete mediation.
                  It does not prove the external effect occurred, constrain alternate credentials,
                  or make the action wise, legal, or correct.
                </p>
                <p>
                  Host events are not Consequence Ledger reconciliation. Host does not reconcile the Consequence Ledger,
                  and Scan does not automatically activate Host. Customer review, signed authority, deployment pinning,
                  durable state, provider profiles, and bypass removal remain part of the governed deployment.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className={styles.faqSection} aria-labelledby="faq-title">
          <div className={`${styles.shell} ${styles.faqGrid}`}>
            <div className={styles.faqIntro}>
              <div className={styles.eyebrow}>Questions buyers ask</div>
              <h2 id="faq-title">Before you put it beside a real credential.</h2>
              <p>These answers describe the current private alpha and governed-pilot boundary.</p>
            </div>
            <div className={styles.faqList}>
              {FAQ.map(({ q, a }) => (
                <details key={q}>
                  <summary>{q}</summary>
                  <p>{a}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.finalCta} aria-labelledby="final-title">
          <div className={styles.shell}>
            <div className={styles.finalPanel}>
              <div>
                <div className={styles.eyebrow}>One consequence path first</div>
                <h2 id="final-title">Bring the action. Keep the credential. Install the boundary.</h2>
                <p>
                  We will scope one activated HTTP or MCP path, the authority it must require,
                  the bypasses that must be removed, and the evidence the customer needs to retain.
                </p>
              </div>
              <div className={styles.actions}>
                <Link className={styles.primaryLight} href="/pilot?v=host">Scope a governed Host pilot</Link>
                <Link className={styles.secondaryDark} href="/docs">Read deployment docs</Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
