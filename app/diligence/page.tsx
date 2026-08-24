// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import { headers } from 'next/headers';
import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import proofStats from '@/lib/proof-stats.json';
import { ENTITY } from '@/lib/site-config';
import { color, cta, font, styles } from '@/lib/tokens';

const PAGE_URL = 'https://www.emiliaprotocol.ai/diligence';
const GOLD_TEXT = '#765A13';

export const metadata: Metadata = {
  title: 'Public Diligence: Product, Proof, Security, and Status',
  description:
    'Verify EMILIA Protocol and Gate from primary sources: product boundaries, rerunnable proof, conformance vectors, security posture, legal identity, and machine-readable context.',
  alternates: { canonical: '/diligence' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'EMILIA Public Diligence',
    description: 'Check the product, proof, security posture, and claim boundaries from primary sources.',
    url: PAGE_URL,
    type: 'website',
  },
};

const SNAPSHOT_DATE = new Intl.DateTimeFormat('en-US', {
  month: 'long',
  day: 'numeric',
  year: 'numeric',
  timeZone: 'UTC',
}).format(new Date(proofStats.generatedAt));

const SNAPSHOT = [
  {
    value: Number(proofStats.tests.total).toLocaleString('en-US'),
    label: 'automated tests',
    detail: `${proofStats.tests.files} test files`,
  },
  {
    value: proofStats.securityCase.claims,
    label: 'executable security claims',
    detail: `${proofStats.securityCase.evidenceFiles} evidence files`,
  },
  {
    value: proofStats.conformance.vectors,
    label: 'conformance vectors',
    detail: `${proofStats.conformance.suites} suites`,
  },
  {
    value: proofStats.tla.invariants,
    label: 'TLA+ invariants',
    detail: `${proofStats.tamarin.verifiedObligations} verified Tamarin obligations`,
  },
];

const SURFACES = [
  {
    title: 'Open Protocol',
    body: 'The Apache-2.0 evidence and verification substrate. The posted documents are individual Internet-Drafts, not RFCs or IETF endorsement.',
    href: '/protocol',
    label: 'Read the protocol path',
  },
  {
    title: 'EMILIA Gate',
    body: 'The enforcement product for configured, completely mediated action paths. It checks authority and evidence before an admitted executor attempt.',
    href: '/gate',
    label: 'Inspect the Gate boundary',
  },
  {
    title: 'Assurance',
    body: 'The evidence-facing layer that packages and re-performs a bounded record. A report or certificate never becomes action authority.',
    href: '/assurance',
    label: 'Inspect assurance',
  },
];

const LIMITS = [
  'EMILIA does not protect an action path that bypasses its configured enforcement boundary.',
  'It does not claim exactly-once physical execution. Durable admission can bound a protected path to at most one admitted provider attempt, while uncertain outcomes remain INDETERMINATE until authenticated reconciliation.',
  'Repository-generated tests, models, and security-case evidence are engineering evidence, not an external certification or a guarantee that every deployment is correctly mediated.',
  'Reference ports maintained by the same team are not independent implementation adoption. The current clean-room acceptance field remains false.',
  'Individual Internet-Drafts are work in progress. Publication on the IETF Datatracker does not make them RFCs or imply IETF adoption.',
];

const EVIDENCE_LINKS = [
  ['/proof', 'Engineering evidence', 'Current proof summary, artifact hashes, and rerun instructions.'],
  ['/conformance', 'Conformance', 'Public vectors and reference behavior for consequence admission.'],
  ['/security', 'Product security', 'Disclosure, threat boundaries, and current security material.'],
  ['/verify-live', 'Repository snapshot', 'A public view of the current verification snapshot.'],
  ['/.well-known/emilia-context.json', 'Machine context', 'Structured, source-pinned context for agents and diligence systems.'],
  ['/llms.txt', 'LLM context index', 'A compact text index that points models to canonical public sources.'],
] as const;

const PAGE_JSONLD = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebPage',
      '@id': `${PAGE_URL}#webpage`,
      url: PAGE_URL,
      name: 'EMILIA Public Diligence',
      description: metadata.description,
      isPartOf: { '@id': 'https://www.emiliaprotocol.ai/#website' },
      about: { '@id': 'https://www.emiliaprotocol.ai/#organization' },
      breadcrumb: { '@id': `${PAGE_URL}#breadcrumb` },
    },
    {
      '@type': 'BreadcrumbList',
      '@id': `${PAGE_URL}#breadcrumb`,
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://www.emiliaprotocol.ai/' },
        { '@type': 'ListItem', position: 2, name: 'Public Diligence', item: PAGE_URL },
      ],
    },
  ],
};

export default async function DiligencePage(): Promise<React.ReactElement> {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(PAGE_JSONLD) }}
        nonce={nonce}
      />
      <SiteNav />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 92, paddingBottom: 42 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: GOLD_TEXT }}>PUBLIC DILIGENCE · PRIMARY SOURCES</div>
            <h1 style={{ ...styles.h1, marginTop: 16, maxWidth: 930 }}>
              Check the product, proof, and boundary yourself.
            </h1>
            <p style={{ ...styles.lead, maxWidth: 820, marginTop: 20 }}>
              EMILIA sits before configured consequential actions and asks whether this exact action is
              within customer-controlled authority. This page points buyers, investors, security teams,
              and machines to the public evidence, including what the evidence does not prove.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 26 }}>
              <a
                href="https://github.com/emiliaprotocol/emilia-protocol"
                target="_blank"
                rel="noopener noreferrer"
                style={cta.primary}
              >
                Inspect the repository
              </a>
              <Link href="/proof" style={cta.secondary}>Reproduce the evidence</Link>
              <Link href="/security" style={cta.secondary}>Review security</Link>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 12 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.t2 }}>CURRENT CHECKED-IN SNAPSHOT · {SNAPSHOT_DATE}</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 14, marginTop: 18 }}>
              {SNAPSHOT.map((item) => (
                <div key={item.label} style={{ ...styles.card, padding: 22 }}>
                  <div style={{ fontFamily: font.sans, fontSize: 36, fontWeight: 750, color: color.t1 }}>{item.value}</div>
                  <div style={{ ...styles.h3, fontSize: 15, marginTop: 6 }}>{item.label}</div>
                  <div style={{ ...styles.body, fontSize: 12, color: color.t3, marginTop: 6 }}>{item.detail}</div>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 820, marginTop: 16 }}>
              These values are read from the repository&apos;s generated proof summary. They move only when the underlying
              evidence changes and the generation check passes. They are not customer adoption or certification counts.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE PRODUCT SHAPE</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Proof, control, and assurance stay separate.</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 24 }}>
              {SURFACES.map((surface) => (
                <div key={surface.title} style={{ ...styles.card, padding: 24 }}>
                  <h3 style={{ ...styles.h3, margin: 0 }}>{surface.title}</h3>
                  <p style={{ ...styles.body, color: color.t2, fontSize: 14, marginTop: 12 }}>{surface.body}</p>
                  <Link href={surface.href} style={{ color: GOLD_TEXT, fontFamily: font.mono, fontSize: 12 }}>
                    {surface.label} &rarr;
                  </Link>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, background: '#171717', color: '#FAFAF9' }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: '#d6a83f' }}>CLAIM BOUNDARY</div>
            <h2 style={{ ...styles.h2, color: '#FAFAF9', marginTop: 12 }}>What we do not ask you to assume.</h2>
            <div style={{ maxWidth: 900, marginTop: 22 }}>
              {LIMITS.map((limit, index) => (
                <div
                  key={limit}
                  style={{ display: 'flex', gap: 18, padding: '16px 0', borderTop: '1px solid rgba(255,255,255,0.12)' }}
                >
                  <span style={{ fontFamily: font.mono, color: '#d6a83f', fontSize: 12 }}>{String(index + 1).padStart(2, '0')}</span>
                  <span style={{ fontFamily: font.sans, color: 'rgba(250,250,249,0.78)', fontSize: 15, lineHeight: 1.65 }}>{limit}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>RERUN, DO NOT TRUST</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>The diligence path is executable.</h2>
            <p style={{ ...styles.body, maxWidth: 780, color: color.t2, marginTop: 14 }}>
              Clone the public repository and run the checked-in evidence gates. The security case and
              machine context fail when their source artifacts drift.
            </p>
            <pre style={{
              marginTop: 22,
              padding: 22,
              overflowX: 'auto',
              background: '#0b0d12',
              color: '#e8eaf0',
              borderRadius: 10,
              fontFamily: font.mono,
              fontSize: 13,
              lineHeight: 1.75,
            }}><code>{`git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
npm ci
npm run check:proof-stats
npm run check:security-case
npm run check:public-conformance-claims
npm run check:llm-context`}</code></pre>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 10 }}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>CANONICAL EVIDENCE SURFACES</div>
            <div style={{ marginTop: 20 }}>
              {EVIDENCE_LINKS.map(([href, label, detail]) => (
                <div
                  key={href}
                  style={{ display: 'flex', gap: 22, alignItems: 'baseline', flexWrap: 'wrap', padding: '16px 0', borderTop: `1px solid ${color.border}` }}
                >
                  <a href={href} style={{ minWidth: 190, color: color.t1, fontWeight: 700 }}>{label}</a>
                  <span style={{ ...styles.body, color: color.t2, fontSize: 14 }}>{detail}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 30, paddingBottom: 86 }}>
          <div style={{ ...styles.container, borderTop: `1px solid ${color.border}`, paddingTop: 34 }}>
            <h2 style={styles.h2}>Need a source that is not listed?</h2>
            <p style={{ ...styles.body, color: color.t2, maxWidth: 720, marginTop: 12 }}>
              Ask for the exact artifact or a scoped technical review. {ENTITY.legalName} will distinguish
              what is public, what is customer-specific, and what does not exist yet.
            </p>
            <a href={`mailto:${ENTITY.email}?subject=EMILIA%20diligence%20request`} style={{ ...cta.primary, display: 'inline-flex', marginTop: 20 }}>
              Request a sourced answer
            </a>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
