import type { Metadata } from 'next';
import Link from 'next/link';
import {
  Activity,
  ArrowRight,
  FileCheck2,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { ProductStoryHero } from '@/components/product-story/ProductStory';
import { cta, color, font, radius, styles } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Assurance Plane: Re-performance for AI Controls',
  description:
    'Implemented re-performance, conformance-report, and deployment-evidence procedures '
    + 'for supplied EMILIA Gate inputs. Verification remains open and reproducible.',
  alternates: { canonical: '/assurance' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'EMILIA Assurance Plane',
    description:
      'Re-perform Gate evidence under pinned inputs, record drift, and hand reproducible workpapers to auditors and underwriters.',
    url: 'https://www.emiliaprotocol.ai/assurance',
    type: 'website',
  },
};

const PROCEDURES = [
  {
    Icon: RefreshCw,
    title: 'Independent re-performance',
    body:
      'The procedure reruns the open verifier over a supplied population using explicitly pinned keys, profiles, clocks, and input digests. Runtime claims are compared, never trusted.',
  },
  {
    Icon: FileCheck2,
    title: 'Versioned conformance records',
    body:
      'A signed record binds the implementation, source revision, vector bundle, procedure, and result. Divergence remains visible instead of being rounded into a pass.',
  },
  {
    Icon: Activity,
    title: 'Repeatable evidence checks',
    body:
      'Repeated evidence-head capture, checks, and drift reporting can turn supplied point-in-time inputs into a traceable operating record.',
  },
  {
    Icon: ShieldCheck,
    title: 'Audit and underwriter packages',
    body:
      'Portable workpapers summarize the population, refusals, exceptions, integrity warnings, and control operation. The auditor or underwriter keeps the conclusion.',
  },
];

const ARTIFACTS = [
  {
    name: 'ep-assure',
    role: 'CLI for building and independently re-performing an assurance package.',
    href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/gate/ep-assure.mjs',
  },
  {
    name: 'EP-ASSURANCE-PACKAGE-v1',
    role: 'Content-addressed bundle of decisions, evidence, pinned profile, and stated runtime verdicts.',
    href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/gate/reports/assurance-package.js',
  },
  {
    name: 'EP-GATE-REPERFORMANCE-v1',
    role: 'Independent hash-chain, receipt, signoff, quorum, and reported-count recomputation.',
    href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/gate/reports/reperform.js',
  },
  {
    name: 'EP-EXTERNAL-VERIFICATION-STATEMENT-v1',
    role: 'Signed, input-pinned statement of what an outside verifier ran and where it diverged.',
    href: 'https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/external-verification',
  },
  {
    name: 'Auditor workpaper',
    role: 'Reproducible technical procedure and evidence fields for a control test.',
    href: '/auditors',
  },
  {
    name: 'EP-GATE-UNDERWRITER-ATTESTATION-v1',
    role: 'Deterministic operating-control package with explicit exclusions and integrity warnings.',
    href: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/packages/gate/reports/underwriter.js',
  },
];

const C = ({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

export default function AssurancePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Assurance" />

      <main>
        <ProductStoryHero product="assurance" />

        <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={{ maxWidth: 720, marginBottom: 46 }}>
              <div style={styles.eyebrow}>IMPLEMENTED PROCEDURES</div>
              <h2 style={{ ...styles.h2, marginTop: 14 }}>
                Evidence operations above the open verifier.
              </h2>
              <p style={{ ...styles.body, marginTop: 16 }}>
                Verification stays free and reproducible. The repository implements procedures for
                pinning inputs, re-performing a supplied population, preserving the record, exposing
                drift, and preparing a technical handoff. A pilot or service engagement must be
                separately scoped.
              </p>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
              {PROCEDURES.map(({ Icon, title, body }) => (
                <article
                  key={title}
                  style={{
                    border: `1px solid ${color.border}`,
                    borderTop: `3px solid ${color.gold}`,
                    borderRadius: radius.base,
                    padding: 26,
                    background: color.card,
                  }}
                >
                  <Icon size={20} color={color.gold} aria-hidden="true" />
                  <h3 style={{ fontFamily: font.sans, fontSize: 17, color: color.t1, margin: '18px 0 10px' }}>
                    {title}
                  </h3>
                  <p style={{ fontSize: 14, lineHeight: 1.68, color: color.t2, margin: 0 }}>{body}</p>
                </article>
              ))}
            </div>
          </C>
        </section>

        <section style={{ padding: '88px 0', background: 'rgba(245,244,240,0.45)', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={{ maxWidth: 760, marginBottom: 40 }}>
              <div style={styles.eyebrow}>RUNNING ARTIFACTS</div>
              <h2 style={{ ...styles.h2, marginTop: 14 }}>
                The procedure is grounded in code a third party can inspect.
              </h2>
            </div>
            <div style={{ borderTop: `1px solid ${color.border}` }}>
              {ARTIFACTS.map((artifact) => (
                <a
                  key={artifact.name}
                  href={artifact.href}
                  className="ep-assurance-artifact-row"
                  target={artifact.href.startsWith('http') ? '_blank' : undefined}
                  rel={artifact.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'minmax(240px, 0.75fr) minmax(280px, 1.25fr) 24px',
                    gap: 24,
                    alignItems: 'center',
                    padding: '22px 0',
                    borderBottom: `1px solid ${color.border}`,
                    textDecoration: 'none',
                  }}
                >
                  <code style={{ fontFamily: font.mono, fontSize: 13, color: color.t1 }}>{artifact.name}</code>
                  <span style={{ fontSize: 14, lineHeight: 1.6, color: color.t2 }}>{artifact.role}</span>
                  <ArrowRight size={16} color={color.gold} aria-hidden="true" />
                </a>
              ))}
            </div>
          </C>
        </section>

        <section id="open-verification" style={{ padding: '88px 0', background: '#1C1917', color: '#FAFAF9' }}>
          <C>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 64, alignItems: 'center' }}>
              <div>
                <div style={{ ...styles.eyebrow, color: color.gold }}>OPEN VERIFICATION</div>
                <h2 style={{ ...styles.h2, color: '#FAFAF9', marginTop: 14 }}>
                  The customer never has to trust an EMILIA-only verdict.
                </h2>
                <p style={{ fontSize: 16, lineHeight: 1.72, color: 'rgba(250,250,249,0.7)', marginTop: 18 }}>
                  The package, verifier, vectors, and procedure are public. A customer, audit firm,
                  insurer, regulator, or competitor can rerun the same inputs without an EMILIA
                  account or server in the verification path.
                </p>
                <Link href="/protocol" style={{ color: color.gold, fontFamily: font.mono, fontSize: 12 }}>
                  Inspect the open Protocol <ArrowRight size={13} style={{ verticalAlign: 'middle' }} aria-hidden="true" />
                </Link>
              </div>
              <pre style={{
                fontFamily: font.mono,
                fontSize: 13,
                lineHeight: 1.75,
                color: '#D6D3D1',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.13)',
                borderRadius: radius.base,
                padding: 26,
                margin: 0,
                overflowX: 'auto',
              }}>{`# Build or re-perform a package locally
npx -p @emilia-protocol/gate \\
  ep-assure evidence.json --strict

# Machine-readable workpaper
npx -p @emilia-protocol/gate \\
  ep-assure evidence.json --json`}</pre>
            </div>
          </C>
        </section>

        <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 56 }}>
              <div>
                <div style={styles.eyebrow}>WHAT IT CAN ESTABLISH</div>
                <h2 style={{ ...styles.h2, marginTop: 14 }}>A reproducible technical record.</h2>
                <ul style={{ ...styles.list, marginTop: 22 }}>
                  <li>The supplied package digest matches its contents.</li>
                  <li>Evidence verifies under the explicitly pinned keys and profiles.</li>
                  <li>Recomputed results agree or drift from the runtime&rsquo;s stated results.</li>
                  <li>The named conformance procedure produced the recorded result on the pinned inputs.</li>
                  <li>Exceptions and integrity warnings remain visible in the handoff.</li>
                </ul>
              </div>
              <div>
                <div style={styles.eyebrow}>WHAT IT DOES NOT ESTABLISH</div>
                <h2 style={{ ...styles.h2, marginTop: 14 }}>No borrowed authority.</h2>
                <ul style={{ ...styles.list, marginTop: 22 }}>
                  <li>No accredited certification or public certification mark is currently issued.</li>
                  <li>No audit opinion, legal-compliance conclusion, insurance coverage decision, or regulatory approval.</li>
                  <li>No proof that withheld events were included unless the population is bound to an external checkpoint.</li>
                  <li>No judgment that an authorized action was wise, lawful, safe, or successful.</li>
                  <li>No guarantee beyond the system boundaries and evidence actually examined.</li>
                </ul>
              </div>
            </div>
          </C>
        </section>

        <section style={{ padding: '88px 0' }}>
          <C>
            <div style={{ maxWidth: 780 }}>
              <div style={styles.eyebrow}>INDEPENDENT CERTIFICATION</div>
              <h2 style={{ ...styles.h2, marginTop: 14 }}>A partner path, not a claim we make today.</h2>
              <p style={{ ...styles.body, marginTop: 18 }}>
                Independent certification belongs with qualified third parties and future
                multi-stakeholder governance. Any future EMILIA conformance program must use the
                same public vectors, published procedures, and uniform criteria available to every
                implementer. EMILIA can prepare and re-perform the technical record; the independent
                partner decides what conclusion, if any, it supports.
              </p>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 30 }}>
                <Link href="/partners" className="ep-cta" style={cta.primary}>
                  Discuss a scoped assurance pilot <ArrowRight size={15} aria-hidden="true" />
                </Link>
                <Link href="/auditors" className="ep-cta-secondary" style={cta.secondary}>
                  Auditor procedure
                </Link>
                <Link href="/security" className="ep-cta-secondary" style={cta.secondary}>
                  Security boundaries
                </Link>
              </div>
            </div>
          </C>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
