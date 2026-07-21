import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';

export const metadata: Metadata = {
  title: 'Repository Verification Snapshot',
  description: 'The current machine-verification snapshot for the EMILIA Protocol repository, with deployment and pentest limits stated plainly.',
  alternates: { canonical: '/verify-live' },
};

const number = (value) => Number(value).toLocaleString('en-US');
const status = proofStats.securityCase.status === 'passed' ? 'Repository checks passed' : 'Attention required';

const CHECKS = [
  {
    label: 'TLA+ state-machine invariants',
    value: `${proofStats.tla.invariants}`,
    detail: `${proofStats.tla.checker}; no reported error in the checked configuration`,
  },
  {
    label: 'Alloy structural checks',
    value: `${proofStats.alloy.facts} / ${proofStats.alloy.assertions}`,
    detail: 'facts / assertions in the current model inventory',
  },
  {
    label: 'Tamarin symbolic obligations',
    value: `${proofStats.tamarin.verifiedObligations}`,
    detail: `${proofStats.tamarin.deliberatelyUnsafeCounterexamples} deliberately unsafe counterexamples retained`,
  },
  {
    label: 'Executable security claims',
    value: `${proofStats.securityCase.claims}`,
    detail: `${proofStats.securityCase.evidenceFiles} hashed evidence files in the resolved case`,
  },
  {
    label: 'Conformance vectors',
    value: `${proofStats.conformance.vectors}`,
    detail: `${proofStats.conformance.suites} suites across ${proofStats.conformance.referencePorts} reference ports`,
  },
  {
    label: 'Automated test cases',
    value: number(proofStats.tests.total),
    detail: `${number(proofStats.tests.files)} test files; platform-specific skips are disclosed`,
  },
];

const LIMITS = [
  'This is a repository evidence snapshot, not an assertion that every deployed instance has been independently verified.',
  'Formal results apply only within each model’s stated assumptions and bounded configuration.',
  'The external implementation evidence is interoperability evidence; strict clean-room acceptance remains separately disclosed.',
  'A passing model or test does not prove that an approved action is wise, legal, or safe.',
];

export default function VerifyLivePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Proof" />
      <main>
        <section style={{ ...styles.sectionWide, paddingTop: 76, paddingBottom: 48 }}>
          <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA / verification status</div>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 28, flexWrap: 'wrap' }}>
            <div>
              <h1 style={{ ...styles.h1Large, maxWidth: 800, lineHeight: 1.02 }}>The proof surface is public.</h1>
              <p style={{ ...styles.body, fontSize: 18, maxWidth: 720, marginTop: 24 }}>
                This page reports the latest machine-generated evidence snapshot. It exposes the numbers,
                the retained attack traces, and the boundary between what was checked and what was not.
              </p>
              <p style={{ ...styles.body, fontSize: 14, maxWidth: 720, marginTop: 16 }}>
                This is not a production security clearance. The current Strix retest and deployment
                validation remain open until the fixes are deployed and re-tested on the live service.
              </p>
            </div>
            <div style={{ minWidth: 220, padding: 20, border: `1px solid ${color.border}`, borderRadius: 8, background: '#F5F5F4' }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, textTransform: 'uppercase', letterSpacing: 1 }}>Current status</div>
              <div style={{ color: color.green, fontSize: 20, fontWeight: 700, marginTop: 10 }}>{status}</div>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, marginTop: 9, lineHeight: 1.5 }}>
                Generated {proofStats.generatedAt}
              </div>
            </div>
          </div>
        </section>

        <section style={{ borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`, background: '#F5F5F4' }}>
          <div style={{ ...styles.sectionWide, paddingTop: 34, paddingBottom: 34 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 220px), 1fr))', gap: 0 }}>
              {CHECKS.map((check) => (
                <article key={check.label} style={{ padding: '18px 24px 18px 0', minHeight: 126 }}>
                  <div style={{ color: color.gold, fontSize: 31, fontWeight: 700, lineHeight: 1 }}>{check.value}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t1, textTransform: 'uppercase', letterSpacing: 1, lineHeight: 1.45, marginTop: 10 }}>{check.label}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, lineHeight: 1.5, marginTop: 6 }}>{check.detail}</div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 76, paddingBottom: 76 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))', gap: 56 }}>
            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>How to read this</div>
              <h2 style={{ ...styles.h2, fontSize: 32 }}>Evidence is layered, not averaged.</h2>
              <p style={styles.body}>
                The symbolic models constrain protocol state. Executable claims connect those constraints to
                code and vectors. Conformance checks portability. Stateful fault tests exercise the path under
                races and restarts. No one layer gets to borrow another layer’s authority.
              </p>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
                <Link href="/proof" className="ep-cta" style={cta.primary}>Read the evidence case</Link>
                <a href="/.well-known/emilia-context.json" className="ep-cta-secondary" style={cta.secondary}>Open machine context</a>
              </div>
            </div>
            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>Claim boundary</div>
              <h2 style={{ ...styles.h2, fontSize: 32 }}>What this does not establish.</h2>
              <div style={{ borderTop: `1px solid ${color.border}` }}>
                {LIMITS.map((limit) => <p key={limit} style={{ ...styles.body, fontSize: 14, margin: 0, padding: '15px 0', borderBottom: `1px solid ${color.border}` }}>{limit}</p>)}
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
