// SPDX-License-Identifier: Apache-2.0
// /fire-drill/gallery — a static declaration index plus separately tested
// runtime reference implementations.

import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import { scan } from '../../../packages/fire-drill/index.js';
import { REPRESENTATIVE_CORPUS } from '../../../packages/fire-drill/corpus.js';

export const metadata: Metadata = {
  title: 'Receipt Declaration Index — EMILIA',
  description: 'Static MCP schema coverage: which detected high-risk tools declare a required receipt input?',
};

// Score every server in the corpus; worst first (most urgent / most useful).
const SCANNED = REPRESENTATIVE_CORPUS
  .map((c) => ({ ...c, report: scan(c.manifest) }))
  .sort((a, b) => a.report.score - b.report.score);

const VERIFIED = [
  { name: '@emilia-protocol/gate', note: 'The firewall itself — 8/8 EG-1 checks.' },
  { name: 'require-receipt-pr-kit', note: 'The MCP dev-wedge reference.' },
];

function ScorePill({ report }) {
  const c = report.score >= 50 ? color.gold : '#DC2626';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '4px 10px', border: `1px solid ${c}`, borderRadius: 999, whiteSpace: 'nowrap' }}>
      <span style={{ fontFamily: font.mono, fontSize: 12, color: c }}>{report.score}/100</span>
      <span style={{ fontFamily: font.mono, fontSize: 10, color: c, letterSpacing: 0.5, textTransform: 'uppercase' }}>static {report.static_result}</span>
    </span>
  );
}

export default function GalleryPage() {
  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 28 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE RECEIPT DECLARATION INDEX</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Which MCP schemas declare required evidence?</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Each server is scored on the share of detected high-risk operations whose public schema
              declares a required receipt input. This is not a safety ranking and does not test runtime enforcement.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 24, flexWrap: 'wrap' }}>
              <a href="/fire-drill" style={cta.primary}>Run the fire drill</a>
              <Link href="/fire-drill/report" style={cta.secondary}>The Report</Link>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>SCANNED SERVERS</div>
            <div style={{ marginTop: 12 }}>
              {SCANNED.map((s) => (
                <div key={s.slug} style={{ display: 'flex', gap: 16, alignItems: 'center', padding: '13px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                  <a href={`/fire-drill/scan/${s.slug}`} style={{ ...styles.body, fontSize: 15, color: color.t1, minWidth: 240, fontWeight: 600 }}>{s.name}</a>
                  <ScorePill report={s.report} />
                  <div style={{ ...styles.body, fontSize: 13, color: color.t2 }}>
                    {s.report.summary.missing_declaration > 0
                      ? `${s.report.summary.missing_declaration} required declaration(s) missing`
                      : 'all detected dangerous actions declare evidence'}
                  </div>
                  <a href={s.repo} target="_blank" rel="noopener noreferrer" style={{ ...styles.body, fontSize: 13, color: color.gold, marginLeft: 'auto' }}>repo ↗</a>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 18, maxWidth: 720 }}>
              Static assessment of publicly documented tool surfaces, not a live deployment scan,
              vulnerability report, or certification. Click a server for detail, or run{' '}
              <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> on yours.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>RUNTIME EG-1 — SEPARATELY TESTED REFERENCES</div>
            <div style={{ marginTop: 12 }}>
              {VERIFIED.map((e) => (
                <div key={e.name} style={{ display: 'flex', gap: 16, alignItems: 'center', padding: '13px 0', borderTop: `1px solid ${color.border}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.t1, minWidth: 240 }}>{e.name}</div>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '4px 10px', border: `1px solid ${color.green}`, borderRadius: 999 }}>
                    <span style={{ width: 7, height: 7, borderRadius: 999, background: color.green, display: 'inline-block' }} />
                    <span style={{ fontFamily: font.mono, fontSize: 11, color: color.green }}>EG-1 Enforced</span>
                  </span>
                  <div style={{ ...styles.body, fontSize: 14, color: color.t2 }}>{e.note}</div>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 16 }}>
              Static completion is not enough. A runtime listing requires the negative, replay,
              wrong-action, and storage-failure EG-1 suite against the deployed integration.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
