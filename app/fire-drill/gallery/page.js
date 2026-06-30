// SPDX-License-Identifier: Apache-2.0
// /fire-drill/gallery — the Agent Action Safety Index. A leaderboard of MCP
// servers scored by the Agent Action Firewall Test, plus the EG-1-Enforced
// reference implementations. Static assessment of documented tool surfaces.

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import { scan } from '../../../packages/fire-drill/index.js';
import { REPRESENTATIVE_CORPUS } from '../../../packages/fire-drill/corpus.js';

export const metadata = {
  title: 'Agent Action Safety Index — EMILIA',
  description: 'MCP servers scored by the Agent Action Firewall Test: can an agent take a dangerous action without an accountable human receipt?',
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
  const c = report.score === 100 ? color.green : report.score >= 50 ? color.gold : '#DC2626';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '4px 10px', border: `1px solid ${c}`, borderRadius: 999, whiteSpace: 'nowrap' }}>
      <span style={{ fontFamily: font.mono, fontSize: 12, color: c }}>{report.score}/100</span>
      <span style={{ fontFamily: font.mono, fontSize: 10, color: c, letterSpacing: 0.5, textTransform: 'uppercase' }}>EG-1 {report.eg1}</span>
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
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE AGENT ACTION SAFETY INDEX</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Which MCP servers refuse dangerous actions without a receipt?</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Each server is scored by the Agent Action Firewall Test: the share of its dangerous operations
              (money, data destruction, deploy, permissions, export, regulated override) that require an
              accountable human/quorum receipt. <b>Is this your project?</b> Add a gate and earn EG-1.
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
                    {s.report.summary.ungated > 0 ? `${s.report.summary.ungated} action(s) run without a receipt` : 'all dangerous actions gated'}
                  </div>
                  <a href={s.repo} target="_blank" rel="noopener noreferrer" style={{ ...styles.body, fontSize: 13, color: color.gold, marginLeft: 'auto' }}>repo ↗</a>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 18, maxWidth: 720 }}>
              Static assessment of publicly-documented tool surfaces — not a live deployment scan and not a vulnerability
              report. Click a server for detail, or run <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> on yours.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>EG-1 ENFORCED — REFERENCE IMPLEMENTATIONS</div>
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
              Earn your place: pass <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> and{' '}
              <a href="/gate#eg1" style={{ color: color.gold }}>open a PR</a>.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
