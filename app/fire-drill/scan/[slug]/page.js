// SPDX-License-Identifier: Apache-2.0
// /fire-drill/scan/[slug] — a public, indexable Agent Action Firewall result for
// a named MCP server. Static assessment of the documented tool surface (not a
// live deployment scan, not a vulnerability claim). Links to the real repo
// (backlink) and routes the maintainer to the fix (earn EG-1).

import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import { scan } from '../../../../packages/fire-drill/index.js';
import { REPRESENTATIVE_CORPUS } from '../../../../packages/fire-drill/corpus.js';

const BY_SLUG = Object.fromEntries(REPRESENTATIVE_CORPUS.map((c) => [c.slug, c]));

export function generateStaticParams() {
  return REPRESENTATIVE_CORPUS.map((c) => ({ slug: c.slug }));
}

export function generateMetadata({ params }) {
  const c = BY_SLUG[params.slug];
  if (!c) return { title: 'Scan not found — EMILIA Fire Drill' };
  const r = scan(c.manifest);
  return {
    title: `${c.name} — Agent Action Firewall score ${r.score}/100 | EMILIA`,
    description: `Static assessment of the ${c.name} MCP tool surface: ${r.summary.ungated} dangerous action(s) can run without an accountable human receipt. Score ${r.score}/100, EG-1 ${r.eg1}.`,
  };
}

export default function ScanPage({ params }) {
  const c = BY_SLUG[params.slug];
  if (!c) notFound();
  const report = scan(c.manifest);
  const scoreColor = report.score === 100 ? color.green : report.score >= 50 ? color.gold : '#DC2626';

  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 28 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>AGENT ACTION FIREWALL · SCAN RESULT</div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>{c.name}</h1>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 20, marginTop: 16, flexWrap: 'wrap' }}>
              <div style={{ fontFamily: font.mono, fontSize: 44, fontWeight: 700, color: scoreColor }}>{report.score}<span style={{ fontSize: 20, color: color.t3 }}>/100</span></div>
              <div style={{ fontFamily: font.mono, fontSize: 13, color: report.eg1 === 'pass' ? color.green : '#DC2626', letterSpacing: 1, textTransform: 'uppercase' }}>
                EG-1 {report.eg1}
              </div>
              <a href={c.repo} target="_blank" rel="noopener noreferrer" style={{ ...styles.body, fontSize: 14, color: color.gold, marginLeft: 'auto' }}>repository ↗</a>
            </div>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              {report.summary.dangerous} dangerous operation(s) in the documented tool surface; {report.summary.ungated} can run
              <b> without an accountable human receipt</b>. {report.summary.gated} already gated.
            </p>
          </div>
        </section>

        {report.findings.length > 0 && (
          <section style={{ ...styles.section, paddingTop: 0 }}>
            <div style={styles.container}>
              <div style={styles.eyebrow}>WHAT CAN RUN WITHOUT A RECEIPT</div>
              <div style={{ marginTop: 12 }}>
                {report.findings.map((f) => (
                  <div key={f.operation} style={{ borderTop: `1px solid ${color.border}`, padding: '14px 0' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 14, color: '#DC2626' }}>✗ {f.operation}<span style={{ color: color.t3 }}> — {f.family}</span></div>
                    <div style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 6 }}>{f.fix}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={{ ...styles.h2, maxWidth: 760 }}>Is this your project? Earn <span style={{ color: color.gold }}>EG-1 Enforced</span>.</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 14 }}>
              Wrap the dangerous tools with <code style={{ fontFamily: font.mono }}>@emilia-protocol/gate</code> so they require a
              human/quorum receipt, re-run <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code>, and this
              result turns green. We update it on request.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 24, flexWrap: 'wrap' }}>
              <a href="/gate#eg1" style={cta.primary}>How to earn EG-1</a>
              <a href="/fire-drill" style={cta.secondary}>Run it yourself</a>
              <a href="/fire-drill/gallery" style={cta.secondary}>Full index</a>
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 22, maxWidth: 720 }}>
              Static assessment of the publicly-documented tool surface — not a live scan of any deployment and not a vulnerability
              report. It reflects whether the manifest requires a receipt for high-risk actions. Verify at runtime with EG-1 conformance.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
