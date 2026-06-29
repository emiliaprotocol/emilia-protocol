// SPDX-License-Identifier: Apache-2.0
// /fire-drill/gallery — the Agent Action Safety Index. Projects that refuse
// dangerous actions without an accountable human receipt (EG-1 Enforced).

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata = {
  title: 'Agent Action Safety Index — EMILIA',
  description: 'Projects that refuse dangerous AI-agent actions without an accountable human receipt (EG-1 Enforced).',
};

// Launch set: the EMILIA reference implementations that are EG-1 Enforced today.
// Third-party projects appear here once they pass `npx @emilia-protocol/fire-drill`
// and open a PR — we do not list projects we have not verified.
const CATEGORIES = [
  {
    name: 'Reference implementations',
    entries: [
      { project: '@emilia-protocol/gate', score: 100, eg1: 'pass', note: 'The firewall itself — 8/8 EG-1 checks.' },
      { project: 'require-receipt-pr-kit', score: 100, eg1: 'pass', note: 'The MCP dev-wedge reference.' },
    ],
  },
  { name: 'MCP servers', entries: [], invite: 'Run the fire drill on your MCP server and open a PR.' },
  { name: 'Finance agents', entries: [], invite: 'Payments, payouts, refunds — be the first verified.' },
  { name: 'DevOps agents', entries: [], invite: 'Deploy, IAM, infra — be the first verified.' },
  { name: 'Data agents', entries: [], invite: 'Delete, export, RLS — be the first verified.' },
];

function Badge({ eg1, score }) {
  const pass = eg1 === 'pass' || score === 100;
  const c = pass ? color.green : (score >= 50 ? color.gold : '#DC2626');
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '4px 10px', border: `1px solid ${c}`, borderRadius: 999 }}>
      <span style={{ width: 7, height: 7, borderRadius: 999, background: c, display: 'inline-block' }} />
      <span style={{ fontFamily: font.mono, fontSize: 11, color: c, letterSpacing: 0.5 }}>{pass ? 'EG-1 Enforced' : `${score}/100`}</span>
    </span>
  );
}

export default function GalleryPage() {
  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 32 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE AGENT ACTION SAFETY INDEX</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Projects that refuse dangerous actions without a receipt.</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Every project here passes the Agent Action Firewall Test: no money movement, data
              destruction, deploy, permission change, export, or regulated override can run without an
              accountable human (or quorum) receipt. Earn your place — pass <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> and open a PR.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
              <a href="/fire-drill" style={cta.primary}>Run the fire drill</a>
              <a href="/gate#eg1" style={cta.secondary}>How EG-1 works</a>
            </div>
          </div>
        </section>

        {CATEGORIES.map((cat) => (
          <section key={cat.name} style={{ ...styles.section, paddingTop: 0, paddingBottom: 28 }}>
            <div style={styles.container}>
              <div style={{ ...styles.eyebrow }}>{cat.name.toUpperCase()}</div>
              {cat.entries.length === 0 ? (
                <p style={{ ...styles.body, color: color.t2, marginTop: 12, fontSize: 15 }}>{cat.invite} <a href="/fire-drill" style={{ color: color.gold }}>Run it →</a></p>
              ) : (
                <div style={{ marginTop: 12 }}>
                  {cat.entries.map((e) => (
                    <div key={e.project} style={{ display: 'flex', gap: 16, alignItems: 'center', padding: '14px 0', borderTop: `1px solid ${color.border}` }}>
                      <div style={{ fontFamily: font.mono, fontSize: 14, color: color.t1, minWidth: 260 }}>{e.project}</div>
                      <Badge eg1={e.eg1} score={e.score} />
                      <div style={{ ...styles.body, fontSize: 14, color: color.t2 }}>{e.note}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        ))}

        <section style={styles.section}>
          <div style={styles.container}>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 720 }}>
              We list only projects we have verified pass EG-1. The categories above seed the index;
              third-party entries are added as they pass and merge the gate. See the{' '}
              <a href="/fire-drill/report" style={{ color: color.gold }}>Agent Action Firewall Report</a> for methodology.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
