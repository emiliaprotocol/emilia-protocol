// SPDX-License-Identifier: Apache-2.0
// /fire-drill/report — The Agent Action Firewall Report (methodology edition).
// Honest framing: we publish the methodology now; the aggregate figure is
// populated from real scans, not invented.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata = {
  title: 'The Agent Action Firewall Report — EMILIA',
  description: 'How safe are AI agents that can take irreversible actions? The methodology behind the Agent Action Firewall Test.',
};

const FAMILIES = [
  ['Money movement', 'pay / payout / refund / transfer / payroll'],
  ['Data destruction', 'delete / drop / truncate / purge (and any HTTP DELETE)'],
  ['Production deploy', 'deploy / release / terraform apply / migrate'],
  ['Permission change', 'IAM / role / grant / policy / RBAC'],
  ['Bulk data export', 'export / dump / download / backup'],
  ['Regulated override', 'override a claim, benefit, credit, or decision'],
];

export default function ReportPage() {
  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 32 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE AGENT ACTION FIREWALL REPORT</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>How many agents can take an irreversible action without a receipt?</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              The market is wiring AI agents into systems that move money, change permissions, and
              delete production. This report measures one thing: can the agent take a dangerous action
              <b> without an accountable human approval anyone can later verify?</b>
            </p>
          </div>
        </section>

        <section style={{ ...styles.section, background: '#1C1917', color: '#FAFAF9', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE HEADLINE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, color: '#FAFAF9', maxWidth: 820 }}>
              In every workflow we have tested so far, the dangerous action could run with no receipt
              at all — until a gate was added.
            </h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16, color: 'rgba(250,250,249,0.72)' }}>
              The aggregate percentage is computed from real scans as the corpus grows — we publish the
              methodology here rather than a number we cannot stand behind. Run{' '}
              <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> on your stack to contribute a data point.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>METHODOLOGY</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>What the fire drill measures.</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              For each operation in an MCP manifest, OpenAPI spec, or tool list, the scanner classifies
              it into a high-risk family and checks whether a dangerous one can execute without a
              receipt requirement. The <b>Agent Action Firewall score</b> is the share of dangerous
              operations that require a receipt; <b>EG-1</b> passes only when that share is 100%.
            </p>
            <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {FAMILIES.map(([name, ex]) => (
                <div key={name} style={{ borderTop: `1px solid ${color.border}`, paddingTop: 14 }}>
                  <div style={{ ...styles.h3, fontSize: 16 }}>{name}</div>
                  <div style={{ ...styles.body, fontSize: 13, color: color.t2, marginTop: 6, fontFamily: font.mono }}>{ex}</div>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 24, maxWidth: 720 }}>
              Static assessment from the manifest/spec — like SSL Labs or <code style={{ fontFamily: font.mono }}>npm audit</code>.
              A passing fix is verified at runtime with EG-1 conformance.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
              <a href="/fire-drill" style={cta.primary}>Run the fire drill</a>
              <a href="/fire-drill/gallery" style={cta.secondary}>See the index</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
