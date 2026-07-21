// SPDX-License-Identifier: Apache-2.0
// /fire-drill/report — The Agent Action Firewall Report (methodology edition).
// Honest framing: we publish the methodology now; the aggregate figure is
// populated from real scans, not invented.

import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import { scan, aggregate } from '../../../packages/fire-drill/index.js';
import { REPRESENTATIVE_CORPUS } from '../../../packages/fire-drill/corpus.js';
// Registry-wide signal: name+description scan of the public MCP registry
// (coarser than tool-level). Produced by `node packages/fire-drill/ingest.mjs`.
import REGISTRY from '../../../packages/fire-drill/registry-index.json';

// Computed live over a representative sample of common MCP server tool surfaces.
// Honest scope: a sample, not the whole ecosystem — run `corpus.mjs <dir>` to expand.
const INDEX = aggregate(REPRESENTATIVE_CORPUS.map((c) => scan(c.manifest)));

export const metadata: Metadata = {
  title: 'The Receipt Declaration Report — EMILIA',
  description: 'A static, revision-pinned view of where documented high-risk agent tools declare required receipt evidence.',
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
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE RECEIPT DECLARATION REPORT</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Where do documented agent tools require evidence?</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              The market is wiring AI agents into systems that move money, change permissions, and
              delete production. This report measures a narrower question: does the documented tool
              surface declare a required receipt input for a detected high-risk action?
            </p>
          </div>
        </section>

        <section style={{ ...styles.section, background: '#1C1917', color: '#FAFAF9', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE HEADLINE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, color: '#FAFAF9', maxWidth: 880 }}>
              We ran the fire drill across <span style={{ color: color.gold }}>{REGISTRY.servers_scanned.toLocaleString()}</span>
              {' '}servers in the public MCP registry. At least <span style={{ color: color.gold }}>{REGISTRY.pct_advertise_high_risk}%</span>
              {' '}advertise a high-risk capability — and in a tool-level sample, <span style={{ color: color.gold }}>{INDEX.pct_servers_missing_declaration}%</span>
              {' '}omit a required receipt declaration on at least one detected dangerous tool.
            </h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16, color: 'rgba(250,250,249,0.72)' }}>
              Two lenses, both honest. <b>Registry-wide</b> ({REGISTRY.servers_scanned.toLocaleString()} servers): a scan of each
              server's advertised name + description — a conservative floor, since most servers don't name a dangerous verb
              in their blurb. <b>Tool-level</b> ({INDEX.servers}-server sample, {INDEX.missing_declarations} missing declarations,
              mean static score {INDEX.mean_score}/100): the deeper look at documented schemas. Neither is a live
              deployment scan, a vulnerability claim, or evidence that declared controls are enforced. Run{' '}
              <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> on your stack to add a data point.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>METHODOLOGY</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>What the fire drill measures.</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              For each operation in an MCP manifest, OpenAPI spec, or tool list, the scanner classifies
              it into a high-risk family and checks whether a dangerous one structurally declares a
              required receipt input. The score is the share of detected dangerous operations with
              that declaration. <b>EG-1 is not assessed by this report.</b>
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
              Static assessment from the manifest/spec. A complete declaration result is a review
              prerequisite only; runtime verification, trust anchoring, and replay consumption require EG-1 conformance.
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
