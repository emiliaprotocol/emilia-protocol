// SPDX-License-Identifier: Apache-2.0
// /fire-drill/registry — index of MCP-registry servers that ADVERTISE a high-risk
// capability and publish a repo. Registry-level signal (name + description), not
// a tool-level scan. Each row backlinks to the real repo + its result page.

import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import { REGISTRY_CORPUS } from '../../../packages/fire-drill/registry-corpus.js';
import registryIndex from '../../../packages/fire-drill/registry-index.json';
import reports from '../../../packages/fire-drill/reports.json';

export const metadata: Metadata = {
  title: 'Agent Action Firewall — MCP registry index (43,800 servers) | EMILIA',
  description: `Scanned the full public MCP registry: ${registryIndex.servers_scanned.toLocaleString()} servers, ${registryIndex.pct_advertise_high_risk}% advertise a high-risk capability. Registry-level signal (name + description), not a tool-level scan.`,
};

const FAMILY_LABEL = {
  money: 'money movement', data: 'data destruction', deploy: 'deploy / infra',
  permission: 'permissions', export: 'data export', regulated: 'regulated',
};

export default function RegistryIndexPage() {
  const byFamily: Record<string, any[]> = {};
  for (const s of REGISTRY_CORPUS) (byFamily[s.family] ||= []).push(s);
  const families = Object.entries(byFamily).sort((a, b) => b[1].length - a[1].length);

  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 24 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>AGENT ACTION FIREWALL · REGISTRY INDEX</div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>
              {registryIndex.servers_scanned.toLocaleString()} MCP servers scanned ·{' '}
              <span style={{ color: '#DC2626' }}>{registryIndex.advertise_high_risk.toLocaleString()}</span> advertise a high-risk capability
            </h1>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
              We scanned the entire public MCP registry ({registryIndex.source}) — every registered server&rsquo;s advertised
              name and description. <b>{registryIndex.pct_advertise_high_risk}%</b> advertise a capability that can move money,
              destroy or export data, deploy infrastructure, or change permissions. For agent use, every one of those should
              require an accountable human authorization receipt before it runs.
            </p>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 14, maxWidth: 760 }}>
              Registry-level signal (name + description), not a tool-level manifest scan or a deployment scan or a vulnerability
              report. Listed below: {REGISTRY_CORPUS.length} high-risk-advertising servers that publish a repo. We&rsquo;re testing
              the ecosystem for receipt-required dangerous actions — maintainers can <a href="/fire-drill/rr-1" style={{ color: color.gold }}>earn RR-1</a> and
              make their most dangerous action safer than the default.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
              <Link href="/fire-drill/rr-1" style={cta.primary}>Earn RR-1</Link>
              <Link href="/fire-drill/report" style={cta.secondary}>Full report</Link>
            </div>
          </div>
        </section>

        {reports.reports.filter((r) => r.published).length > 0 && (
          <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
            <div style={styles.container}>
              <div style={{ ...styles.eyebrow, color: color.gold }}>VERIFIED FIRE DRILL REPORTS · {reports.reports.filter((r) => r.published).length}</div>
              <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 8, maxWidth: 760 }}>
                Where we read the source and confirmed a real dangerous handler, the report cites the exact code and the
                Receipt Required fix. Each is a path to RR-1, not a callout.
              </p>
              <div style={{ marginTop: 8 }}>
                {reports.reports.filter((r) => r.published).map((r) => (
                  <div key={r.slug} style={{ display: 'flex', gap: 14, alignItems: 'center', padding: '11px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                    <Link href={`/fire-drill/report/${r.slug}`} style={{ ...styles.body, fontSize: 14, color: color.t1, minWidth: 260, fontWeight: 600 }}>{r.name}</Link>
                    <span style={{ fontFamily: font.mono, fontSize: 12, color: '#DC2626' }}>{r.dangerous_tool}</span>
                    <Link href={`/fire-drill/report/${r.slug}`} style={{ ...styles.body, fontSize: 13, color: color.gold, marginLeft: 'auto' }}>report →</Link>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {families.map(([fam, servers]) => (
          <section key={fam} style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
            <div style={styles.container}>
              <div style={styles.eyebrow}>{(FAMILY_LABEL[fam] || fam).toUpperCase()} · {servers.length}</div>
              <div style={{ marginTop: 8 }}>
                {servers.map((s) => (
                  <div key={s.slug} style={{ display: 'flex', gap: 14, alignItems: 'center', padding: '11px 0', borderTop: `1px solid ${color.border}`, flexWrap: 'wrap' }}>
                    <a href={`/fire-drill/registry/${s.slug}`} style={{ ...styles.body, fontSize: 14, color: color.t1, minWidth: 260, fontWeight: 600 }}>{s.name}</a>
                    <span style={{ fontFamily: font.mono, fontSize: 12, color: '#DC2626' }}>advertises {FAMILY_LABEL[s.family] || s.family}</span>
                    <a href={s.repo} target="_blank" rel="noopener noreferrer" style={{ ...styles.body, fontSize: 13, color: color.gold, marginLeft: 'auto' }}>repo ↗</a>
                  </div>
                ))}
              </div>
            </div>
          </section>
        ))}
      </main>
      <SiteFooter />
    </>
  );
}
