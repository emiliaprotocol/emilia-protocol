// SPDX-License-Identifier: Apache-2.0
// /fire-drill/report/[slug] — a per-MCP Fire Drill REPORT for a VERIFIED target.
// Unlike the registry-level pages (name/description signal), each report here
// cites a real dangerous handler read from the repo source (file + symbol +
// verbatim quote), states it currently runs unguarded, proposes the Receipt
// Required wrapper, and shows the after-patch RR-1 outcomes. Non-shaming:
// it ends at "earn RR-1", and reports go live in tandem with the fix PR.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import reports from '../../../../packages/fire-drill/reports.json';

const PUBLISHED = reports.reports.filter((r) => r.published);
const BY_SLUG = Object.fromEntries(PUBLISHED.map((r) => [r.slug, r]));

const FAMILY_LABEL = {
  money_movement: 'money movement',
  production_deploy: 'production deploy',
  data_destruction: 'data destruction',
  permission_change: 'permission change',
  data_export: 'data export',
  webhook: 'external dispatch / webhook',
};

export function generateStaticParams() {
  return PUBLISHED.map((r) => ({ slug: r.slug }));
}

export function generateMetadata({ params }) {
  const r = BY_SLUG[params.slug];
  if (!r) return { title: 'Report not found — EMILIA Fire Drill' };
  return {
    title: `Fire Drill: ${r.name} — ${r.dangerous_tool} | EMILIA`,
    description: `EMILIA Fire Drill of ${r.name}: dangerous action ${r.dangerous_tool} (${FAMILY_LABEL[r.family] || r.family}) currently runs with no authorization receipt. Proposed fix: Receipt Required (RR-1).`,
  };
}

function StatusPill({ status }) {
  const map = {
    report_ready: { t: 'Report ready', c: color.t2 },
    pr_open: { t: 'Fix PR open', c: color.gold },
    merged: { t: 'RR-1 — merged', c: '#16a34a' },
  };
  const s = map[status] || map.report_ready;
  return (
    <span style={{ fontFamily: font.mono, fontSize: 12, color: s.c, border: `1px solid ${s.c}`, borderRadius: 10, padding: '2px 9px' }}>
      {s.t}
    </span>
  );
}

function Outcome({ n, label, result }) {
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'baseline', padding: '10px 0', borderTop: `1px solid ${color.border}` }}>
      <span style={{ fontFamily: font.mono, fontSize: 13, color: color.gold, minWidth: 20 }}>{n}</span>
      <span style={{ ...styles.body, fontSize: 14.5, color: color.t1, fontWeight: 600, minWidth: 260 }}>{label}</span>
      <span style={{ fontFamily: font.mono, fontSize: 12.5, color: '#16a34a' }}>{result}</span>
    </div>
  );
}

export default function FireDrillReportPage({ params }) {
  const r = BY_SLUG[params.slug];
  if (!r) notFound();
  const fam = FAMILY_LABEL[r.family] || r.family;

  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 22 }}>
          <div style={styles.container}>
            <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ ...styles.eyebrow, color: color.gold, margin: 0 }}>EMILIA FIRE DRILL · REPORT</div>
              <StatusPill status={r.status} />
            </div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>{r.name}</h1>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 18, marginTop: 14, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: font.mono, fontSize: 13, color: '#DC2626', textTransform: 'uppercase', letterSpacing: 1 }}>{fam}</span>
              <a href={r.repo} target="_blank" rel="noopener noreferrer" style={{ ...styles.body, fontSize: 13, color: color.gold, marginLeft: 'auto' }}>repository ↗</a>
            </div>
          </div>
        </section>

        {/* Dangerous action found */}
        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>Dangerous action found</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 10 }}>
              <code style={{ fontFamily: font.mono, color: color.t1 }}>{r.dangerous_tool}</code> — {r.dangerous_summary}
            </p>
            <pre style={{
              fontFamily: font.mono, fontSize: 12.5, color: color.t1, background: '#0b0e14',
              border: `1px solid ${color.border}`, borderRadius: 8, padding: '12px 14px', overflowX: 'auto', marginTop: 12,
            }}>{`// ${r.handler_file}  ·  ${r.handler_symbol}\n${r.handler_quote}`}</pre>
            <p style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 14, maxWidth: 760 }}>
              <b style={{ color: '#DC2626' }}>Currently:</b> {r.currently}
            </p>
          </div>
        </section>

        {/* Proposed fix + after-patch */}
        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <h2 style={styles.h2}>Proposed fix — Receipt Required</h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 10 }}>{r.proposed_fix}</p>
            <h3 style={{ ...styles.body, fontSize: 14, fontWeight: 700, color: color.t1, marginTop: 22 }}>Result after patch (RR-1):</h3>
            <div style={{ marginTop: 6 }}>
              <Outcome n="1" label="Missing receipt" result={r.after_patch.missing} />
              <Outcome n="2" label="Valid receipt" result={r.after_patch.valid} />
              <Outcome n="3" label="Replayed receipt" result={r.after_patch.replay} />
              <Outcome n="4" label="Forged receipt" result={r.after_patch.forged} />
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 24, alignItems: 'center', flexWrap: 'wrap' }}>
              {r.pr_url ? (
                <a href={r.pr_url} target="_blank" rel="noopener noreferrer" style={cta.primary}>View the fix PR ↗</a>
              ) : (
                <a href="https://www.npmjs.com/package/@emilia-protocol/require-receipt" target="_blank" rel="noopener noreferrer" style={cta.primary}>Earn RR-1</a>
              )}
              <Link href="/fire-drill/rr-1" style={cta.secondary}>What is RR-1?</Link>
              {/* eslint-disable-next-line @next/next/no-img-element -- static SVG badge, next/image is overkill */}
              <img src="/badges/rr-1.svg" alt="Receipt Required: RR-1" width={178} height={20} style={{ marginLeft: 'auto' }} />
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, maxWidth: 760 }}>
              Scope: this is a static reference-implementation assessment of a <b>missing human-authorization receipt</b> on one
              irreversible action, derived from the repository&rsquo;s public source. It is <b>not</b> a vulnerability report, not a
              claim the action is exploitable, and not auth or permissions. {r.maintainer_note}
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
