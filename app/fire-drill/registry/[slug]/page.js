// SPDX-License-Identifier: Apache-2.0
// /fire-drill/registry/[slug] — a public, indexable Agent Action Firewall
// REGISTRY result for a named MCP server. This is a registry-level signal
// (server name + description advertise a high-risk capability), NOT a tool-level
// scan and NOT a vulnerability claim. Links to the real repo (backlink) and
// routes the maintainer to a schema and runtime review.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import { REGISTRY_CORPUS } from '../../../../packages/fire-drill/registry-corpus.js';

const BY_SLUG = Object.fromEntries(REGISTRY_CORPUS.map((c) => [c.slug, c]));

const FAMILY_LABEL = {
  money: 'money movement',
  data: 'data destruction / mutation',
  deploy: 'deploy / infrastructure',
  permission: 'permission / access control',
  export: 'data export',
  regulated: 'regulated action',
};

export function generateStaticParams() {
  return REGISTRY_CORPUS.map((c) => ({ slug: c.slug }));
}

export function generateMetadata({ params }) {
  const c = BY_SLUG[params.slug];
  if (!c) return { title: 'Server not found — EMILIA Fire Drill' };
  const fam = FAMILY_LABEL[c.family] || c.family;
  return {
    title: `${c.name} — advertises ${fam} | Agent Action Firewall (EMILIA)`,
    description: `${c.name} advertises a high-risk ${fam} capability in the public MCP registry. Registry-level signal (name + description), not a tool-level scan. If it acts for an AI agent, it should require an authorization receipt.`,
  };
}

export default function RegistryScanPage({ params }) {
  const c = BY_SLUG[params.slug];
  if (!c) notFound();
  const fam = FAMILY_LABEL[c.family] || c.family;

  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 28 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>AGENT ACTION FIREWALL · REGISTRY SIGNAL</div>
            <h1 style={{ ...styles.h1, marginTop: 14 }}>{c.name}</h1>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 20, marginTop: 16, flexWrap: 'wrap' }}>
              <div style={{ fontFamily: font.mono, fontSize: 14, color: '#DC2626', letterSpacing: 1, textTransform: 'uppercase' }}>
                advertises {fam}
              </div>
              <a href={c.repo} target="_blank" rel="noopener noreferrer" style={{ ...styles.body, fontSize: 14, color: color.gold, marginLeft: 'auto' }}>repository ↗</a>
            </div>
            {c.description ? (
              <p style={{ ...styles.body, maxWidth: 720, marginTop: 16, color: color.t2, fontStyle: 'italic' }}>“{c.description}”</p>
            ) : null}
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              This server&rsquo;s public MCP-registry listing advertises a <b>{fam}</b> capability. If it performs that action
              on behalf of an AI agent, it should require an <b>accountable human authorization receipt</b> before executing —
              The listing alone does not reveal whether that action is exposed, gated, or executed in a deployment.
            </p>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={{ ...styles.h2, maxWidth: 760 }}>Is this your project? Publish the tool schema and test the runtime.</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 14 }}>
              Wrap the high-risk tools with <code style={{ fontFamily: font.mono }}>@emilia-protocol/gate</code> so they require a
              receipt evidence, then run <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code> against
              your manifest for static declaration coverage and the separate EG-1 suite against the deployed handler.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 24, flexWrap: 'wrap' }}>
              <a href="/gate#eg1" style={cta.primary}>How to earn EG-1</a>
              <a href="/fire-drill" style={cta.secondary}>Run it yourself</a>
              <Link href="/fire-drill/registry" style={cta.secondary}>Full registry index</Link>
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 22, maxWidth: 720 }}>
              Registry-level signal only: derived from this server&rsquo;s publicly-advertised name and description in
              registry.modelcontextprotocol.io. It is <b>not</b> a scan of any deployment, <b>not</b> a tool-level manifest scan,
              and <b>not</b> a vulnerability report. It indicates the server advertises a capability that, for agent use, warrants
              a receipt requirement.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
