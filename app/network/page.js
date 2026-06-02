'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

const C = ({ children, style }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

const COMPOUND = [
  { num: '01', title: 'One vendor issues a receipt', body: 'A company publishes a signed Trust Receipt for a high-risk action. It is portable, offline-verifiable evidence — not a logo on a slide.' },
  { num: '02', title: 'The next party verifies it', body: 'Their counterparty checks the receipt with @emilia-protocol/verify. No account, no API key, no trust in us required — just Ed25519 and a Merkle proof.' },
  { num: '03', title: 'Verification becomes the expectation', body: 'Once one side demands receipts, the other supplies them. Agent A checks Agent B before collaborating. The network — not any vendor — becomes the standard.' },
];

const EMBED_SNIPPET = `<script src="https://www.emiliaprotocol.ai/embed.js"></script>
<ep-trust-badge entity-id="ep_entity_..."></ep-trust-badge>`;

function StatCard({ value, label, accent }) {
  return (
    <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', padding: '26px 24px' }}>
      <div style={{ width: 3, height: 38, borderRadius: 2, background: accent, flexShrink: 0, marginTop: 2 }} />
      <div>
        <div style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, color: accent, letterSpacing: -0.5, lineHeight: 1 }}>{value}</div>
        <div style={{ fontFamily: font.mono, fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t3, marginTop: 8 }}>{label}</div>
      </div>
    </div>
  );
}

export default function NetworkPage() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    let live = true;
    fetch('/api/stats')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (live && d) setStats(d); })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const fmt = (v) => (typeof v === 'number' ? v.toLocaleString() : '—');

  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="" />

      {/* HERO */}
      <section style={{ paddingTop: 120, paddingBottom: 56 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
            The EMILIA Trust Network
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(38px, 5vw, 64px)', letterSpacing: -2.2, lineHeight: 1.0, color: color.t1, margin: '0 0 24px', maxWidth: 800 }}>
            Trust that compounds, not trust you take on faith.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: '0 0 40px' }}>
            Every action gated by EMILIA can produce a receipt anyone can verify &mdash; offline, with
            math, without trusting us. As entities issue and verify each other&rsquo;s receipts, the
            network becomes the place the AI-agent economy checks before it acts.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/explorer" className="ep-cta" style={cta.primary}>Verify a receipt &rarr;</Link>
            <Link href="/adopt" className="ep-cta-secondary" style={cta.secondary}>Join the network</Link>
          </div>
        </C>
      </section>

      {/* LIVE STATS */}
      <section style={{ borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`, background: 'rgba(245,244,240,0.45)' }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)' }}>
            {[
              { value: fmt(stats?.total_entities), label: 'Registered Entities', accent: color.t1 },
              { value: fmt(stats?.trust_policies), label: 'Trust Policies', accent: color.blue },
              { value: fmt(stats?.automated_checks), label: 'Automated Checks', accent: color.gold },
              { value: fmt(stats?.mcp_tools), label: 'MCP Tools', accent: color.green },
            ].map((s, i) => (
              <div key={s.label} style={{ borderRight: i < 3 ? `1px solid ${color.border}` : 'none' }}>
                <StatCard {...s} />
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* HOW IT COMPOUNDS */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
            Why a network, not a tool
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 36px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 560, marginBottom: 48 }}>
            Each verified receipt makes the next one more valuable.
          </h2>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {COMPOUND.map((item) => (
              <div key={item.num} style={{ display: 'grid', gridTemplateColumns: '90px 1fr', gap: 40, alignItems: 'start', padding: '36px 0', borderBottom: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 22, fontWeight: 700, color: 'rgba(12,10,9,0.12)' }}>{item.num}</div>
                <div>
                  <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 17, color: color.t1, marginBottom: 8 }}>{item.title}</h3>
                  <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, margin: 0, maxWidth: 620 }}>{item.body}</p>
                </div>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* EMBED BADGE */}
      <section style={{ padding: '88px 0', background: 'rgba(245,244,240,0.45)', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 56, alignItems: 'center' }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                Show it, don&rsquo;t claim it
              </div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(22px, 2.6vw, 32px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, marginBottom: 16 }}>
                Embed a live trust badge anywhere.
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, marginBottom: 20 }}>
                One script tag, one web component. The badge pulls live data from the network &mdash; it
                can&rsquo;t be faked, because the number isn&rsquo;t yours to set. Links straight to the
                Explorer for full verification.
              </p>
              <Link href="/adopt" style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 0.5, textDecoration: 'underline', textUnderlineOffset: 3 }}>
                Get your badge &rarr;
              </Link>
            </div>
            <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.7, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px', margin: 0, overflowX: 'auto', whiteSpace: 'pre' }}>{EMBED_SNIPPET}</pre>
          </div>
        </C>
      </section>

      {/* CTA */}
      <section style={{ padding: '88px 0' }}>
        <C>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 32, flexWrap: 'wrap' }}>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 3vw, 38px)', letterSpacing: -1.2, lineHeight: 1.1, color: color.t1, maxWidth: 520, margin: 0 }}>
              Put your trust on the record.
            </h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/adopt" className="ep-cta" style={cta.primary}>Register an entity</Link>
              <Link href="/explorer" className="ep-cta-secondary" style={cta.secondary}>Explore the network</Link>
            </div>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
