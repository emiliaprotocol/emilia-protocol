'use client';

import SiteNav from '@/components/SiteNav';

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  section: { maxWidth: 600, margin: '0 auto', padding: '100px 24px 80px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 16 },
  h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 44px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
  body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 32 },
  card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: '32px 28px', marginBottom: 16 },
  cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, marginBottom: 8 },
  cardDesc: { fontSize: 14, color: '#94A3B8', lineHeight: 1.65, marginBottom: 8 },
  link: { fontSize: 14, color: '#3B82F6', textDecoration: 'none' },
};

export default function ContactPage() {
  return (
    <div style={s.page}>
      <SiteNav activePage="Contact" />
      <div style={s.section}>
        <div style={s.eyebrow}>Contact</div>
        <h1 style={s.h1}>Get in touch</h1>
        <p style={s.body}>We are available to discuss protocol integrations, pilot programs, and partnership opportunities.</p>

        <div style={s.card}>
          <div style={s.cardTitle}>General Inquiries</div>
          <div style={s.cardDesc}>For questions about EMILIA Protocol, integrations, or collaboration.</div>
          <a href="mailto:team@emiliaprotocol.ai" style={s.link}>team@emiliaprotocol.ai</a>
        </div>

        <div style={s.card}>
          <div style={s.cardTitle}>Pilot Program</div>
          <div style={s.cardDesc}>Interested in running a pilot? Submit a request through our partner portal.</div>
          <a href="/partners" style={s.link}>Request a Pilot &#8594;</a>
        </div>

        <div style={s.card}>
          <div style={s.cardTitle}>Investor Relations</div>
          <div style={s.cardDesc}>For investment inquiries and funding discussions.</div>
          <a href="/investors" style={s.link}>Investor Information &#8594;</a>
        </div>
      </div>
    </div>
  );
}
