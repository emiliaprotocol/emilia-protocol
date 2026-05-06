'use client';

import { useEffect } from 'react';
import Image from 'next/image';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import { ENTITY, FOUNDERS, ADVISORS } from '@/lib/site-config';

export default function AboutPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge">About</div>
        <h1 className="ep-hero-text" style={styles.h1}>The team behind EMILIA Protocol</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          EMILIA Protocol is an open standard for verifiable pre-action authorization. The protocol is formally verified — 26 TLA+ theorems and 35 Alloy facts run in CI on every change — and the reference runtime is Apache 2.0. Below: the people responsible for it, the advisors guiding it, and the entity behind it.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Mission</h2>
        <p className="ep-reveal" style={styles.body}>
          For consequential, irreversible actions — wire transfers, benefit redirects, infrastructure changes, AI-agent-issued operations — session-level and scope-level authorization stop short of what the action itself needs. We build the layer that binds authorization to the exact action and to a named human, so the system refuses to execute anything that isn't both authorized and accountable.
        </p>
        <p className="ep-reveal" style={styles.body}>
          We treat this as standards work, not platform work. The protocol is open. The reference implementation is open. The conformance suite is open. The trust layer for AI-era infrastructure has to be inspectable, or it isn't trust.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Team</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {FOUNDERS.map((f, i) => (
            <div key={i} className="ep-reveal" style={{
              border: `1px solid ${color.border}`,
              borderRadius: radius.base,
              padding: '24px',
              background: '#FAFAF9',
            }}>
              {f.photo ? (
                <Image
                  src={f.photo}
                  alt={f.name}
                  width={80}
                  height={80}
                  style={{ borderRadius: '50%', marginBottom: 16, objectFit: 'cover' }}
                />
              ) : (
                <div style={{
                  width: 80, height: 80, borderRadius: '50%',
                  background: `linear-gradient(135deg, ${color.gold}33, ${color.blue}33)`,
                  marginBottom: 16,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: font.mono, fontSize: 22, fontWeight: 700, color: color.t1,
                }}>
                  {f.name && !f.name.startsWith('TODO') ? f.name.split(/\s+/).map(n => n[0]).slice(0, 2).join('') : 'EP'}
                </div>
              )}
              <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, color: color.t1, marginBottom: 4 }}>
                {f.name}
              </div>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 12 }}>
                {f.role}
              </div>
              <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.65, marginBottom: 12 }}>
                {f.bio}
              </p>
              {f.linkedin && (
                <a href={f.linkedin} target="_blank" rel="noopener noreferrer" style={{ fontFamily: font.mono, fontSize: 11, color: color.blue, textDecoration: 'none' }}>
                  LinkedIn →
                </a>
              )}
            </div>
          ))}
        </div>
        <p className="ep-reveal" style={{ ...styles.body, marginTop: 24, fontSize: 13, color: color.t3 }}>
          Procurement and partnership inquiries: <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue }}>{ENTITY.email}</a>
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Advisors</h2>
        {ADVISORS.length === 0 ? (
          <p className="ep-reveal" style={styles.body}>
            We are actively recruiting an advisory board across formal methods, federal regulatory, and financial-fraud-defense expertise. We will name advisors on this page only after each individual has confirmed engagement; an empty advisor list is more credible than a fabricated one. If you are a former OCC / FDIC / Federal Reserve examiner, a former Treasury / FinCEN / CISA official, a bank or credit-union CISO or fraud lead, or an academic cryptographer interested in this category, we would value the conversation. Reach <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue }}>{ENTITY.email}</a>.
          </p>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {ADVISORS.map((a, i) => (
              <div key={i} className="ep-reveal" style={{
                border: `1px solid ${color.border}`,
                borderRadius: radius.base,
                padding: '20px',
                background: '#FAFAF9',
              }}>
                <div style={{ fontFamily: font.sans, fontSize: 16, fontWeight: 700, color: color.t1, marginBottom: 4 }}>{a.name}</div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 8 }}>{a.title}</div>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.6 }}>{a.bio}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Entity</h2>
        <div className="ep-reveal" style={{
          border: `1px solid ${color.border}`,
          borderRadius: radius.base,
          padding: '24px',
          background: '#FAFAF9',
          fontFamily: font.mono,
          fontSize: 13,
          color: color.t2,
          lineHeight: 1.8,
        }}>
          <div><span style={{ color: color.t3 }}>Legal name —</span> {ENTITY.legalName}</div>
          <div><span style={{ color: color.t3 }}>Entity type —</span> {ENTITY.entityType}</div>
          <div><span style={{ color: color.t3 }}>Jurisdiction —</span> {ENTITY.jurisdiction}</div>
          <div><span style={{ color: color.t3 }}>Address —</span> {ENTITY.address}</div>
          {ENTITY.registrationNumber && (
            <div><span style={{ color: color.t3 }}>Registration —</span> {ENTITY.registrationNumber}</div>
          )}
          <div style={{ marginTop: 12 }}>
            <span style={{ color: color.t3 }}>Inquiries —</span> <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue, textDecoration: 'none' }}>{ENTITY.email}</a>
          </div>
        </div>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Read the work</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/protocol" className="ep-cta" style={cta.primary}>Read the protocol</a>
          <a href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the spec</a>
          <a href="/security" className="ep-cta-ghost" style={cta.ghost}>Trust & security →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
