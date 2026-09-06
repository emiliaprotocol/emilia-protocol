'use client';

import { useEffect } from 'react';
import Image from 'next/image';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import { ENTITY, FOUNDERS, ADVISORS, isPlaceholder } from '@/lib/site-config';

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
        <h1 className="ep-hero-text" style={styles.h1}>The company behind the work</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Your AI workforce needs management. Someone has to define each job, decide
          what the agent may do, and review its work. EMILIA is building that workspace,
          with authorization infrastructure for agentic AI underneath it.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>The agent can change. The job carries on.</h2>
        <p className="ep-reveal" style={styles.body}>
          Replacing an agent should not reset its allowance or lose track of unfinished
          work. The job needs a named owner, limits that stay accounted for, and a
          record of what happened. That is the problem we are working on.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EMILIA is the company. EMILIA Gate is the commercial product: the workforce
          workspace organizes jobs and assignments around Gate, which enforces the
          customer&rsquo;s authority on configured execution paths. The customer owns
          the limits, credentials and acceptance criteria.
        </p>
        <p className="ep-reveal" style={styles.body}>
          EMILIA Protocol is the open foundation. Its formats, verifiers, reference
          code and conformance artifacts are available without buying from us.
          Individual Internet-Drafts are proposals, not RFCs or IETF endorsement.
          You can <a href="/proof" style={{ color: color.blue }}>inspect the engineering evidence</a>.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The workforce workspace is an implemented private local alpha. It is not
          a hosted service or a customer deployment, and we have not measured customer
          ROI. We are seeking one finance team to evaluate a refunds workflow with a
          named owner and a clear acceptance test. Production credential custody,
          recovery and coverage need a separate deployment review.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Team</h2>
        {FOUNDERS.every(f => isPlaceholder(f.name)) ? (
          <div className="ep-reveal" style={{
            border: `1px solid ${color.border}`,
            borderRadius: radius.base,
            padding: '24px',
            background: '#FAFAF9',
          }}>
            <p style={{ ...styles.body, marginBottom: 12 }}>
              Team biographies are not yet listed on this page. You can see the open-source contributors on <a href="https://github.com/emiliaprotocol/emilia-protocol/graphs/contributors" target="_blank" rel="noopener noreferrer" style={{ color: color.blue }}>GitHub</a>.
            </p>
            <p style={{ ...styles.body, marginBottom: 0 }}>
              For workflow evaluations, procurement or partnership conversations, reach <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue }}>{ENTITY.email}</a>.
            </p>
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {FOUNDERS.filter(f => !isPlaceholder(f.name)).map((f, i) => (
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
                    {f.name.split(/\s+/).map(n => n[0]).slice(0, 2).join('')}
                  </div>
                )}
                <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, color: color.t1, marginBottom: 4 }}>{f.name}</div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 12 }}>{f.role}</div>
                {!isPlaceholder(f.bio) && (
                  <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.65, marginBottom: 12 }}>{f.bio}</p>
                )}
                {f.linkedin && (
                  <a href={f.linkedin} target="_blank" rel="noopener noreferrer" style={{ fontFamily: font.mono, fontSize: 11, color: color.blue, textDecoration: 'none' }}>
                    LinkedIn →
                  </a>
                )}
              </div>
            ))}
          </div>
        )}
        <p className="ep-reveal" style={{ ...styles.body, marginTop: 24, fontSize: 13, color: color.t3 }}>
          Procurement and partnership inquiries: <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue }}>{ENTITY.email}</a>
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Advisors</h2>
        {ADVISORS.length === 0 ? (
          <p className="ep-reveal" style={styles.body}>
            We welcome potential advisors in formal methods, financial controls
            and agent operations. Advisors will be listed after their
            engagement is confirmed. Contact <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue }}>{ENTITY.email}</a>.
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
        <h2 style={styles.h2}>Start with one real job</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/contact#workforce" className="ep-cta" style={cta.primary}>Discuss your workflow</a>
          <a href="/workforce" className="ep-cta-secondary" style={cta.secondary}>See the workforce product</a>
          <a href="/security" className="ep-cta-ghost" style={cta.ghost}>Trust & security →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
