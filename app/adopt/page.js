'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

/**
 * /adopt — Gradient of Commitment
 *
 * Shows the 7 adoption levels from "read-only verifier" to "federation operator."
 * Designed to make EP adoption feel low-risk and incremental.
 *
 * @license Apache-2.0
 */

const LEVELS = [
  {
    level: 0, name: 'Verifier', tag: 'Read-only',
    desc: 'Verify other people\'s receipts. Standalone library, no account needed.',
    how: 'npm install @emilia-protocol/verify',
    effort: '5 minutes', risk: 'None',
    color: '#16A34A',
  },
  {
    level: 1, name: 'Observer', tag: 'Read API',
    desc: 'Use EP to check trust scores before your AI agent acts. Read-only API access.',
    how: 'Call /api/trust/evaluate before high-risk actions',
    effort: '30 minutes', risk: 'None',
    color: '#16A34A',
  },
  {
    level: 2, name: 'Participant', tag: 'Submit receipts',
    desc: 'Submit trust receipts and build a public trust profile for your entities.',
    how: 'Register entities, submit receipts via API or SDK',
    effort: '1 hour', risk: 'Low',
    color: '#3B82F6',
  },
  {
    level: 3, name: 'Enforcer', tag: 'Handshake required',
    desc: 'Require handshake ceremonies before high-risk actions. Pre-action authorization.',
    how: 'Integrate EP Handshake into your action pipeline',
    effort: '1 day', risk: 'Medium',
    color: '#3B82F6',
  },
  {
    level: 4, name: 'Governor', tag: 'Human signoff',
    desc: 'Add EP Signoff requirements for human accountability on critical actions.',
    how: 'Configure signoff policies, assign named signers',
    effort: '1 week', risk: 'Medium',
    color: '#B08D35',
  },
  {
    level: 5, name: 'Operator', tag: 'Run your own node',
    desc: 'Run your own EP operator in the federation. Full sovereignty over your trust data.',
    how: 'Deploy EP Core, publish /.well-known/ep-trust.json',
    effort: '1 month', risk: 'Medium',
    color: '#B08D35',
  },
  {
    level: 6, name: 'Contributor', tag: 'Shape the protocol',
    desc: 'Submit PIPs, contribute code, run conformance tests. Shape the future of trust.',
    how: 'Fork the repo, submit a PIP, join governance',
    effort: 'Ongoing', risk: 'None',
    color: '#9333EA',
  },
];

function LevelCard({ l, index }) {
  return (
    <div style={{
      ...styles.card,
      padding: '24px 28px',
      borderLeft: `3px solid ${l.color}`,
      display: 'grid',
      gridTemplateColumns: '60px 1fr auto',
      gap: 20,
      alignItems: 'start',
    }}>
      {/* Level number */}
      <div style={{ textAlign: 'center' }}>
        <div style={{
          fontFamily: font.mono, fontSize: 28, fontWeight: 700, color: l.color, lineHeight: 1,
        }}>L{l.level}</div>
        <div style={{
          fontFamily: font.mono, fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase',
          color: color.t3, marginTop: 4,
        }}>{l.tag}</div>
      </div>

      {/* Content */}
      <div>
        <h3 style={{ fontFamily: font.sans, fontSize: 16, fontWeight: 700, color: color.t1, marginBottom: 6 }}>
          {l.name}
        </h3>
        <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, margin: 0, marginBottom: 10 }}>
          {l.desc}
        </p>
        <div style={{
          fontFamily: font.mono, fontSize: 12, color: color.t2,
          background: '#F5F5F4', padding: '8px 12px', borderRadius: radius.sm,
          display: 'inline-block',
        }}>
          {l.how}
        </div>
      </div>

      {/* Meta */}
      <div style={{ textAlign: 'right', minWidth: 80 }}>
        <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 0.5, marginBottom: 4 }}>
          EFFORT
        </div>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t1, fontWeight: 600 }}>
          {l.effort}
        </div>
        <div style={{
          fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 0.5, marginTop: 10, marginBottom: 4,
        }}>
          RISK
        </div>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t1, fontWeight: 600 }}>
          {l.risk}
        </div>
      </div>
    </div>
  );
}

export default function AdoptPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 40 }}>
        <div style={styles.eyebrow}>Adoption</div>
        <h1 style={styles.h1}>Start anywhere. Go as far as you need.</h1>
        <p style={{ ...styles.body, maxWidth: 600 }}>
          EP is useful from the first minute. Verify a receipt with zero setup — or run a full federation node. Every level is independently valuable. No lock-in, no commitment required.
        </p>
      </section>

      <section style={styles.section}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {LEVELS.map((l, i) => <LevelCard key={i} l={l} index={i} />)}
        </div>

        {/* Quick start CTA */}
        <div style={{
          marginTop: 48, textAlign: 'center',
          padding: '40px 32px',
          background: color.card,
          border: `1px solid ${color.border}`,
          borderRadius: radius.base,
        }}>
          <h2 style={{ ...styles.h2, marginBottom: 8 }}>Start at Level 0 in 30 seconds</h2>
          <p style={{ ...styles.body, maxWidth: 440, margin: '0 auto 24px' }}>
            Install the standalone verification library. Zero dependencies. No account. Just math.
          </p>
          <div style={{
            fontFamily: font.mono, fontSize: 14,
            background: '#0C0A09', color: '#F5F5F4',
            padding: '14px 24px', borderRadius: radius.sm,
            display: 'inline-block', marginBottom: 20,
          }}>
            npm install @emilia-protocol/verify
          </div>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 8 }}>
            <a href="/playground" style={cta.primary}>Open Playground</a>
            <a href="/explorer" style={cta.secondary}>Trust Explorer</a>
            <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" rel="noopener noreferrer" style={cta.secondary}>GitHub</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
