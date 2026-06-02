'use client';

/**
 * CrashTestDemo — hero panel telling the "agent that tried to" story in one frame.
 * @license Apache-2.0
 *
 * Holds aspectRatio 600/560 to match the old HeroStatic so the hero grid does
 * not reflow. Mirrors the real /r/example vendor-bank-change scenario. CTA → /demo.
 */

import Link from 'next/link';
import { motion } from 'motion/react';
import { color, font, radius } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1];

export default function CrashTestDemo() {
  const step = (delay) => ({
    initial: { opacity: 0, y: 8 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.5, delay, ease: EASE },
  });
  return (
    <div
      role="img"
      aria-label="An AI agent attempts a $2.4M wire to a new account; EMILIA blocks it pending a signed human approval."
      style={{
        width: '100%',
        aspectRatio: '600 / 560',
        borderRadius: radius.base,
        border: `1px solid ${color.border}`,
        background: '#0F172A',
        overflow: 'hidden',
        position: 'relative',
        padding: 'clamp(16px, 3vw, 26px)',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        boxSizing: 'border-box',
      }}
    >
      <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, color: '#94A3B8' }}>
        AGENT CONSOLE · pre-execution gate
      </div>

      <motion.div {...step(0.05)} style={lineDim}>
        agent&gt; reconciling invoices…
      </motion.div>
      <motion.div {...step(0.15)} style={{ ...lineRed }}>
        agent&gt; about to wire <b style={{ color: '#FCA5A5' }}>$2,400,000</b> to a new account
      </motion.div>

      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, delay: 0.45, ease: EASE }}
        style={{
          border: `2px solid ${color.red}`,
          background: 'rgba(220,38,38,0.10)',
          borderRadius: radius.base,
          padding: '14px 16px',
          marginTop: 4,
        }}
      >
        <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 700, color: '#F87171', letterSpacing: 1 }}>
          ⛔ BLOCKED — 403 SIGNOFF_REQUIRED
        </div>
        <div style={{ fontFamily: font.sans, fontSize: 13, color: '#FCA5A5', marginTop: 6, lineHeight: 1.5 }}>
          The agent cannot self-authorize an irreversible money move. A real human must sign off.
        </div>
      </motion.div>

      <motion.div {...step(0.75)} style={{ marginTop: 2 }}>
        <div style={lineDim}>✗ self-approval rejected — separation of duties</div>
        <div style={{ ...lineGold }}>✓ Controller approved · ✓ CFO Delegate approved</div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5, delay: 0.95 }}
        style={{
          border: `1px solid ${color.green}`,
          background: 'rgba(22,163,74,0.10)',
          borderRadius: radius.base,
          padding: '10px 14px',
        }}
      >
        <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 700, color: '#4ADE80', letterSpacing: 1 }}>
          ✓ COMMITTED · signed receipt
        </span>
      </motion.div>

      <div style={{ flex: 1 }} />
      <motion.div {...step(1.1)}>
        <Link
          href="/demo"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            fontFamily: font.sans,
            fontSize: 14,
            fontWeight: 600,
            color: '#0F172A',
            background: color.gold,
            padding: '11px 16px',
            borderRadius: radius.sm,
            textDecoration: 'none',
          }}
        >
          ▶ Run the live crash test
        </Link>
      </motion.div>
    </div>
  );
}

const lineDim = { fontFamily: font.mono, fontSize: 12.5, color: '#CBD5E1', lineHeight: 1.5 };
const lineRed = { fontFamily: font.mono, fontSize: 12.5, color: '#FCA5A5', lineHeight: 1.5 };
const lineGold = { fontFamily: font.mono, fontSize: 12.5, color: color.gold, lineHeight: 1.5, marginTop: 2 };
