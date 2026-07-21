/**
 * Animated protocol ceremony schematic — four phases of the EP lifecycle.
 * Uses Motion (motion/react) for:
 *   - spine line draw (pathLength 0→1)
 *   - phase cards staggered slide-in from right
 *   - dot spring pop-in per phase
 *   - repeating pulse ring on the active (first) node
 */
'use client';

import { motion } from 'motion/react';
import { color } from '@/lib/tokens';

const FONT_SANS = "'IBM Plex Sans', -apple-system, sans-serif";
const FONT_MONO = "'IBM Plex Mono', 'Menlo', monospace";
const EASE: [number, number, number, number] = [0.23, 1, 0.32, 1];

const PHASES = [
  { id: 'eye',       num: '01', label: 'EYE',       verb: 'observes',  accent: color.green },
  { id: 'handshake', num: '02', label: 'HANDSHAKE', verb: 'verifies',  accent: color.blue  },
  { id: 'signoff',   num: '03', label: 'SIGNOFF',   verb: 'owns',      accent: color.gold  },
  { id: 'commit',    num: '04', label: 'COMMIT',    verb: 'seals',     accent: '#78716C'   },
];

type HeroStaticProps = Record<string, never>;

export default function HeroStatic({}: HeroStaticProps) {
  return (
    <div
      role="img"
      aria-label="Four-phase EMILIA Protocol ceremony: Eye observes, Handshake verifies, Signoff owns, Commit seals."
      style={{
        width: '100%',
        aspectRatio: '600 / 560',
        borderRadius: 4,
        border: `1px solid ${color.border}`,
        background: '#FAFAF9',
        overflow: 'hidden',
        position: 'relative',
      }}
    >
      <svg
        viewBox="0 0 600 560"
        width="100%"
        height="100%"
        preserveAspectRatio="xMidYMid meet"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="hero-spine" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor={color.green} stopOpacity="0.7" />
            <stop offset="33%"  stopColor={color.blue}  stopOpacity="0.7" />
            <stop offset="66%"  stopColor={color.gold}  stopOpacity="0.7" />
            <stop offset="100%" stopColor="#78716C"     stopOpacity="0.7" />
          </linearGradient>
          <pattern id="hero-grid" width="24" height="24" patternUnits="userSpaceOnUse">
            <path d="M 24 0 L 0 0 0 24" fill="none" stroke={color.border} strokeWidth="0.5" opacity="0.4" />
          </pattern>
        </defs>

        {/* background grid */}
        <rect width="600" height="560" fill="url(#hero-grid)" />

        {/* eyebrow label */}
        <motion.text
          x="40" y="50"
          fontFamily={FONT_MONO}
          fontSize="10"
          letterSpacing="2"
          fill={color.t3}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.1, ease: EASE }}
        >
          PROTOCOL CEREMONY · 4 PHASES
        </motion.text>

        {/* spine line — draws downward */}
        <motion.path
          d="M 80 108 L 80 492"
          stroke="url(#hero-spine)"
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ pathLength: { duration: 1.4, delay: 0.25, ease: EASE }, opacity: { duration: 0.2, delay: 0.25 } }}
        />

        {/* phase groups — staggered slide + fade from right */}
        {PHASES.map((phase, i) => {
          const y = 120 + i * 100;
          const delay = 0.3 + i * 0.13;
          return (
            <motion.g
              key={phase.id}
              initial={{ opacity: 0, x: 28 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.55, delay, ease: EASE }}
            >
              {/* outer ring — subtle, static */}
              <circle
                cx="80" cy={y} r="14"
                fill="none" stroke={phase.accent}
                strokeWidth="1" opacity="0.25"
              />

              {/* core dot — spring pop */}
              <motion.circle
                cx="80" cy={y} r="8"
                fill={phase.accent}
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 280, damping: 14, delay: delay + 0.04 }}
                style={{ transformOrigin: `80px ${y}px` }}
              />

              {/* repeating pulse ring on the first (active) phase only */}
              {i === 0 && (
                <motion.circle
                  cx="80" cy={y} r="14"
                  fill="none" stroke={phase.accent}
                  strokeWidth="1.5"
                  initial={{ scale: 1, opacity: 0.5 }}
                  animate={{ scale: 2.2, opacity: 0 }}
                  transition={{ duration: 1.8, delay: 0.9, ease: 'easeOut', repeat: Infinity, repeatDelay: 1.6 }}
                  style={{ transformOrigin: `80px ${y}px` }}
                />
              )}

              {/* horizontal connector */}
              <line
                x1="94" y1={y} x2="160" y2={y}
                stroke={color.border} strokeWidth="1"
              />

              {/* card background */}
              <rect
                x="160" y={y - 32}
                width="384" height="64"
                rx="6"
                fill="#FFFFFF"
                stroke={color.border}
                strokeWidth="1"
              />

              {/* left accent border */}
              <rect
                x="160" y={y - 32}
                width="3.5" height="64"
                rx="1.5"
                fill={phase.accent}
              />

              {/* phase number */}
              <text
                x="178" y={y - 10}
                fontFamily={FONT_MONO} fontSize="10"
                letterSpacing="2" fill={color.t3}
              >
                {phase.num}
              </text>

              {/* phase label */}
              <text
                x="178" y={y + 8}
                fontFamily={FONT_SANS} fontSize="15"
                fontWeight="700" fill={color.t1}
              >
                {phase.label}
              </text>

              {/* phase verb */}
              <text
                x="178" y={y + 24}
                fontFamily={FONT_MONO} fontSize="10"
                letterSpacing="1" fill={color.t2}
              >
                {phase.verb}
              </text>

              {/* BOUND status pill */}
              <rect
                x="490" y={y - 10}
                width="42" height="20"
                rx="4"
                fill={phase.accent}
                opacity="0.12"
              />
              <text
                x="511" y={y + 4}
                fontFamily={FONT_MONO} fontSize="9"
                fontWeight="600" letterSpacing="1.5"
                fill={phase.accent} textAnchor="middle"
              >
                BOUND
              </text>
            </motion.g>
          );
        })}

        {/* footer caption */}
        <motion.text
          x="80" y="535"
          fontFamily={FONT_MONO} fontSize="10"
          letterSpacing="1" fill={color.t3}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.9, ease: EASE }}
        >
          Each phase emits a cryptographic event. The chain commits — or refuses.
        </motion.text>
      </svg>
    </div>
  );
}
