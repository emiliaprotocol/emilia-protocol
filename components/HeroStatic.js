/**
 * Static fallback shown above the fold while the Remotion-based
 * HeroAnimation hydrates. Without this the right panel renders as a
 * blank rectangle on first paint — the highest-stakes pixel on the site.
 *
 * The schematic depicts the four-phase EP ceremony (Eye → Handshake →
 * Signoff → Commit) so the visual is meaningful even if the dynamic
 * animation never loads (slow network, JS disabled, Remotion error).
 */

import { color } from '@/lib/tokens';

const FONT_SANS = "'IBM Plex Sans', -apple-system, sans-serif";
const FONT_MONO = "'IBM Plex Mono', 'Menlo', monospace";

const PHASES = [
  { id: 'eye',       label: 'EYE',       verb: 'observes',  accent: color.green },
  { id: 'handshake', label: 'HANDSHAKE', verb: 'verifies',  accent: color.blue },
  { id: 'signoff',   label: 'SIGNOFF',   verb: 'owns',      accent: color.gold },
  { id: 'commit',    label: 'COMMIT',    verb: 'seals',     accent: '#78716C' },
];

export default function HeroStatic() {
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
            <stop offset="0%"  stopColor={color.green} stopOpacity="0.6" />
            <stop offset="33%" stopColor={color.blue}  stopOpacity="0.6" />
            <stop offset="66%" stopColor={color.gold}  stopOpacity="0.6" />
            <stop offset="100%" stopColor="#78716C"   stopOpacity="0.6" />
          </linearGradient>
          <pattern id="hero-grid" width="24" height="24" patternUnits="userSpaceOnUse">
            <path d="M 24 0 L 0 0 0 24" fill="none" stroke={color.border} strokeWidth="0.5" opacity="0.4" />
          </pattern>
        </defs>

        <rect width="600" height="560" fill="url(#hero-grid)" />

        {/* eyebrow label */}
        <text
          x="40" y="50"
          fontFamily={FONT_MONO}
          fontSize="10"
          letterSpacing="2"
          fill={color.t3}
        >
          PROTOCOL CEREMONY · 4 PHASES
        </text>

        {/* vertical spine */}
        <line x1="80" y1="100" x2="80" y2="500" stroke="url(#hero-spine)" strokeWidth="2" />

        {/* phase nodes */}
        {PHASES.map((phase, i) => {
          const y = 120 + i * 100;
          return (
            <g key={phase.id}>
              {/* spine node */}
              <circle cx="80" cy={y} r="8" fill={phase.accent} />
              <circle cx="80" cy={y} r="14" fill="none" stroke={phase.accent} strokeWidth="1" opacity="0.3" />

              {/* horizontal connector */}
              <line x1="94" y1={y} x2="160" y2={y} stroke={color.border} strokeWidth="1" />

              {/* phase card */}
              <rect
                x="160" y={y - 32}
                width="380" height="64"
                rx="6"
                fill="#FFFFFF"
                stroke={color.border}
                strokeWidth="1"
              />
              <line x1="160" y1={y - 32} x2="164" y2={y + 32} stroke={phase.accent} strokeWidth="3" />

              {/* phase number */}
              <text
                x="180" y={y - 10}
                fontFamily={FONT_MONO}
                fontSize="10"
                letterSpacing="2"
                fill={color.t3}
              >
                0{i + 1}
              </text>

              {/* phase label */}
              <text
                x="180" y={y + 8}
                fontFamily={FONT_SANS}
                fontSize="15"
                fontWeight="700"
                fill={color.t1}
              >
                {phase.label}
              </text>

              {/* phase verb */}
              <text
                x="180" y={y + 24}
                fontFamily={FONT_MONO}
                fontSize="10"
                letterSpacing="1"
                fill={color.t2}
              >
                {phase.verb}
              </text>

              {/* status pill */}
              <rect
                x="490" y={y - 9}
                width="38" height="18"
                rx="4"
                fill={phase.accent}
                opacity="0.12"
              />
              <text
                x="509" y={y + 3}
                fontFamily={FONT_MONO}
                fontSize="9"
                fontWeight="600"
                letterSpacing="1.5"
                fill={phase.accent}
                textAnchor="middle"
              >
                BOUND
              </text>
            </g>
          );
        })}

        {/* footer caption */}
        <text
          x="80" y="535"
          fontFamily={FONT_MONO}
          fontSize="10"
          letterSpacing="1"
          fill={color.t3}
        >
          Each phase emits a cryptographic event. The chain commits — or refuses.
        </text>
      </svg>
    </div>
  );
}
