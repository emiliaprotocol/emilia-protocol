/**
 * EP Design Tokens
 * Single source of truth for colors, typography, spacing, and radius.
 * Every page imports from here. No inline hex values.
 */

// ─── Colors ─────────────────────────────────────────────────
export const color = {
  bg:         '#020617',
  card:       '#0F172A',
  cardHover:  '#1a2238',

  t1:         '#F8FAFC',   // primary text
  t2:         '#94A3B8',   // secondary text / body
  t3:         '#64748B',   // tertiary text / captions

  green:      '#22C55E',   // primary accent — trust, CTAs, active states
  blue:       '#3B82F6',   // secondary accent — states, technical labels
  red:        '#f87171',   // destructive / error

  border:     'rgba(255,255,255,0.06)',
  borderHover:'rgba(255,255,255,0.12)',
  inputBorder:'rgba(255,255,255,0.08)',
};

// ─── Typography ─────────────────────────────────────────────
export const font = {
  sans: "'IBM Plex Sans', -apple-system, sans-serif",
  mono: "'IBM Plex Mono', monospace",
};

// ─── Radius ─────────────────────────────────────────────────
// Two sizes only. Controls = small. Containers = base.
export const radius = {
  sm: 4,     // buttons, tags, small controls
  base: 8,   // cards, inputs, containers
};

// ─── Shared Style Objects ───────────────────────────────────
// These replace the per-page `s = { ... }` objects.

export const styles = {
  page: {
    minHeight: '100vh',
    background: color.bg,
    color: color.t1,
    fontFamily: font.sans,
  },
  section: {
    maxWidth: 760,
    margin: '0 auto',
    padding: '80px 24px',
  },
  sectionWide: {
    maxWidth: 1080,
    margin: '0 auto',
    padding: '80px 24px',
  },
  sectionAlt: {
    background: color.card,
    borderTop: `1px solid ${color.border}`,
    borderBottom: `1px solid ${color.border}`,
  },
  eyebrow: {
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 3,
    textTransform: 'uppercase',
    color: color.green,
    marginBottom: 16,
  },
  eyebrowBlue: {
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 3,
    textTransform: 'uppercase',
    color: color.blue,
    marginBottom: 16,
  },
  h1: {
    fontFamily: font.sans,
    fontSize: 'clamp(32px, 5vw, 48px)',
    fontWeight: 700,
    letterSpacing: -1,
    marginBottom: 16,
    lineHeight: 1.1,
  },
  h1Large: {
    fontFamily: font.sans,
    fontWeight: 700,
    fontSize: 'clamp(42px, 7vw, 72px)',
    lineHeight: 0.95,
    letterSpacing: -2,
    margin: '0 0 16px',
  },
  h2: {
    fontFamily: font.sans,
    fontSize: 24,
    fontWeight: 700,
    letterSpacing: -0.5,
    marginBottom: 16,
  },
  h3: {
    fontFamily: font.sans,
    fontSize: 18,
    fontWeight: 700,
    letterSpacing: -0.3,
    marginBottom: 10,
    color: color.t1,
  },
  body: {
    fontSize: 16,
    color: color.t2,
    lineHeight: 1.75,
    marginBottom: 24,
  },
  card: {
    background: color.card,
    border: `1px solid ${color.border}`,
    borderRadius: radius.base,
    padding: '24px 28px',
  },
  cardTitle: {
    fontFamily: font.sans,
    fontSize: 16,
    fontWeight: 700,
    color: color.t1,
    marginBottom: 6,
  },
  cardBody: {
    fontSize: 14,
    color: color.t2,
    lineHeight: 1.65,
  },
  input: {
    width: '100%',
    padding: '12px 16px',
    borderRadius: radius.base,
    border: `1px solid ${color.inputBorder}`,
    background: color.card,
    color: color.t1,
    fontSize: 15,
    fontFamily: 'inherit',
    outline: 'none',
  },
  label: {
    display: 'block',
    fontSize: 13,
    fontWeight: 600,
    color: color.t2,
    marginBottom: 6,
    fontFamily: font.mono,
    letterSpacing: 0.5,
  },
  mono: {
    fontFamily: font.mono,
    fontSize: 13,
    color: color.blue,
  },
  divider: {
    height: 1,
    background: color.border,
    maxWidth: 400,
    margin: '0 auto',
  },
  tableHead: {
    padding: '12px 16px',
    borderBottom: `1px solid ${color.borderHover}`,
    fontSize: 12,
    fontWeight: 700,
    color: color.t1,
    fontFamily: font.mono,
    letterSpacing: 1,
    textTransform: 'uppercase',
    textAlign: 'left',
  },
  tableCell: {
    padding: '12px 16px',
    borderBottom: `1px solid ${color.border}`,
    fontSize: 14,
    color: color.t2,
    lineHeight: 1.5,
  },
  list: {
    color: color.t2,
    lineHeight: 1.8,
    fontSize: 16,
    paddingLeft: 18,
  },
};

// ─── CTA Styles ─────────────────────────────────────────────
// Three tiers only: primary (solid), secondary (outline), ghost.

const ctaBase = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 8,
  padding: '12px 28px',
  borderRadius: radius.base,
  fontFamily: font.mono,
  fontSize: 13,
  fontWeight: 700,
  letterSpacing: 1,
  textTransform: 'uppercase',
  textDecoration: 'none',
  cursor: 'pointer',
  border: 'none',
  transition: 'opacity 0.15s, transform 0.15s',
};

export const cta = {
  primary: {
    ...ctaBase,
    background: color.green,
    color: color.bg,
  },
  primaryBlue: {
    ...ctaBase,
    background: color.blue,
    color: color.bg,
  },
  secondary: {
    ...ctaBase,
    background: 'transparent',
    color: color.green,
    border: `1px solid ${color.green}`,
  },
  secondaryBlue: {
    ...ctaBase,
    background: 'transparent',
    color: color.blue,
    border: `1px solid rgba(59,130,246,0.3)`,
  },
  ghost: {
    ...ctaBase,
    background: 'transparent',
    color: color.t2,
    border: `1px solid ${color.border}`,
  },
  disabled: {
    ...ctaBase,
    background: '#1a1e30',
    color: color.t3,
    cursor: 'default',
  },
};

// ─── Grid helpers ───────────────────────────────────────────
export const grid = {
  auto: (minWidth = 280) => ({
    display: 'grid',
    gridTemplateColumns: `repeat(auto-fit, minmax(${minWidth}px, 1fr))`,
    gap: 16,
  }),
  cols2: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: 16,
  },
  stack: {
    display: 'grid',
    gap: 16,
  },
};
