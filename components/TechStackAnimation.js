'use client';

import { AbsoluteFill, useCurrentFrame, useVideoConfig, interpolate, spring } from 'remotion';

/*
  Three-layer stack animation for the EP hero.
  Cycles through the protocol layers:
    Eye (warns) → EP Handshake (verifies) → Signoff (owns)
  Each layer pulses in with its associated tech domains.
  White background theme, gold accent.
*/

const LAYERS = [
  {
    label: 'EYE',
    verb: 'warns',
    color: '#16A34A',
    domains: ['GOV', 'FIN', 'ENT', 'AI'],
    icon: '◉',
  },
  {
    label: 'EP HANDSHAKE',
    verb: 'verifies',
    color: '#3B82F6',
    domains: ['IDENTITY', 'POLICY', 'CONTEXT', 'NONCE'],
    icon: '⬡',
  },
  {
    label: 'SIGNOFF',
    verb: 'owns',
    color: '#B08D35',
    domains: ['PASSKEY', 'SECURE APP', 'DUAL', 'AUDIT'],
    icon: '◈',
  },
];

const FONT_SANS = "'IBM Plex Sans', -apple-system, sans-serif";
const FONT_MONO = "'IBM Plex Mono', monospace";

function ProngSVG({ progress, color: prongColor }) {
  const spread = interpolate(progress, [0, 1], [0, 1], { extrapolateRight: 'clamp' });
  return (
    <svg width="52" height="52" viewBox="0 0 34 34" fill="none" style={{ opacity: interpolate(progress, [0, 0.3], [0, 1], { extrapolateRight: 'clamp' }) }}>
      <rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#elg2)" />
      <rect x="9.5" y="5" width={interpolate(spread, [0, 1], [4, 16])} height="2.5" rx="1.25" fill="#0C0A09" />
      <rect x="9.5" y="15.5" width={interpolate(spread, [0, 1], [4, 12])} height="2.5" rx="1.25" fill={prongColor} />
      <rect x="9.5" y="26.5" width={interpolate(spread, [0, 1], [4, 14])} height="2.5" rx="1.25" fill="#0C0A09" />
      <defs>
        <linearGradient id="elg2" x1="8" y1="5" x2="8" y2="29">
          <stop offset="0%" stopColor="#0C0A09" />
          <stop offset="100%" stopColor="#B08D35" />
        </linearGradient>
      </defs>
    </svg>
  );
}

function DomainTag({ label, color: tagColor, delay, frame, fps }) {
  const prog = spring({ frame: frame - delay, fps, config: { damping: 18, stiffness: 80, mass: 0.5 } });
  const opacity = interpolate(prog, [0, 1], [0, 1], { extrapolateRight: 'clamp' });
  const y = interpolate(prog, [0, 1], [8, 0], { extrapolateRight: 'clamp' });
  return (
    <span
      style={{
        display: 'inline-block',
        fontFamily: FONT_MONO,
        fontSize: 11,
        fontWeight: 500,
        letterSpacing: 1.5,
        color: tagColor,
        border: `1px solid ${tagColor}30`,
        borderRadius: 3,
        padding: '6px 14px',
        opacity,
        transform: `translateY(${y}px)`,
        background: `${tagColor}08`,
      }}
    >
      {label}
    </span>
  );
}

function LayerRow({ layer, index, frame, fps, totalDuration }) {
  const cycleLength = totalDuration / 3;
  const layerStart = index * cycleLength;

  const fadeIn = interpolate(frame, [layerStart, layerStart + 20], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const fadeOut = interpolate(frame, [layerStart + cycleLength - 20, layerStart + cycleLength], [1, 0.35], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const isActive = frame >= layerStart && frame < layerStart + cycleLength;
  const opacity = isActive ? fadeIn * fadeOut : 0.3;
  const glow = isActive ? interpolate(fadeIn, [0.5, 1], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }) : 0;

  const scale = isActive
    ? interpolate(spring({ frame: frame - layerStart, fps, config: { damping: 22, stiffness: 80, mass: 0.6 } }), [0, 1], [0.97, 1])
    : 0.97;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 20,
        padding: '16px 24px',
        borderRadius: 6,
        border: `1px solid ${isActive ? layer.color + '35' : '#E7E5E4'}`,
        background: isActive ? `${layer.color}06` : 'transparent',
        opacity: Math.max(opacity, 0.3),
        transform: `scale(${scale})`,
        boxShadow: glow > 0 ? `0 0 ${24 * glow}px ${layer.color}10` : 'none',
      }}
    >
      <span style={{ fontSize: 22, color: layer.color, opacity: isActive ? 1 : 0.25, flexShrink: 0, width: 30, textAlign: 'center' }}>
        {layer.icon}
      </span>

      <div style={{ flex: '0 0 140px' }}>
        <div style={{ fontFamily: FONT_MONO, fontSize: 10, fontWeight: 500, letterSpacing: 2, color: layer.color, textTransform: 'uppercase' }}>
          {layer.label}
        </div>
        <div style={{ fontFamily: FONT_SANS, fontSize: 18, fontWeight: 600, color: isActive ? '#0C0A09' : '#A1A1AA', marginTop: 2 }}>
          {layer.verb}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', flex: 1 }}>
        {layer.domains.map((d, i) => (
          <DomainTag
            key={d}
            label={d}
            color={isActive ? layer.color : '#A1A1AA'}
            delay={isActive ? layerStart + 12 + i * 6 : 0}
            frame={isActive ? frame : 0}
            fps={fps}
          />
        ))}
      </div>
    </div>
  );
}

function ScanLine({ frame, totalDuration }) {
  const progress = (frame % totalDuration) / totalDuration;
  const y = interpolate(progress, [0, 0.33, 0.66, 1], [0, 33, 66, 100]);
  const opacity = interpolate(Math.sin(progress * Math.PI * 3), [-1, 1], [0.08, 0.3]);
  return (
    <div
      style={{
        position: 'absolute',
        left: 0,
        right: 0,
        top: `${y}%`,
        height: 1,
        background: `linear-gradient(90deg, transparent, rgba(176,141,53,0.35), transparent)`,
        opacity,
        pointerEvents: 'none',
      }}
    />
  );
}

export function TechStackComposition() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  const taglineOpacity = interpolate(frame, [0, 30], [0, 1], { extrapolateRight: 'clamp' });
  const prongProgress = interpolate(frame, [0, 45], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

  const cycleLength = durationInFrames / 3;
  const activeIndex = Math.min(Math.floor(frame / cycleLength), 2);

  return (
    <AbsoluteFill style={{ background: 'transparent', fontFamily: FONT_SANS, overflow: 'hidden' }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'center', padding: '36px 32px' }}>
        {/* Animated E + tagline */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 32, opacity: taglineOpacity }}>
          <ProngSVG progress={prongProgress} color={LAYERS[activeIndex].color} />
          <div style={{ fontFamily: FONT_MONO, fontSize: 15, letterSpacing: 0.5, color: '#0C0A09' }}>
            <span style={{ color: activeIndex === 0 ? '#16A34A' : '#A1A1AA' }}>Eye warns.</span>
            {' '}
            <span style={{ color: activeIndex === 1 ? '#3B82F6' : '#A1A1AA' }}>EP verifies.</span>
            {' '}
            <span style={{ color: activeIndex === 2 ? '#B08D35' : '#A1A1AA' }}>Signoff owns.</span>
          </div>
        </div>

        {/* Stack layers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, position: 'relative' }}>
          <ScanLine frame={frame} totalDuration={durationInFrames} />
          {LAYERS.map((layer, i) => (
            <LayerRow
              key={layer.label}
              layer={layer}
              index={i}
              frame={frame}
              fps={fps}
              totalDuration={durationInFrames}
            />
          ))}
        </div>
      </div>
    </AbsoluteFill>
  );
}
