'use client';

import { AbsoluteFill, useCurrentFrame, useVideoConfig, interpolate, spring } from 'remotion';

/*
  Three-layer stack animation for the EP hero.
  Cycles through the protocol layers:
    Eye (warns) → EP Handshake (verifies) → Signoff (owns)
  Each layer pulses in with its associated tech domains.
*/

const LAYERS = [
  {
    label: 'EYE',
    verb: 'warns',
    color: '#22C55E',
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
    color: '#F59E0B',
    domains: ['PASSKEY', 'SECURE APP', 'DUAL', 'AUDIT'],
    icon: '◈',
  },
];

const FONT_SANS = "'IBM Plex Sans', -apple-system, sans-serif";
const FONT_MONO = "'IBM Plex Mono', monospace";

function ProngSVG({ progress, color: prongColor }) {
  const spread = interpolate(progress, [0, 1], [0, 1], { extrapolateRight: 'clamp' });
  return (
    <svg width="48" height="48" viewBox="0 0 34 34" fill="none" style={{ opacity: interpolate(progress, [0, 0.3], [0, 1], { extrapolateRight: 'clamp' }) }}>
      <rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#elg2)" />
      <rect x="9.5" y="5" width={interpolate(spread, [0, 1], [4, 16])} height="2.5" rx="1.25" fill="#3B82F6" />
      <rect x="9.5" y="15.5" width={interpolate(spread, [0, 1], [4, 12])} height="2.5" rx="1.25" fill={prongColor} />
      <rect x="9.5" y="26.5" width={interpolate(spread, [0, 1], [4, 14])} height="2.5" rx="1.25" fill="#3B82F6" />
      <defs>
        <linearGradient id="elg2" x1="8" y1="5" x2="8" y2="29">
          <stop offset="0%" stopColor="#3B82F6" />
          <stop offset="100%" stopColor="#22C55E" />
        </linearGradient>
      </defs>
    </svg>
  );
}

function DomainTag({ label, color: tagColor, delay, frame, fps }) {
  const prog = spring({ frame: frame - delay, fps, config: { damping: 15, stiffness: 120, mass: 0.4 } });
  const opacity = interpolate(prog, [0, 1], [0, 1], { extrapolateRight: 'clamp' });
  const y = interpolate(prog, [0, 1], [8, 0], { extrapolateRight: 'clamp' });
  return (
    <span
      style={{
        display: 'inline-block',
        fontFamily: FONT_MONO,
        fontSize: 10,
        fontWeight: 500,
        letterSpacing: 1.5,
        color: tagColor,
        border: `1px solid ${tagColor}33`,
        borderRadius: 3,
        padding: '4px 10px',
        opacity,
        transform: `translateY(${y}px)`,
        background: `${tagColor}0A`,
      }}
    >
      {label}
    </span>
  );
}

function LayerRow({ layer, index, frame, fps, totalDuration }) {
  const cycleLength = totalDuration / 3;
  const layerStart = index * cycleLength;

  // Each layer fades in, holds, then fades out
  const fadeIn = interpolate(frame, [layerStart, layerStart + 15], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const fadeOut = interpolate(frame, [layerStart + cycleLength - 15, layerStart + cycleLength], [1, 0.3], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const isActive = frame >= layerStart && frame < layerStart + cycleLength;
  const opacity = isActive ? fadeIn * fadeOut : interpolate(frame, [layerStart, layerStart + 10], [0.2, 0.2], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const glow = isActive ? interpolate(fadeIn, [0.5, 1], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }) : 0;

  // Scale pulse when active
  const scale = isActive
    ? interpolate(spring({ frame: frame - layerStart, fps, config: { damping: 20, stiffness: 100, mass: 0.5 } }), [0, 1], [0.97, 1])
    : 0.97;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        padding: '12px 20px',
        borderRadius: 6,
        border: `1px solid ${isActive ? layer.color + '40' : 'rgba(255,255,255,0.06)'}`,
        background: isActive ? `${layer.color}08` : 'transparent',
        opacity: Math.max(opacity, 0.25),
        transform: `scale(${scale})`,
        transition: 'border-color 0.3s',
        boxShadow: glow > 0 ? `0 0 ${20 * glow}px ${layer.color}15` : 'none',
      }}
    >
      {/* Icon */}
      <span style={{ fontSize: 20, color: layer.color, opacity: isActive ? 1 : 0.3, flexShrink: 0, width: 28, textAlign: 'center' }}>
        {layer.icon}
      </span>

      {/* Label + verb */}
      <div style={{ flex: '0 0 130px' }}>
        <div style={{ fontFamily: FONT_MONO, fontSize: 10, fontWeight: 500, letterSpacing: 2, color: layer.color, textTransform: 'uppercase' }}>
          {layer.label}
        </div>
        <div style={{ fontFamily: FONT_SANS, fontSize: 16, fontWeight: 600, color: isActive ? '#FAFAFA' : '#71717A', marginTop: 2 }}>
          {layer.verb}
        </div>
      </div>

      {/* Domain tags */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', flex: 1 }}>
        {layer.domains.map((d, i) => (
          <DomainTag
            key={d}
            label={d}
            color={isActive ? layer.color : '#71717A'}
            delay={isActive ? layerStart + 8 + i * 4 : 0}
            frame={isActive ? frame : 0}
            fps={fps}
          />
        ))}
      </div>
    </div>
  );
}

// Scanning line that moves down through the layers
function ScanLine({ frame, totalDuration }) {
  const progress = (frame % totalDuration) / totalDuration;
  const y = interpolate(progress, [0, 0.33, 0.66, 1], [0, 33, 66, 100]);
  const opacity = interpolate(Math.sin(progress * Math.PI * 3), [-1, 1], [0.1, 0.5]);
  return (
    <div
      style={{
        position: 'absolute',
        left: 0,
        right: 0,
        top: `${y}%`,
        height: 1,
        background: `linear-gradient(90deg, transparent, rgba(34,197,94,0.4), transparent)`,
        opacity,
        pointerEvents: 'none',
      }}
    />
  );
}

export function TechStackComposition() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  // Tagline appears throughout with gentle pulse
  const taglineOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: 'clamp' });
  const prongProgress = interpolate(frame, [0, 30], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

  // Active layer index for the tagline emphasis
  const cycleLength = durationInFrames / 3;
  const activeIndex = Math.min(Math.floor(frame / cycleLength), 2);

  return (
    <AbsoluteFill style={{ background: 'transparent', fontFamily: FONT_SANS, overflow: 'hidden' }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'center', padding: '16px 0' }}>
        {/* Animated E + tagline */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginBottom: 20, opacity: taglineOpacity }}>
          <ProngSVG progress={prongProgress} color={LAYERS[activeIndex].color} />
          <div style={{ fontFamily: FONT_MONO, fontSize: 13, letterSpacing: 0.5, color: '#FAFAFA' }}>
            <span style={{ color: activeIndex === 0 ? '#22C55E' : '#71717A', transition: 'color 0.3s' }}>Eye warns.</span>
            {' '}
            <span style={{ color: activeIndex === 1 ? '#3B82F6' : '#71717A', transition: 'color 0.3s' }}>EP verifies.</span>
            {' '}
            <span style={{ color: activeIndex === 2 ? '#F59E0B' : '#71717A', transition: 'color 0.3s' }}>Signoff owns.</span>
          </div>
        </div>

        {/* Stack layers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, position: 'relative' }}>
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
