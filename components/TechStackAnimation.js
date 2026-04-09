'use client';

import { AbsoluteFill, useCurrentFrame, useVideoConfig, interpolate, spring } from 'remotion';

/*
  EP Protocol Ceremony — Hero Animation
  =======================================
  Tells the story of a complete EP ceremony in four phases:
    Eye → observes action context, flags risk
    Handshake → verifies 8 bindings one by one
    Signoff → human attestation ceremony
    Commit → seals the chain, releases execution

  Layout: step progress bar | phase panel | event log
*/

const FONT_SANS  = "'IBM Plex Sans', -apple-system, sans-serif";
const FONT_MONO  = "'IBM Plex Mono', 'Menlo', monospace";

const COLOR = {
  bg:     '#FAFAF9',
  border: '#E8E5E1',
  t1:     '#0C0A09',
  t2:     '#57534E',
  t3:     '#A8A29E',
  gold:   '#B08D35',
  blue:   '#3B82F6',
  green:  '#16A34A',
  stone:  '#78716C',
};

const PHASES = [
  { id: 'eye',       label: 'EYE',       verb: 'observes',  color: COLOR.green, start: 0,   end: 89  },
  { id: 'handshake', label: 'HANDSHAKE', verb: 'verifies',  color: COLOR.blue,  start: 90,  end: 179 },
  { id: 'signoff',   label: 'SIGNOFF',   verb: 'owns',      color: COLOR.gold,  start: 180, end: 269 },
  { id: 'commit',    label: 'COMMIT',    verb: 'seals',     color: COLOR.stone, start: 270, end: 359 },
];

const BINDINGS = [
  { label: 'Actor identity',             code: 'verify(entity.keyId)' },
  { label: 'Authority chain',            code: '∀d: d(root→actor)' },
  { label: 'Exact action context',       code: 'bind(action, params)' },
  { label: 'Policy version and hash',    code: 'pin(policy.sha256)' },
  { label: 'Nonce and expiry',           code: 'N_{t} ≠ N_{t-1}' },
  { label: 'One-time consumption',       code: 'consume(token, lock)' },
  { label: 'Immutable traceability',     code: 'Append(Log, Hash(E))' },
  { label: 'Accountable signoff',        code: 'signoff_required=true' },
];

const LOG_EVENTS = [
  { frame: 18,  phase: 'eye',       text: 'eye.observe',   detail: 'action=wire.transfer  actor=treasury_ops',     color: COLOR.green },
  { frame: 52,  phase: 'eye',       text: 'eye.flag',      detail: 'risk=HIGH  rule=dual_approval_required',        color: COLOR.green },
  { frame: 96,  phase: 'handshake', text: 'hsk.init',      detail: 'nonce=a8f3d2c1  policy=v4.2.1#abc123',         color: COLOR.blue  },
  { frame: 148, phase: 'handshake', text: 'hsk.verify',    detail: 'bindings=8/8  status=BOUND',                    color: COLOR.blue  },
  { frame: 192, phase: 'signoff',   text: 'sof.challenge', detail: 'actor=treasury_ops  deadline=30s',              color: COLOR.gold  },
  { frame: 242, phase: 'signoff',   text: 'sof.attest',    detail: 'PASS  signer=treasury_ops  elapsed=8.3s',       color: COLOR.gold  },
  { frame: 286, phase: 'commit',    text: 'commit.seal',   detail: 'chain=ep_7  consumed=true',                     color: COLOR.stone },
  { frame: 328, phase: 'commit',    text: 'RELEASED',      detail: 'hash=8f2a3d9e  latency=127ms  CEREMONY_PASS',   color: COLOR.green },
];

/* ─── Utility ───────────────────────────────────────────── */
function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

function fadeIn(frame, start, dur = 12) {
  return clamp(interpolate(frame, [start, start + dur], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }), 0, 1);
}

function springIn(frame, fps, start, config = { damping: 20, stiffness: 90, mass: 0.5 }) {
  const s = spring({ frame: frame - start, fps, config });
  return clamp(s, 0, 1);
}

/* ─── Step Progress Bar ─────────────────────────────────── */
function StepBar({ frame }) {
  const activeIndex = PHASES.findIndex(p => frame >= p.start && frame <= p.end);
  const phase = PHASES[activeIndex] || PHASES[0];

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 0 }}>
      {PHASES.map((p, i) => {
        const isDone    = frame > p.end;
        const isActive  = i === activeIndex;
        const isPending = frame < p.start;
        const circleColor = isDone ? p.color : isActive ? p.color : COLOR.border;
        const dotOpacity  = isActive ? 1 : isDone ? 0.6 : 0.3;
        const labelColor  = isDone ? p.color : isActive ? p.color : COLOR.t3;

        // Connecting line progress
        const lineProgress = i < PHASES.length - 1
          ? (frame > p.end ? 1 : isActive
              ? interpolate(frame, [p.start, p.end], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' })
              : 0)
          : null;

        return (
          <div key={p.id} style={{ display: 'flex', alignItems: 'center', flex: i < PHASES.length - 1 ? '1 1 auto' : '0 0 auto' }}>
            {/* Step */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
              <div style={{
                width: 20, height: 20, borderRadius: '50%',
                background: isDone ? p.color : isActive ? `${p.color}18` : 'transparent',
                border: `1.5px solid ${circleColor}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                opacity: dotOpacity,
              }}>
                {isDone ? (
                  <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: '#fff', fontWeight: 700 }}>✓</span>
                ) : (
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: circleColor }} />
                )}
              </div>
              <span style={{
                fontFamily: FONT_MONO, fontSize: 8, fontWeight: 600,
                letterSpacing: 1.2, textTransform: 'uppercase', color: labelColor,
              }}>{p.label}</span>
            </div>

            {/* Connecting line */}
            {i < PHASES.length - 1 && (
              <div style={{ flex: 1, height: 1, background: COLOR.border, margin: '0 8px', position: 'relative', overflow: 'hidden' }}>
                <div style={{
                  position: 'absolute', left: 0, top: 0, bottom: 0,
                  width: `${(lineProgress || 0) * 100}%`,
                  background: p.color, transition: 'none',
                }} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ─── Phase Panel: Eye ──────────────────────────────────── */
function EyePanel({ frame, fps }) {
  const lf = frame - PHASES[0].start; // local frame 0-89

  const headerProgress  = springIn(frame, fps, PHASES[0].start);
  const cardProgress    = springIn(frame, fps, PHASES[0].start + 14);
  const riskProgress    = springIn(frame, fps, PHASES[0].start + 44);
  const domainsProgress = springIn(frame, fps, PHASES[0].start + 56);

  // Scan progress (0→1 over 60 frames)
  const scanProgress = interpolate(lf, [0, 70], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

  const ACTION_ROWS = [
    { k: 'action',      v: 'wire.transfer' },
    { k: 'amount',      v: '$2,400,000.00' },
    { k: 'actor',       v: 'treasury_ops' },
    { k: 'destination', v: 'external_acct_NEW' },
  ];

  const scanLineY = interpolate(lf, [0, 70], [0, 100], { extrapolateRight: 'clamp' });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%' }}>
      {/* Section header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: headerProgress, transform: `translateY(${interpolate(headerProgress, [0, 1], [6, 0])}px)` }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: COLOR.green }} />
        <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.green, letterSpacing: 1.5, textTransform: 'uppercase' }}>
          Observing action context
        </span>
      </div>

      {/* Detected action card */}
      <div style={{
        border: `1px solid ${COLOR.border}`,
        borderLeft: `3px solid ${COLOR.green}`,
        borderRadius: 4,
        padding: '14px 16px',
        background: COLOR.bg,
        position: 'relative', overflow: 'hidden',
        opacity: cardProgress,
        transform: `translateY(${interpolate(cardProgress, [0, 1], [8, 0])}px)`,
      }}>
        {/* Scan line */}
        <div style={{
          position: 'absolute', left: 0, right: 0,
          top: `${scanLineY}%`, height: 1,
          background: `linear-gradient(90deg, transparent, ${COLOR.green}50, transparent)`,
        }} />
        <div style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 10 }}>
          DETECTED ACTION
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          {ACTION_ROWS.map((row, i) => {
            const rowOpacity = interpolate(lf, [14 + i * 6, 14 + i * 6 + 10], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
            return (
              <div key={row.k} style={{ display: 'flex', gap: 12, opacity: rowOpacity }}>
                <span style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLOR.t3, minWidth: 90 }}>{row.k}</span>
                <span style={{ fontFamily: FONT_MONO, fontSize: 11, color: COLOR.t1, fontWeight: 500 }}>{row.v}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Risk assessment */}
      <div style={{
        border: `1px solid rgba(176,141,53,0.3)`,
        borderRadius: 4,
        padding: '10px 16px',
        background: 'rgba(176,141,53,0.06)',
        display: 'flex', alignItems: 'center', gap: 10,
        opacity: riskProgress,
        transform: `translateY(${interpolate(riskProgress, [0, 1], [6, 0])}px)`,
      }}>
        <div style={{ fontFamily: FONT_MONO, fontSize: 9, fontWeight: 700, color: COLOR.gold, letterSpacing: 1.5 }}>RISK: HIGH</div>
        <div style={{ width: 1, height: 14, background: COLOR.border }} />
        <div style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t2, letterSpacing: 0.5 }}>DUAL APPROVAL REQUIRED</div>
      </div>

      {/* Domains */}
      <div style={{ display: 'flex', gap: 6, opacity: domainsProgress }}>
        {['GOV', 'FIN', 'ENT', 'AI AGENT'].map((d, i) => {
          const dOp = interpolate(lf, [56 + i * 5, 56 + i * 5 + 8], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
          return (
            <span key={d} style={{
              fontFamily: FONT_MONO, fontSize: 9, fontWeight: 500,
              color: COLOR.green, border: `1px solid ${COLOR.green}30`,
              background: `${COLOR.green}08`, borderRadius: 2,
              padding: '4px 8px', letterSpacing: 0.8,
              opacity: dOp,
            }}>{d}</span>
          );
        })}
      </div>
    </div>
  );
}

/* ─── Phase Panel: Handshake ────────────────────────────── */
function HandshakePanel({ frame, fps }) {
  const lf = frame - PHASES[1].start;

  const headerProgress = springIn(frame, fps, PHASES[1].start);

  // Each binding checks at lf: 8, 16, 24, 32, 40, 48, 56, 64
  // Fully checked at lf: 8+10=18, 16+10=26, etc.
  const BINDING_FRAME_GAP = 9;
  const BINDING_CHECK_DUR = 8;

  const verifiedCount = BINDINGS.reduce((n, _, i) => {
    return lf >= (i * BINDING_FRAME_GAP + BINDING_CHECK_DUR) ? n + 1 : n;
  }, 0);

  const allDoneProgress = springIn(frame, fps, PHASES[1].start + 75);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        opacity: headerProgress,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: COLOR.blue }} />
          <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.blue, letterSpacing: 1.5, textTransform: 'uppercase' }}>
            Verifying bindings
          </span>
        </div>
        <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.t3 }}>
          {verifiedCount}/8
        </span>
      </div>

      {/* Bindings grid — 2 columns */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '5px 10px', flex: 1 }}>
        {BINDINGS.map((b, i) => {
          const appearFrame = i * BINDING_FRAME_GAP;
          const checkFrame  = i * BINDING_FRAME_GAP + BINDING_CHECK_DUR;
          const appeared  = lf >= appearFrame;
          const isChecking = lf >= appearFrame && lf < checkFrame;
          const isChecked  = lf >= checkFrame;

          const itemOpacity = interpolate(lf, [appearFrame, appearFrame + 6], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
          const checkProgress = interpolate(lf, [checkFrame - 6, checkFrame + 2], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

          return (
            <div key={b.label} style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '7px 10px',
              border: `1px solid ${isChecked ? `${COLOR.blue}25` : COLOR.border}`,
              borderRadius: 3,
              background: isChecked ? `${COLOR.blue}05` : 'transparent',
              opacity: appeared ? itemOpacity : 0,
            }}>
              {/* Check indicator */}
              <div style={{
                width: 14, height: 14, borderRadius: '50%', flexShrink: 0,
                border: `1.5px solid ${isChecked ? COLOR.blue : isChecking ? `${COLOR.blue}80` : COLOR.border}`,
                background: isChecked ? COLOR.blue : 'transparent',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                {isChecked && (
                  <span style={{ color: '#fff', fontSize: 8, fontWeight: 700, lineHeight: 1 }}>✓</span>
                )}
              </div>
              <div>
                <div style={{ fontFamily: FONT_SANS, fontSize: 10, fontWeight: 500, color: isChecked ? COLOR.t1 : COLOR.t2, lineHeight: 1.2 }}>
                  {b.label}
                </div>
                <div style={{ fontFamily: FONT_MONO, fontSize: 8, color: isChecked ? COLOR.blue : COLOR.t3, letterSpacing: 0.3 }}>
                  {b.code}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* All verified badge */}
      {verifiedCount === 8 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 12px',
          border: `1px solid ${COLOR.blue}30`,
          background: `${COLOR.blue}08`,
          borderRadius: 3,
          opacity: allDoneProgress,
          transform: `scale(${interpolate(allDoneProgress, [0, 1], [0.97, 1])})`,
        }}>
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, fontWeight: 700, color: COLOR.blue, letterSpacing: 1 }}>8/8 BOUND</span>
          <div style={{ width: 1, height: 12, background: COLOR.border }} />
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t2, letterSpacing: 0.5 }}>ceremony token issued</span>
        </div>
      )}
    </div>
  );
}

/* ─── Phase Panel: Signoff ──────────────────────────────── */
function SignoffPanel({ frame, fps }) {
  const lf = frame - PHASES[2].start;

  const headerProgress    = springIn(frame, fps, PHASES[2].start);
  const challengeProgress = springIn(frame, fps, PHASES[2].start + 15);
  const waitingProgress   = springIn(frame, fps, PHASES[2].start + 30);
  const attestedProgress  = springIn(frame, fps, PHASES[2].start + 56);

  const isAttested = lf >= 62;

  // Timer: shows 0s → 8.3s over frames 30-62
  const timerSeconds = interpolate(lf, [30, 62], [0, 8.3], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: headerProgress }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: COLOR.gold }} />
        <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.gold, letterSpacing: 1.5, textTransform: 'uppercase' }}>
          Accountable signoff required
        </span>
      </div>

      {/* Challenge card */}
      <div style={{
        border: `1px solid ${COLOR.border}`,
        borderLeft: `3px solid ${COLOR.gold}`,
        borderRadius: 4, padding: '14px 16px',
        opacity: challengeProgress,
        transform: `translateY(${interpolate(challengeProgress, [0, 1], [6, 0])}px)`,
      }}>
        <div style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3, letterSpacing: 1.5, marginBottom: 10, textTransform: 'uppercase' }}>
          Challenge Issued
        </div>
        {[
          { k: 'challenge_id', v: 'ep_sof_7f3a9b1c' },
          { k: 'action_bound', v: 'wire.transfer / $2.4M' },
          { k: 'policy_hash',  v: 'sha256:abc123…' },
          { k: 'deadline',     v: '30 seconds' },
        ].map((row, i) => {
          const rowOp = interpolate(lf, [15 + i * 5, 15 + i * 5 + 8], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
          return (
            <div key={row.k} style={{ display: 'flex', gap: 12, opacity: rowOp, marginBottom: 4 }}>
              <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.t3, minWidth: 100 }}>{row.k}</span>
              <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.t1, fontWeight: 500 }}>{row.v}</span>
            </div>
          );
        })}
      </div>

      {/* Waiting / Attested */}
      {!isAttested ? (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '8px 12px',
          border: `1px solid ${COLOR.gold}25`,
          borderRadius: 3, background: 'rgba(176,141,53,0.04)',
          opacity: waitingProgress,
        }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%', background: COLOR.gold,
            animation: 'none',
            opacity: 0.5 + 0.5 * Math.sin((frame - PHASES[2].start - 30) * 0.3),
          }} />
          <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.gold, letterSpacing: 0.5 }}>
            Awaiting attestation…
          </span>
          <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.t3, marginLeft: 'auto' }}>
            {timerSeconds.toFixed(1)}s
          </span>
        </div>
      ) : (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '8px 12px',
          border: `1px solid ${COLOR.green}30`,
          borderRadius: 3, background: 'rgba(22,163,74,0.06)',
          opacity: attestedProgress,
          transform: `scale(${interpolate(attestedProgress, [0, 1], [0.97, 1])})`,
        }}>
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, fontWeight: 700, color: COLOR.green, letterSpacing: 1 }}>ATTESTED</span>
          <div style={{ width: 1, height: 12, background: COLOR.border }} />
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t2 }}>treasury_ops</span>
          <div style={{ width: 1, height: 12, background: COLOR.border }} />
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3 }}>8.3s response</span>
        </div>
      )}
    </div>
  );
}

/* ─── Phase Panel: Commit ───────────────────────────────── */
function CommitPanel({ frame, fps }) {
  const lf = frame - PHASES[3].start;

  const headerProgress   = springIn(frame, fps, PHASES[3].start);
  const consumedProgress = springIn(frame, fps, PHASES[3].start + 14);
  const hashProgress     = springIn(frame, fps, PHASES[3].start + 30);
  const sealedProgress   = springIn(frame, fps, PHASES[3].start + 50);
  const releasedProgress = springIn(frame, fps, PHASES[3].start + 65);

  // Typing in the hash
  const HASH = 'sha256: 8f2a3d9e4b1c7a6f';
  const charsVisible = Math.floor(interpolate(lf, [30, 56], [0, HASH.length], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }));
  const hashTyped = HASH.slice(0, charsVisible);

  const isReleased = lf >= 72;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: headerProgress }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: COLOR.stone }} />
        <span style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.stone, letterSpacing: 1.5, textTransform: 'uppercase' }}>
          Sealing ceremony chain
        </span>
      </div>

      {/* Commit steps */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {/* Token consumed */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '9px 12px',
          border: `1px solid ${COLOR.border}`, borderRadius: 3,
          opacity: consumedProgress,
          transform: `translateY(${interpolate(consumedProgress, [0, 1], [6, 0])}px)`,
        }}>
          <div style={{ width: 12, height: 12, borderRadius: '50%', border: `1.5px solid ${COLOR.stone}`, background: COLOR.stone, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <span style={{ color: '#fff', fontSize: 7, fontWeight: 700 }}>✓</span>
          </div>
          <div>
            <div style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.t1, fontWeight: 500 }}>Handshake token consumed</div>
            <div style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3 }}>ep_hsk_a8f3d2c1 — cannot be replayed</div>
          </div>
        </div>

        {/* Hash computed */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '9px 12px',
          border: `1px solid ${COLOR.border}`, borderRadius: 3,
          opacity: hashProgress,
          transform: `translateY(${interpolate(hashProgress, [0, 1], [6, 0])}px)`,
        }}>
          <div style={{ width: 12, height: 12, borderRadius: '50%', border: `1.5px solid ${lf >= 56 ? COLOR.stone : COLOR.border}`, background: lf >= 56 ? COLOR.stone : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            {lf >= 56 && <span style={{ color: '#fff', fontSize: 7, fontWeight: 700 }}>✓</span>}
          </div>
          <div>
            <div style={{ fontFamily: FONT_MONO, fontSize: 10, color: COLOR.t1, fontWeight: 500 }}>
              {hashTyped}<span style={{ opacity: lf >= 56 ? 0 : 0.5 + 0.5 * Math.sin(frame * 0.4) }}>_</span>
            </div>
            <div style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3 }}>ceremony event hash</div>
          </div>
        </div>

        {/* Chain sealed */}
        {lf >= 50 && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10, padding: '9px 12px',
            border: `1px solid ${COLOR.stone}25`, borderRadius: 3, background: `${COLOR.stone}05`,
            opacity: sealedProgress,
            transform: `scale(${interpolate(sealedProgress, [0, 1], [0.97, 1])})`,
          }}>
            <span style={{ fontFamily: FONT_MONO, fontSize: 9, fontWeight: 700, color: COLOR.stone, letterSpacing: 1 }}>SEALED</span>
            <div style={{ width: 1, height: 12, background: COLOR.border }} />
            <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t2 }}>ep_chain_7  ·  append-only</span>
          </div>
        )}
      </div>

      {/* Released */}
      {isReleased && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
          border: `2px solid ${COLOR.green}40`,
          borderRadius: 4, background: 'rgba(22,163,74,0.07)',
          opacity: releasedProgress,
          transform: `scale(${interpolate(releasedProgress, [0, 1], [0.97, 1])})`,
        }}>
          <span style={{ fontFamily: FONT_MONO, fontSize: 10, fontWeight: 700, color: COLOR.green, letterSpacing: 1 }}>RELEASED</span>
          <div style={{ width: 1, height: 14, background: COLOR.border }} />
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t2 }}>execution authorized</span>
          <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3, marginLeft: 'auto' }}>127ms</span>
        </div>
      )}
    </div>
  );
}

/* ─── Event Log ─────────────────────────────────────────── */
function EventLog({ frame }) {
  const visibleEvents = LOG_EVENTS.filter(e => frame >= e.frame);
  // Show last 4
  const shown = visibleEvents.slice(-4);

  return (
    <div style={{
      borderTop: `1px solid ${COLOR.border}`,
      paddingTop: 10,
    }}>
      <div style={{ fontFamily: FONT_MONO, fontSize: 8, color: COLOR.t3, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 6 }}>
        Protocol Event Stream
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {shown.map((e, i) => {
          const isNew  = i === shown.length - 1 && frame - e.frame < 12;
          const entryOpacity = Math.min(1, interpolate(frame, [e.frame, e.frame + 8], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }));
          const entryY = interpolate(frame, [e.frame, e.frame + 8], [4, 0], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
          return (
            <div key={`${e.frame}-${e.text}`} style={{
              display: 'flex', gap: 10, alignItems: 'baseline',
              opacity: entryOpacity * (i < shown.length - 1 ? 0.65 : 1),
              transform: `translateY(${entryY}px)`,
            }}>
              <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3, flexShrink: 0, minWidth: 32 }}>
                {String(Math.floor(e.frame / 30)).padStart(2, '0')}s
              </span>
              <span style={{ fontFamily: FONT_MONO, fontSize: 9, fontWeight: 600, color: e.color, flexShrink: 0, minWidth: 90 }}>
                {e.text}
              </span>
              <span style={{ fontFamily: FONT_MONO, fontSize: 9, color: COLOR.t3, overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}>
                {e.detail}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ─── Grid Background ───────────────────────────────────── */
function GridBg() {
  return (
    <div style={{
      position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 0,
      backgroundImage: `linear-gradient(${COLOR.border}60 1px, transparent 1px), linear-gradient(90deg, ${COLOR.border}60 1px, transparent 1px)`,
      backgroundSize: '40px 40px',
      opacity: 0.4,
    }} />
  );
}

/* ─── Main Composition ──────────────────────────────────── */
export function TechStackComposition() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  const activeIndex = PHASES.findIndex(p => frame >= p.start && frame <= p.end);
  const activePhase = PHASES[Math.max(0, activeIndex)];

  const overallOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: 'clamp' });

  return (
    <AbsoluteFill style={{ background: COLOR.bg, overflow: 'hidden' }}>
      <GridBg />
      <div style={{
        position: 'relative', zIndex: 1,
        display: 'flex', flexDirection: 'column', height: '100%',
        padding: '24px 28px',
        opacity: overallOpacity,
      }}>
        {/* ── Top bar: logo + step progress ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 18, flexShrink: 0 }}>
          {/* EP logo mark */}
          <div style={{
            fontFamily: FONT_MONO, fontSize: 11, fontWeight: 700,
            color: COLOR.t1, letterSpacing: 0, flexShrink: 0,
          }}>
            EP<span style={{ color: COLOR.gold }}>::</span>
            <span style={{ color: activePhase.color, fontWeight: 500, fontSize: 9, letterSpacing: 1 }}>
              {activePhase.id.toUpperCase()}
            </span>
          </div>
          <div style={{ flex: 1 }}>
            <StepBar frame={frame} />
          </div>
        </div>

        {/* ── Phase panel ── */}
        <div style={{ flex: 1, minHeight: 0, overflow: 'hidden' }}>
          {activeIndex === 0 && <EyePanel       frame={frame} fps={fps} />}
          {activeIndex === 1 && <HandshakePanel frame={frame} fps={fps} />}
          {activeIndex === 2 && <SignoffPanel   frame={frame} fps={fps} />}
          {activeIndex === 3 && <CommitPanel    frame={frame} fps={fps} />}
        </div>

        {/* ── Event log ── */}
        <div style={{ flexShrink: 0, marginTop: 12 }}>
          <EventLog frame={frame} />
        </div>
      </div>
    </AbsoluteFill>
  );
}
