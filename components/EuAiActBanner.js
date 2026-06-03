'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

// EU AI Act milestone. Aug 2, 2026 is a real enforcement date for parts of the
// Act (incl. GPAI / governance provisions). We state the date and link to our
// mapping — we do NOT claim the law literally mandates "a receipt".
const DEADLINE = Date.UTC(2026, 7, 2); // month is 0-indexed → 7 = August
const DISMISS_KEY = 'ep_euaiact_banner_dismissed_v1';

export default function EuAiActBanner() {
  const [show, setShow] = useState(false);
  const [days, setDays] = useState(null);

  // Compute on the client only — avoids SSR/hydration mismatch and lets us
  // read the per-browser dismissal flag without flashing for dismissed users.
  useEffect(() => {
    let cancelled = false;
    // Defer to a microtask so the update isn't synchronous in the effect body
    // (satisfies react-hooks/set-state-in-effect); still runs immediately.
    Promise.resolve().then(() => {
      if (cancelled) return;
      try {
        if (localStorage.getItem(DISMISS_KEY) === '1') return;
      } catch { /* private mode — show anyway */ }
      const remaining = Math.ceil((DEADLINE - Date.now()) / 86_400_000);
      if (remaining <= 0) return; // past the date — retire the banner
      setDays(remaining);
      setShow(true);
    });
    return () => { cancelled = true; };
  }, []);

  if (!show) return null;

  const dismiss = () => {
    try { localStorage.setItem(DISMISS_KEY, '1'); } catch { /* ignore */ }
    setShow(false);
  };

  return (
    <div style={{
      width: '100%', boxSizing: 'border-box',
      background: '#1C1917', color: '#FAFAF9',
      borderBottom: '1px solid rgba(176,141,53,0.35)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 14,
      padding: '9px 44px 9px 16px', position: 'relative',
      fontFamily: "'IBM Plex Mono', monospace", fontSize: 12.5, letterSpacing: 0.2,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#B08D35', flexShrink: 0 }} className="ep-pulse-dot" />
      <Link href="/eu-ai-act" style={{ color: '#FAFAF9', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
        <span style={{ color: '#B08D35', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>EU AI Act</span>
        <span style={{ color: 'rgba(250,250,249,0.85)' }}>
          obligations take effect Aug 2, 2026 — <strong style={{ color: '#FAFAF9' }}>{days} days</strong>. See how EMILIA maps to them
        </span>
        <span style={{ color: '#B08D35' }}>&rarr;</span>
      </Link>
      <button
        onClick={dismiss}
        aria-label="Dismiss EU AI Act notice"
        style={{
          position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
          background: 'none', border: 'none', color: 'rgba(250,250,249,0.5)',
          cursor: 'pointer', fontSize: 15, lineHeight: 1, padding: 4,
        }}
      >&times;</button>
    </div>
  );
}
