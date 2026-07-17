'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

// EU AI Act status, kept honest and current. The Commission's implementation
// timeline following the May 7, 2026 political agreement applies Annex III
// high-risk rules from Dec 2, 2027 and product-integrated high-risk rules from
// Aug 2, 2028. We do NOT claim the law literally mandates "a receipt".
// Dismiss key bumped to v2 so users who dismissed the countdown see the
// corrected status once.
const DISMISS_KEY = 'ep_euaiact_banner_dismissed_v2';

export default function EuAiActBanner() {
  const [show, setShow] = useState(false);

  // Client-only — avoids SSR/hydration mismatch and lets us read the
  // per-browser dismissal flag without flashing for dismissed users.
  useEffect(() => {
    let cancelled = false;
    Promise.resolve().then(() => {
      if (cancelled) return;
      try {
        if (localStorage.getItem(DISMISS_KEY) === '1') return;
      } catch { /* private mode — show anyway */ }
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
    <div id="ep-eu-ai-act-banner" style={{
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
          Annex III high-risk rules apply from <strong style={{ color: '#FAFAF9' }}>Dec 2, 2027</strong> — build inspectable oversight evidence now
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
