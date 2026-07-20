'use client';
// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import { color, font, radius, styles } from '@/lib/tokens';

/**
 * EmailCapture — owned-audience signup.
 *
 * Posts to the existing public, rate-limited /api/waitlist route and shows the
 * founding "claimed number" the API returns. One field, no third-party tracker,
 * honest copy. Drop it anywhere with <EmailCapture /> (optionally override the
 * eyebrow/heading/sub per page).
 */
export default function EmailCapture({
  eyebrow = 'Follow the build',
  heading = 'Get the essays and protocol updates by email.',
  sub = 'Long-form arguments on agent accountability and the occasional shipping note — sent only when there’s something worth your time.',
  accent = color.gold,
}) {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle'); // idle | loading | done | error
  const [result, setResult] = /** @type {[{already_registered?: boolean, id?: (string|number)} | null, (v: any) => void]} */ (useState(null));
  const [message, setMessage] = useState('');

  async function onSubmit(e) {
    e.preventDefault();
    const value = email.trim();
    if (!value || !value.includes('@')) {
      setMessage('Please enter a valid email address.');
      setStatus('error');
      return;
    }
    setStatus('loading');
    setMessage('');
    try {
      const res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: value }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setMessage(data.detail || data.title || 'Something went wrong — please try again.');
        setStatus('error');
        return;
      }
      setResult(data);
      setStatus('done');
    } catch {
      setMessage('Network error — please try again.');
      setStatus('error');
    }
  }

  const eyebrowStyle = { fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 10 };
  const headingStyle = { fontFamily: font.sans, fontSize: 'clamp(22px, 3vw, 28px)', fontWeight: 700, color: color.t1, letterSpacing: -0.4, margin: '0 0 10px', maxWidth: 560 };
  const subStyle = { fontFamily: font.sans, fontSize: 15, lineHeight: 1.65, color: color.t2, maxWidth: 560, margin: '0 0 20px' };

  return (
    <section style={{ ...styles.section, paddingTop: 40, paddingBottom: 72, borderTop: `1px solid ${color.border}` }}>
      {status === 'done' ? (
        <div>
          <div style={{ ...eyebrowStyle, color: color.green }}>You&rsquo;re in</div>
          <div style={headingStyle}>
            {result?.already_registered ? 'You’re already on the list.' : 'Thanks — you’re on the list.'}
          </div>
          <p style={subStyle}>
            {result?.id != null ? (
              <>
                Founding member{' '}
                <strong style={{ color: accent, fontFamily: font.mono }}>#{result.id}</strong>. We&rsquo;ll only
                reach out when there&rsquo;s something worth your time.
              </>
            ) : (
              <>We&rsquo;ll only reach out when there&rsquo;s something worth your time.</>
            )}
          </p>
        </div>
      ) : (
        <div>
          <div style={{ ...eyebrowStyle, color: accent }}>{eyebrow}</div>
          <div style={headingStyle}>{heading}</div>
          <p style={subStyle}>{sub}</p>
          <form onSubmit={onSubmit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', maxWidth: 480 }}>
            <input
              type="email"
              inputMode="email"
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                if (status === 'error') setStatus('idle');
              }}
              aria-label="Email address"
              required
              style={{
                flex: '1 1 240px',
                padding: '11px 14px',
                fontFamily: font.sans,
                fontSize: 15,
                color: color.t1,
                background: color.card,
                border: `1px solid ${color.inputBorder}`,
                borderRadius: radius.base,
                outline: 'none',
              }}
            />
            <button
              type="submit"
              disabled={status === 'loading'}
              style={{
                padding: '11px 22px',
                fontFamily: font.sans,
                fontSize: 15,
                fontWeight: 600,
                color: '#FFFFFF',
                background: color.t1,
                border: 'none',
                borderRadius: radius.sm,
                cursor: status === 'loading' ? 'default' : 'pointer',
                opacity: status === 'loading' ? 0.6 : 1,
                whiteSpace: 'nowrap',
              }}
            >
              {status === 'loading' ? 'Joining…' : 'Notify me'}
            </button>
          </form>
          {status === 'error' && <p style={{ ...subStyle, color: color.red, margin: '10px 0 0' }}>{message}</p>}
          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, margin: '12px 0 0' }}>
            No spam. One email field, nothing else.
          </p>
        </div>
      )}
    </section>
  );
}
