/**
 * Internal reviewer dashboard — /internal/trust-desk
 *
 * @license Apache-2.0
 *
 * Read-only queue of Trust Desk engagements: escalations needing a human,
 * recent publishes, and in-flight runs. Server component reading the on-disk
 * engagement store.
 *
 * GATING: this surfaces customer company names and escalation reasons. Access
 * requires a valid `td_internal` HMAC session cookie issued by the bootstrap
 * exchange at /internal/trust-desk/auth?token=... (timing-safe, httpOnly, 8h).
 * The URL bearer is never reused as session state. Disabled entirely when the
 * env token is unset. noindex always.
 */

import { cookies } from 'next/headers';
import { listEngagements } from '@/lib/trust-desk/store';
import { TRUST_DESK_SESSION_COOKIE, verifyTrustDeskSession } from '@/lib/trust-desk/auth';
import { color, font, radius } from '@/lib/tokens';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Trust Desk — Reviewer Queue (internal)',
  robots: { index: false, follow: false },
};

const STATUS_STYLE = {
  escalated: { bg: '#FFFBEB', border: '#F59E0B', label: 'ESCALATED' },
  published: { bg: '#F0FDF4', border: '#16A34A', label: 'PUBLISHED' },
  failed: { bg: '#FEF2F2', border: '#DC2626', label: 'FAILED' },
  intake_received: { bg: '#F5F5F4', border: '#A8A29E', label: 'QUEUED' },
};

export default async function ReviewerDashboard() {
  const gate = await checkAccess();
  if (gate !== 'ok') {
    return (
      <main style={wrap}>
        <div style={eyebrow}>AI Trust Desk · Internal</div>
        <h1 style={{ fontFamily: font.sans, fontSize: 22, color: color.t1 }}>
          {gate === 'disabled' ? 'Reviewer dashboard disabled' : 'Authentication required'}
        </h1>
        <p style={{ fontFamily: font.sans, color: color.t2, fontSize: 14, maxWidth: 560, lineHeight: 1.6 }}>
          {gate === 'disabled' ? (
            <>
              Set <code style={code}>TRUST_DESK_INTERNAL_TOKEN</code> on the server to enable this
              dashboard. It exposes customer engagement details, so it stays off until a token is set.
            </>
          ) : (
            <>
              Authenticate by visiting{' '}
              <code style={code}>/internal/trust-desk/auth?token=YOUR_TOKEN</code> with the value of{' '}
              <code style={code}>TRUST_DESK_INTERNAL_TOKEN</code>. A distinct reviewer session is issued for 8 hours.
            </>
          )}
        </p>
      </main>
    );
  }

  const engagements = await listEngagements();
  const escalated = engagements.filter((e) => e.status === 'escalated');
  const inflight = engagements.filter(
    (e) => !['escalated', 'published', 'failed'].includes(e.status),
  );
  const published = engagements.filter((e) => e.status === 'published');

  return (
    <main style={wrap}>
      <header style={{ marginBottom: 32 }}>
        <div style={eyebrow}>AI Trust Desk · Internal</div>
        <h1 style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, color: color.t1, margin: 0 }}>
          Reviewer Queue
        </h1>
        <div style={{ display: 'flex', gap: 24, marginTop: 16 }}>
          <Stat n={escalated.length} label="Need review" accent="#F59E0B" />
          <Stat n={inflight.length} label="In flight" accent="#A8A29E" />
          <Stat n={published.length} label="Published" accent="#16A34A" />
        </div>
      </header>

      <Section title="Escalations — action required" rows={escalated} emptyText="No escalations. 🎉" />
      <Section title="In flight" rows={inflight} emptyText="Nothing processing." />
      <Section title="Recently published" rows={published.slice(0, 25)} emptyText="No published pages yet." />
    </main>
  );
}

/**
 * Access gate. 'disabled' = no server token configured; 'unauthorized' = no
 * valid cookie; 'ok' = authenticated.
 */
async function checkAccess() {
  const expected = process.env.TRUST_DESK_INTERNAL_TOKEN;
  if (!expected) return 'disabled';
  const jar = await cookies();
  const session = jar.get(TRUST_DESK_SESSION_COOKIE)?.value || '';
  return verifyTrustDeskSession(session) ? 'ok' : 'unauthorized';
}

function Section({ title, rows, emptyText }) {
  return (
    <section style={{ marginBottom: 40 }}>
      <h2 style={{ fontFamily: font.sans, fontSize: 16, fontWeight: 700, color: color.t1, marginBottom: 12 }}>
        {title}
      </h2>
      {rows.length === 0 ? (
        <p style={{ fontFamily: font.mono, fontSize: 13, color: color.t3 }}>{emptyText}</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rows.map((e) => (
            <Row key={e.engagement_id} e={e} />
          ))}
        </div>
      )}
    </section>
  );
}

function Row({ e }) {
  const s = STATUS_STYLE[e.status] || STATUS_STYLE.intake_received;
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        padding: '14px 16px',
        background: s.bg,
        border: `1px solid ${color.border}`,
        borderLeft: `3px solid ${s.border}`,
        borderRadius: radius.base,
      }}
    >
      <span style={{ ...pill, color: s.border, borderColor: s.border }}>{s.label}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontFamily: font.sans, fontSize: 15, fontWeight: 600, color: color.t1 }}>
          {e.intake?.company || '(unknown)'}
          {e.intake?.tier_preference ? (
            <span style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginLeft: 8 }}>
              {e.intake.tier_preference}
            </span>
          ) : null}
        </div>
        <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginTop: 2 }}>
          {e.engagement_id}
          {e.status === 'escalated' && e.escalation_reason ? ` · ${e.escalation_reason}` : ''}
          {e.verification?.counts
            ? ` · ${e.verification.counts.passed}/${e.verification.counts.total} verified`
            : ''}
        </div>
      </div>
      {e.status === 'published' && e.slug ? (
        <a href={`/trust-desk/c/${e.slug}`} style={linkBtn}>
          View page →
        </a>
      ) : null}
      {e.status === 'escalated' ? (
        <span style={{ fontFamily: font.mono, fontSize: 11, color: '#B45309' }}>SLA 4h</span>
      ) : null}
    </div>
  );
}

function Stat({ n, label, accent }) {
  return (
    <div>
      <div style={{ fontFamily: font.mono, fontSize: 28, fontWeight: 700, color: accent }}>{n}</div>
      <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, letterSpacing: 1 }}>
        {label}
      </div>
    </div>
  );
}

const wrap = {
  minHeight: '100vh',
  background: color.bg,
  padding: '48px 24px',
  maxWidth: 920,
  margin: '0 auto',
};
const eyebrow = {
  fontFamily: font.mono,
  fontSize: 10,
  letterSpacing: 2,
  textTransform: 'uppercase',
  color: color.t3,
  marginBottom: 8,
};
const pill = {
  fontFamily: font.mono,
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: 1.5,
  padding: '3px 8px',
  border: '1px solid',
  borderRadius: 999,
  flexShrink: 0,
};
const linkBtn = {
  fontFamily: font.sans,
  fontSize: 13,
  fontWeight: 600,
  color: color.t1,
  textDecoration: 'none',
  whiteSpace: 'nowrap',
};
const code = {
  fontFamily: font.mono,
  fontSize: 13,
  background: color.cardHover,
  padding: '2px 6px',
  borderRadius: 4,
};
