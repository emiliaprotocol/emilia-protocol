/**
 * Customer AI Trust Page — /trust-desk/c/[slug]
 *
 * @license Apache-2.0
 *
 * The durable product: a live URL a seller shares with their enterprise
 * buyer. Every claim is signed and timestamped; buyer-side independent
 * verification ships day 21.
 *
 * Rendering philosophy: calm, enterprise, attestation-shaped. No hero,
 * no CTA — this is a trust document, not a marketing page.
 */

import { notFound } from 'next/navigation';
import { loadCustomer, trustPageStatus } from '@/lib/trust-desk/customers';
import { styles, color, font, radius } from '@/lib/tokens';

const ACCENT = color.blue;

export async function generateMetadata({ params }) {
  const { slug } = await params;
  const c = loadCustomer(slug);
  if (!c) return { title: 'Not found' };
  return {
    title: `${c.company} · AI Trust Page`,
    description: `Published AI security, data handling, and incident response attestations for ${c.company}.`,
    robots: { index: false, follow: false }, // only buyer with the URL
  };
}

export default async function TrustPage({ params }) {
  const { slug } = await params;
  const customer = loadCustomer(slug);
  if (!customer) notFound();

  const status = trustPageStatus(customer);
  const startedAt = customer?.engagement?.started_at ? new Date(customer.engagement.started_at) : null;
  const deliveredAt = customer?.engagement?.delivered_at ? new Date(customer.engagement.delivered_at) : null;
  const expiresAt = customer?.engagement?.expires_at ? new Date(customer.engagement.expires_at) : null;

  const statusStyle =
    status === 'stale' ? { border: color.red, bg: '#FEF2F2', label: '● Stale — needs refresh' } :
    status === 'expiring' ? { border: '#F59E0B', bg: '#FFFBEB', label: '● Expiring soon' } :
    { border: color.border, bg: color.card, label: '● Current' };

  return (
    <div style={{ ...styles.page, background: color.card }}>
      {/* Status bar */}
      <div style={{ borderBottom: `1px solid ${statusStyle.border}`, background: statusStyle.bg }}>
        <div style={{
          maxWidth: 880, margin: '0 auto', padding: '10px 24px',
          display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between',
          alignItems: 'center', gap: 12, fontSize: 12, color: color.t2,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              fontFamily: font.mono, fontSize: 11, color: statusStyle.border,
              background: color.card, border: `1px solid ${statusStyle.border}`,
              padding: '3px 10px', borderRadius: 999, fontWeight: 600,
            }}>{statusStyle.label}</span>
            {deliveredAt && <span>Last verified {deliveredAt.toLocaleDateString('en-US', { dateStyle: 'medium' })}</span>}
            {expiresAt && <span>· Expires {expiresAt.toLocaleDateString('en-US', { dateStyle: 'medium' })}</span>}
          </div>
          <a href="#verify" style={{ color: color.t3, textDecoration: 'underline' }}>How to verify</a>
        </div>
      </div>

      {/* Header */}
      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ maxWidth: 880, margin: '0 auto', padding: '48px 24px' }}>
          <div style={{
            fontFamily: font.mono, fontSize: 11, color: ACCENT,
            letterSpacing: 2, textTransform: 'uppercase', fontWeight: 600,
          }}>AI Trust Page</div>
          <h1 style={{
            fontFamily: font.sans, fontSize: 40, fontWeight: 700,
            letterSpacing: '-0.01em', color: color.t1, margin: '8px 0 0',
          }}>{customer.company}</h1>
          {customer.product_tagline && (
            <p style={{ fontSize: 18, color: color.t2, marginTop: 8, lineHeight: 1.4 }}>
              {customer.product_tagline}
            </p>
          )}
          <div style={{ fontSize: 14, color: color.t2, marginTop: 20, lineHeight: 1.6, maxWidth: 680 }}>
            This page contains published attestations about{' '}
            <strong style={{ color: color.t1 }}>{customer.company}</strong>&apos;s AI product
            security, data handling, and incident response posture.
            {customer.engagement?.buyer_name && (
              <> Prepared in connection with <strong>{customer.engagement.buyer_name}</strong>.</>
            )}
          </div>
        </div>
      </section>

      {/* Claims */}
      <section>
        <div style={{ maxWidth: 880, margin: '0 auto', padding: '48px 24px' }}>
          <h2 style={{ fontFamily: font.sans, fontSize: 24, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            Published attestations
          </h2>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 8 }}>
            Each claim is signed by AI Trust Desk and timestamped. Hashes are computed over
            the canonical text of the attestation.
          </p>
          <div style={{ marginTop: 32, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {customer.claims.map((claim) => (
              <ClaimCard key={claim.claim_id} claim={claim} />
            ))}
          </div>
        </div>
      </section>

      {/* Verify */}
      <section id="verify" style={{ borderTop: `1px solid ${color.border}`, background: color.bg }}>
        <div style={{ maxWidth: 880, margin: '0 auto', padding: '48px 24px' }}>
          <h2 style={{ fontFamily: font.sans, fontSize: 24, fontWeight: 700, letterSpacing: '-0.01em', margin: 0 }}>
            How to verify
          </h2>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.7, marginTop: 16 }}>
            <p>
              Every claim on this page includes a SHA-256 hash over its canonical text and an
              HMAC signature by AI Trust Desk. The signature covers the claim hash and the
              timestamp together, so a backdated claim produces a signature that no longer verifies.
            </p>
            <p style={{ marginTop: 12 }}>
              To verify a claim today, email{' '}
              <a href="mailto:verify@aitrustdesk.com" style={{ color: ACCENT, textDecoration: 'underline' }}>
                verify@aitrustdesk.com
              </a>{' '}
              with the <code style={codeStyle}>claim_id</code> (starts with <code style={codeStyle}>clm_</code>).
              We will reply with the canonical claim text and signing metadata within 1 business day.
            </p>
            <p style={{ marginTop: 12 }}>
              An automated verification endpoint at{' '}
              <code style={codeStyle}>/api/verify/[claim_id]</code> is rolling out. When live,
              this paragraph will link directly.
            </p>
          </div>
        </div>
      </section>

      <footer style={{ borderTop: `1px solid ${color.border}`, background: color.card }}>
        <div style={{
          maxWidth: 880, margin: '0 auto', padding: '24px',
          display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between',
          gap: 12, fontSize: 12, color: color.t3,
        }}>
          <div>
            Published by <a href="/trust-desk" style={{ color: color.t2, textDecoration: 'underline' }}>AI Trust Desk</a>
            {' · '}
            powered by <a href="/" style={{ color: color.t2, textDecoration: 'underline' }}>Emilia Protocol</a>
          </div>
          {startedAt && <div style={{ fontFamily: font.mono }}>Published {startedAt.toISOString()}</div>}
        </div>
      </footer>
    </div>
  );
}

const codeStyle = {
  background: color.cardHover, padding: '2px 6px', borderRadius: 3,
  fontFamily: font.mono, fontSize: 12, color: color.t1,
};

function ClaimCard({ claim }) {
  const signedAt = new Date(claim.signed_at);
  return (
    <div style={{
      background: color.card, border: `1px solid ${color.border}`,
      borderRadius: radius.base, padding: 24,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{
            fontFamily: font.mono, fontSize: 10, color: ACCENT,
            letterSpacing: 2, textTransform: 'uppercase', fontWeight: 600,
          }}>
            {claim.kind}
          </div>
          <div style={{ fontSize: 16, fontWeight: 600, color: color.t1, marginTop: 6 }}>
            {claim.title}
          </div>
        </div>
        <span style={{
          fontFamily: font.mono, fontSize: 11, color: color.green,
          border: `1px solid ${color.green}`, background: `${color.green}10`,
          padding: '3px 10px', borderRadius: 999, fontWeight: 600,
        }}>● Signed</span>
      </div>

      {claim.summary && (
        <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginTop: 12 }}>
          {claim.summary}
        </p>
      )}

      <details style={{ borderTop: `1px solid ${color.border}`, paddingTop: 16, marginTop: 16 }}>
        <summary style={{ cursor: 'pointer', fontSize: 13, color: color.t3 }}>
          Signature details
        </summary>
        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6, fontFamily: font.mono, fontSize: 11 }}>
          <KV k="claim_id" v={claim.claim_id} />
          <KV k="payload_hash" v={claim.payload_hash} />
          <KV k="signed_at" v={signedAt.toISOString()} />
          <KV k="signer" v={claim.signer} />
          <KV k="signature" v={claim.signature} />
        </div>
      </details>
    </div>
  );
}

function KV({ k, v }) {
  return (
    <div style={{ display: 'flex', gap: 12 }}>
      <span style={{ width: 110, flexShrink: 0, color: color.t3 }}>{k}</span>
      <span style={{ color: color.t1, wordBreak: 'break-all' }}>{v}</span>
    </div>
  );
}
