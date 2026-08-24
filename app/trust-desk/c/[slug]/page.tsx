/**
 * Customer AI Trust Page — /trust-desk/c/[slug]
 *
 * @license Apache-2.0
 *
 * Historical evaluation record. The route remains available for inspecting
 * the prototype's output shape; it is not a current service or offer.
 *
 * Rendering philosophy: calm, enterprise, attestation-shaped. No hero,
 * no CTA — this is a trust document, not a marketing page.
 */

import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getPublishedPage } from '@/lib/trust-desk/page-store';
import { styles, color, font, radius } from '@/lib/tokens';

const ACCENT = color.blue;

type PageParams = { params: Promise<{ slug: string }> };

async function loadArchivedPage(slug: string) {
  try {
    return { page: await getPublishedPage(slug), unavailable: false };
  } catch {
    return { page: null, unavailable: true };
  }
}

export async function generateMetadata({ params }: PageParams): Promise<Metadata> {
  const { slug } = await params;
  const { page, unavailable } = await loadArchivedPage(slug);
  if (unavailable) {
    return {
      title: 'Historical AI Trust Page Evaluation Unavailable',
      description: 'An archived evaluation record is unavailable. No current verification service is offered.',
      robots: { index: false, follow: false, nocache: true },
    };
  }
  if (!page) return { title: 'Not found', robots: { index: false, follow: false, nocache: true } };
  const c = page.customer;
  return {
    title: `${c.company} · Historical AI Trust Page Evaluation`,
    description: `Archived evaluation record containing stored AI security, data handling, and incident response statements for ${c.company}.`,
    robots: { index: false, follow: false, nocache: true },
  };
}

export default async function TrustPage({ params }: PageParams) {
  const { slug } = await params;
  const { page, unavailable } = await loadArchivedPage(slug);
  if (unavailable) return <ArchivedRecordUnavailable />;
  if (!page) notFound();

  const customer = page.customer;
  const status = page.status;
  const startedAt = customer?.engagement?.started_at ? new Date(customer.engagement.started_at) : null;
  const deliveredAt = customer?.engagement?.delivered_at ? new Date(customer.engagement.delivered_at) : null;
  const expiresAt = customer?.engagement?.expires_at ? new Date(customer.engagement.expires_at) : null;

  const statusStyle =
    status === 'stale' ? { border: color.red, bg: '#FEF2F2', label: 'Stored status: stale' } :
    status === 'expiring' ? { border: '#F59E0B', bg: '#FFFBEB', label: 'Stored status: expiring' } :
    { border: color.border, bg: color.card, label: 'Stored status: current at capture' };

  return (
    <div style={{ ...styles.page, background: color.card }}>
      <aside style={{ borderBottom: `1px solid ${color.border}`, background: '#FFFBEB' }}>
        <div style={{ maxWidth: 880, margin: '0 auto', padding: '14px 24px', fontSize: 13, color: color.t2, lineHeight: 1.55 }}>
          <strong style={{ color: color.t1 }}>Historical evaluation artifact.</strong>{' '}
          AI Trust Desk is not a current commercial service. This stored record is preserved to
          inspect the prototype&rsquo;s output shape; it is not a current verification, endorsement,
          audit, customer-status claim, or service commitment.
        </div>
      </aside>

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
            {deliveredAt && <span>Stored delivery date {deliveredAt.toLocaleDateString('en-US', { dateStyle: 'medium' })}</span>}
            {expiresAt && <span>· Stored expiry date {expiresAt.toLocaleDateString('en-US', { dateStyle: 'medium' })}</span>}
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
          }}>Historical AI Trust Page Evaluation</div>
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
            This archived evaluation record contains stored statements about{' '}
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
            Stored evaluation statements
          </h2>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 8 }}>
            Each stored claim includes a timestamp, digest, and prototype signature field. The
            digest is computed over the canonical text of the statement.
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
              The stored SHA-256 value can be recomputed over canonical claim text to detect a
              mismatch. The prototype also stored an HMAC over the claim hash and timestamp.
            </p>
            <p style={{ marginTop: 12 }}>
              HMAC verification depends on an operator-held secret, so this archived page does not
              provide independent public proof of origin. Neither a matching digest nor HMAC proves
              the underlying statement true, constitutes an audit, or records buyer acceptance.
            </p>
            <p style={{ marginTop: 12 }}>
              No current verification response time, endpoint availability, reviewer coverage, or
              refresh service is promised for this historical evaluation record.
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
            Archived by <a href="/trust-desk" style={{ color: color.t2, textDecoration: 'underline' }}>AI Trust Desk evaluation</a>
            {' · '}
            powered by <Link href="/" style={{ color: color.t2, textDecoration: 'underline' }}>Emilia Protocol</Link>
          </div>
          {startedAt && <div style={{ fontFamily: font.mono }}>Published {startedAt.toISOString()}</div>}
        </div>
      </footer>
    </div>
  );
}

function ArchivedRecordUnavailable(): React.ReactElement {
  return (
    <div style={{ ...styles.page, background: color.card }}>
      <main style={{ maxWidth: 720, margin: '0 auto', padding: '80px 24px' }}>
        <div style={{ fontFamily: font.mono, fontSize: 11, color: ACCENT, letterSpacing: 2, textTransform: 'uppercase', fontWeight: 600 }}>
          Historical evaluation artifact
        </div>
        <h1 style={{ fontFamily: font.sans, fontSize: 36, fontWeight: 700, letterSpacing: '-0.01em', color: color.t1, margin: '12px 0 0' }}>
          This archived record is unavailable.
        </h1>
        <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.7, marginTop: 18 }}>
          The evaluation record cannot be rendered from its stored material. AI Trust Desk is not
          a current commercial or verification service, and no response time, refresh, or delivery
          commitment applies to this historical route.
        </p>
        <Link href="/trust-desk" style={{ display: 'inline-block', color: color.blue, marginTop: 18 }}>
          Read the Trust Desk archive notice
        </Link>
      </main>
    </div>
  );
}

interface Claim {
  claim_id: string;
  signed_at: string;
  kind: string;
  title: string;
  summary?: string;
  payload_hash: string;
  signer: string;
  signature: string;
}

interface ClaimCardProps {
  claim: Claim;
}

function ClaimCard({ claim }: ClaimCardProps) {
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

interface KVProps {
  k: string;
  v: string;
}

function KV({ k, v }: KVProps) {
  return (
    <div style={{ display: 'flex', gap: 12 }}>
      <span style={{ width: 110, flexShrink: 0, color: color.t3 }}>{k}</span>
      <span style={{ color: color.t1, wordBreak: 'break-all' }}>{v}</span>
    </div>
  );
}
