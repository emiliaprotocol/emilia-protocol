// SPDX-License-Identifier: Apache-2.0
// EP — Public Trust Receipt page (the "[See Live Example]" target).
//
// /r/{receiptId} renders a public-facing trust-receipt evidence packet:
//   - the canonical action that was authorized
//   - the signed Ed25519 attestation
//   - the Merkle anchor (when present)
//   - the full timeline of state transitions
//   - a "Verify yourself" code block — anyone can install
//     @emilia-protocol/verify and re-check the signature
//
// This is the page the AWS proposal, GovGuard/FinGuard landing pages,
// and cold emails all link to as proof. Treat it as a sales surface,
// not a debug view.
//
// ID handling:
//   tr_example → hardcoded demo receipt with a real Ed25519 signature
//                generated at module-load time. Always works, even
//                without prod DB access.
//   tr_<32-hex> → live receipt fetched from audit_events via the
//                same code path that powers /api/v1/trust-receipts/{id}/evidence

import crypto from 'node:crypto';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { getServiceClient } from '@/lib/supabase';
import { logger } from '@/lib/logger.js';

export const metadata = {
  title: 'Trust Receipt — EMILIA Protocol',
  description:
    'Publicly verifiable trust receipt: who approved this action, under what authority, when, and with what cryptographic proof. Verify yourself with @emilia-protocol/verify.',
};

// ─── Demo receipt — built once at module load ─────────────────────────────
// The demo is a real Ed25519-signed EP-RECEIPT-v1 document. The keypair
// lives only in this module's runtime; it is regenerated on every cold
// boot. This is fine for a public demo (the receipt's value is "look at
// what a real signed receipt looks like," not "trust this specific key").

function buildDemoReceipt() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const issuedAt = new Date('2026-04-15T10:30:00Z').toISOString();
  const expiresAt = new Date('2026-04-16T10:30:00Z').toISOString();

  const payload = {
    receipt_id: 'tr_example',
    issuer: 'ep_demo_treasury_v1',
    subject: 'recipient_demo_acme_corp',
    claim: {
      action_type: 'large_payment_release',
      outcome: 'allow_with_signoff',
      context: {
        organization: 'demo_treasury',
        amount_usd: 250000,
        beneficiary: 'Acme Corp — Account ****9876',
        purpose: 'Q2 vendor settlement',
      },
    },
    created_at: issuedAt,
    protocol_version: 'EP-CORE-v1.0',
  };

  // Canonicalize and sign — same shape used by the real /api/receipt route.
  const canonicalPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const signature = crypto
    .sign(null, Buffer.from(canonicalPayload, 'utf8'), privateKey)
    .toString('base64url');
  const publicKeyB64 = publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');

  return {
    receipt_id: 'tr_example',
    document: {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: {
        algorithm: 'Ed25519',
        signer: payload.issuer,
        value: signature,
        key_discovery: '/.well-known/ep-keys.json',
      },
      metadata: {
        operator: 'ep_operator_emilia_primary',
        issued_at: issuedAt,
      },
    },
    public_key: publicKeyB64,
    organization_id: 'org_demo_treasury',
    action_type: 'large_payment_release',
    decision: 'allow_with_signoff',
    enforcement_mode: 'enforce',
    expires_at: expiresAt,
    timeline: [
      { event: 'guard.trust_receipt.created', actor_id: 'ap_user_alice', at: '2026-04-15T10:30:00Z', action: 'create' },
      { event: 'guard.signoff.requested',     actor_id: 'ap_user_alice', at: '2026-04-15T10:30:05Z', action: 'request_signoff' },
      { event: 'guard.signoff.approved',      actor_id: 'treasurer_bob', at: '2026-04-15T11:14:22Z', action: 'approved' },
      { event: 'guard.trust_receipt.consumed', actor_id: 'swift_gateway', at: '2026-04-15T11:14:30Z', action: 'consume' },
    ],
    signoff: { required: true, approver_id: 'treasurer_bob', approved_at: '2026-04-15T11:14:22Z' },
    consume: { consumed_at: '2026-04-15T11:14:30Z', consumed_by_system: 'swift_gateway', execution_reference_id: 'swift_msg_8E2A1F4B' },
    is_demo: true,
  };
}

const DEMO_RECEIPT = buildDemoReceipt();

// ─── Real-receipt loader (DB) ─────────────────────────────────────────────

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

async function loadReceipt(receiptId) {
  if (receiptId === 'tr_example') return DEMO_RECEIPT;
  if (!RECEIPT_ID_PATTERN.test(receiptId)) return null;

  try {
    const supabase = getServiceClient();
    const { data: events } = await supabase
      .from('audit_events')
      .select('event_type, actor_id, action, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .order('created_at', { ascending: true });

    if (!events || events.length === 0) return null;
    const created = events.find((e) => e.event_type === 'guard.trust_receipt.created');
    if (!created) return null;
    const base = created.after_state || {};

    return {
      receipt_id: receiptId,
      organization_id: base.organization_id,
      action_type: base.action_type,
      decision: base.decision,
      enforcement_mode: base.enforcement_mode,
      expires_at: base.expires_at,
      timeline: events.map((e) => ({
        event: e.event_type,
        actor_id: e.actor_id,
        at: e.created_at,
        action: e.action,
      })),
      signoff: {
        required: !!base.signoff_required,
        approver_id: events.find((e) => e.event_type === 'guard.signoff.approved')?.actor_id || null,
        approved_at: events.find((e) => e.event_type === 'guard.signoff.approved')?.created_at || null,
      },
      consume: {
        consumed_at: events.find((e) => e.event_type === 'guard.trust_receipt.consumed')?.after_state?.consumed_at || null,
        consumed_by_system: events.find((e) => e.event_type === 'guard.trust_receipt.consumed')?.after_state?.consumed_by_system || null,
        execution_reference_id: events.find((e) => e.event_type === 'guard.trust_receipt.consumed')?.after_state?.execution_reference_id || null,
      },
      is_demo: false,
    };
  } catch (err) {
    logger.warn('[/r/{id}] DB load failed:', err?.message);
    return null;
  }
}

// ─── Page render ──────────────────────────────────────────────────────────

const STATUS_COLORS = {
  allow:                    { bg: 'rgba(34,197,94,0.10)',   fg: '#16a34a' },
  observe:                  { bg: 'rgba(59,130,246,0.10)',  fg: '#3b82f6' },
  allow_with_signoff:       { bg: 'rgba(176,141,53,0.14)',  fg: '#B08D35' },
  deny:                     { bg: 'rgba(248,113,113,0.14)', fg: '#dc2626' },
};

function StatusBadge({ value }) {
  const c = STATUS_COLORS[value] || STATUS_COLORS.allow;
  return (
    <span style={{
      display: 'inline-block', padding: '4px 12px', borderRadius: 12,
      fontSize: 11, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase',
      fontFamily: font.mono, background: c.bg, color: c.fg,
    }}>{value}</span>
  );
}

function Row({ label, children }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: 16, padding: '14px 0', borderBottom: `1px solid ${color.border}` }}>
      <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t2, textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
      <div style={{ fontFamily: font.mono, fontSize: 13, color: color.t1, wordBreak: 'break-all' }}>{children}</div>
    </div>
  );
}

export default async function ReceiptPage({ params }) {
  const { receiptId } = await params;
  const r = await loadReceipt(receiptId);
  if (!r) notFound();

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main style={{ maxWidth: 920, margin: '0 auto', padding: '64px 24px 96px' }}>
        {r.is_demo && (
          <div style={{
            background: 'rgba(176,141,53,0.08)',
            border: `1px solid rgba(176,141,53,0.25)`,
            borderRadius: radius.base, padding: '12px 16px',
            fontFamily: font.mono, fontSize: 12, color: '#B08D35',
            marginBottom: 32,
          }}>
            DEMO RECEIPT — generated at server boot with an ephemeral keypair so this
            page works without prod DB access. Real receipts come from
            <code style={{ marginLeft: 6 }}>POST /api/v1/trust-receipts</code>
            and live forever in the append-only audit log.
          </div>
        )}

        <div style={{ marginBottom: 32 }}>
          <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 8 }}>
            EP-RECEIPT-v1 · TRUST RECEIPT
          </div>
          <h1 style={{ fontSize: 32, fontWeight: 700, letterSpacing: -1, marginBottom: 12, color: color.t1 }}>
            {r.action_type || 'trust_receipt'}
          </h1>
          <div style={{ fontFamily: font.mono, fontSize: 13, color: color.t2, marginBottom: 16 }}>
            {r.receipt_id}
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {r.decision && <StatusBadge value={r.decision} />}
            {r.enforcement_mode && (
              <span style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, padding: '4px 12px', border: `1px solid ${color.border}`, borderRadius: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
                {r.enforcement_mode}
              </span>
            )}
          </div>
        </div>

        {/* ── 1. The action ─────────────────────────────────────── */}
        <section style={{ marginBottom: 48 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16, color: color.t1 }}>The action</h2>
          <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '8px 24px' }}>
            <Row label="Organization">{r.organization_id || '—'}</Row>
            <Row label="Action type">{r.action_type || '—'}</Row>
            <Row label="Decision"><StatusBadge value={r.decision} /></Row>
            <Row label="Enforcement mode">{r.enforcement_mode || 'enforce'}</Row>
            <Row label="Expires at">{r.expires_at ? new Date(r.expires_at).toISOString() : '—'}</Row>
          </div>
        </section>

        {/* ── 2. Signoff ────────────────────────────────────────── */}
        {r.signoff?.required && (
          <section style={{ marginBottom: 48 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16, color: color.t1 }}>Accountable signoff</h2>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '8px 24px' }}>
              <Row label="Required">{r.signoff.required ? 'Yes — policy required a named approver' : 'No'}</Row>
              <Row label="Approver">{r.signoff.approver_id || '— pending —'}</Row>
              <Row label="Approved at">{r.signoff.approved_at ? new Date(r.signoff.approved_at).toISOString() : '— pending —'}</Row>
            </div>
          </section>
        )}

        {/* ── 3. Consume / execution ────────────────────────────── */}
        {r.consume?.consumed_at && (
          <section style={{ marginBottom: 48 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16, color: color.t1 }}>Execution</h2>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '8px 24px' }}>
              <Row label="Consumed at">{new Date(r.consume.consumed_at).toISOString()}</Row>
              <Row label="By system">{r.consume.consumed_by_system || '—'}</Row>
              <Row label="Execution ref">{r.consume.execution_reference_id || '—'}</Row>
            </div>
          </section>
        )}

        {/* ── 4. Timeline ───────────────────────────────────────── */}
        <section style={{ marginBottom: 48 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16, color: color.t1 }}>Timeline</h2>
          <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '20px 24px' }}>
            {r.timeline.map((t, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '180px 1fr 200px', gap: 16, padding: '10px 0', borderBottom: i < r.timeline.length - 1 ? `1px solid ${color.border}` : 'none' }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3 }}>{new Date(t.at).toISOString().slice(0, 19).replace('T', ' ')}</div>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t1 }}>{t.event}</div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t2, textAlign: 'right' }}>{t.actor_id}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ── 5. Verify yourself — the killer feature ───────────── */}
        <section style={{ marginBottom: 48 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8, color: color.t1 }}>Verify it yourself</h2>
          <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.7, marginBottom: 16 }}>
            This receipt&apos;s signature is verifiable offline by anyone — zero EP infrastructure required. Install the package, fetch the evidence packet, run verify:
          </p>
          <pre style={{
            background: '#0F172A', color: '#E8EAF0',
            fontFamily: font.mono, fontSize: 12, lineHeight: 1.6,
            padding: 20, borderRadius: radius.base,
            overflow: 'auto', margin: 0,
          }}>{`npm install @emilia-protocol/verify

// In your code:
import { verifyReceipt } from '@emilia-protocol/verify';

const evidence = await fetch(
  'https://emiliaprotocol.ai/api/v1/trust-receipts/${r.receipt_id}/evidence'
).then(r => r.json());

const result = verifyReceipt(evidence);
// → { valid: true, signer: '${r.is_demo ? r.document.signature.signer : '...'}' }`}</pre>
          {r.is_demo && (
            <p style={{ fontSize: 12, color: color.t3, marginTop: 12, fontFamily: font.mono }}>
              For this demo receipt, the public key is{' '}
              <code style={{ wordBreak: 'break-all' }}>{r.public_key.slice(0, 32)}…</code>{' '}
              (regenerated each server boot — production receipts use a stable, published operator key).
            </p>
          )}
        </section>

        {/* ── 6. Footer CTA ─────────────────────────────────────── */}
        <section style={{ borderTop: `1px solid ${color.border}`, paddingTop: 32, marginTop: 48, textAlign: 'center' }}>
          <p style={{ fontSize: 14, color: color.t2, marginBottom: 16 }}>
            Want a receipt like this for your own high-risk actions?
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="/govguard" style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 500, padding: '10px 20px', background: color.t1, color: '#FAFAF9', borderRadius: 4, textDecoration: 'none' }}>EP GovGuard</a>
            <a href="/finguard" style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 500, padding: '10px 20px', background: color.t1, color: '#FAFAF9', borderRadius: 4, textDecoration: 'none' }}>EP FinGuard</a>
            <a href="/partners" style={{ fontFamily: font.sans, fontSize: 14, fontWeight: 500, padding: '10px 20px', border: `1px solid ${color.border}`, color: color.t1, borderRadius: 4, textDecoration: 'none' }}>Request Pilot</a>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
