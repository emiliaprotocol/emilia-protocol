// SPDX-License-Identifier: Apache-2.0
// EP — Public Trust Receipt page (the "[See Live Example]" target).
//
// /r/{receiptId} renders a public-facing trust-receipt evidence packet:
//   - a buyer-readable "what happened" narrative
//   - the canonical action that was authorized
//   - the named humans who took ownership of the decision
//   - the signed Ed25519 attestation
//   - the full timeline of state transitions
//   - a "Verify yourself" code block — anyone can install
//     @emilia-protocol/verify and re-check the signature
//
// This is the page the AWS proposal, GovGuard/FinGuard landing pages,
// and cold emails all link to as proof. Treat it as a sales surface,
// not a debug view.
//
// ID handling:
//   example | tr_example → hardcoded demo receipt with a real Ed25519
//                signature generated at module-load time. Always works,
//                even without prod DB access. The shorter `/r/example`
//                slug is the marketing URL printed in proposals + cold
//                emails; `/r/tr_example` matches the canonical receipt_id
//                so anyone hand-typing a `tr_*` ID gets the same demo.
//   tr_<32-hex> → live receipt fetched from audit_events via the
//                same code path that powers /api/v1/trust-receipts/{id}/evidence

import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { getServiceClient } from '@/lib/supabase';
import { logger } from '@/lib/logger.js';
import { getDemoReceipt, isDemoReceiptId } from '@/lib/demo-receipt.js';

export const metadata = {
  title: 'Trust Receipt — EMILIA Protocol',
  description:
    'Publicly verifiable trust receipt: who approved this action, under what authority, when, and with what cryptographic proof. Verify yourself with @emilia-protocol/verify.',
};

// Demo receipt is built once in lib/demo-receipt.js with a STABLE Ed25519
// keypair (hardcoded JWK) and a recursive canonical-JSON signer. Same key
// across cold starts, same key across routes — so the public_key the page
// advertises matches the public_key returned by
// /api/demo/trust-receipts/tr_example/evidence, and verifyReceipt() over
// the document we serve passes cleanly. This was previously a fresh
// keypair per cold-boot AND used a shallow canonicalize that left
// nested fields outside the signed material — both fixed in
// lib/demo-receipt.js + @emilia-protocol/verify@1.0.1.
const DEMO_RECEIPT = getDemoReceipt();

// ─── Real-receipt loader (DB) ─────────────────────────────────────────────

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

async function loadReceipt(receiptId) {
  // Demo: accept both the marketing slug (/r/example) and the canonical
  // receipt_id (/r/tr_example). The receipt itself always carries
  // receipt_id === 'tr_example' regardless of which URL the user hit.
  if (isDemoReceiptId(receiptId)) return DEMO_RECEIPT;
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

    // Real receipts may have one OR many signoff approvals. Collect them all.
    const approvalEvents = events.filter((e) => e.event_type === 'guard.signoff.approved');
    const consumeEvent = events.find((e) => e.event_type === 'guard.trust_receipt.consumed');

    return {
      receipt_id: receiptId,
      organization_id: base.organization_id,
      action_type: base.action_type,
      decision: base.decision,
      enforcement_mode: base.enforcement_mode,
      expires_at: base.expires_at,
      narrative: null, // narratives are demo-only; real receipts speak through their fields
      risk_signals: base.risk_signals || [],
      change_hashes: base.change || null,
      payments_at_risk_usd: base.outbound_payments_pending_usd || null,
      timeline: events.map((e) => ({
        event: e.event_type,
        actor_id: e.actor_id,
        at: e.created_at,
        action: e.action,
      })),
      signoff: {
        required: !!base.signoff_required,
        threshold: base.approval_policy || null,
        approvers: approvalEvents.map((e) => ({
          id: e.actor_id,
          role: null,
          approved_at: e.created_at,
        })),
        approver_id: approvalEvents[0]?.actor_id || null,
        approved_at: approvalEvents[approvalEvents.length - 1]?.created_at || null,
      },
      consume: {
        consumed_at: consumeEvent?.after_state?.consumed_at || null,
        consumed_by_system: consumeEvent?.after_state?.consumed_by_system || null,
        execution_reference_id: consumeEvent?.after_state?.execution_reference_id || null,
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

function RiskChip({ code }) {
  return (
    <span style={{
      fontFamily: font.mono, fontSize: 10, fontWeight: 500,
      color: '#B91C1C',
      background: 'rgba(185,28,28,0.06)',
      border: '1px solid rgba(185,28,28,0.2)',
      padding: '4px 10px', borderRadius: 2, letterSpacing: 0.5,
      textTransform: 'uppercase',
    }}>{code}</span>
  );
}

export default async function ReceiptPage({ params }) {
  const { receiptId } = await params;
  const r = await loadReceipt(receiptId);
  if (!r) notFound();

  const approvers = r.signoff?.approvers && r.signoff.approvers.length > 0
    ? r.signoff.approvers
    : (r.signoff?.approver_id
        ? [{ id: r.signoff.approver_id, role: null, approved_at: r.signoff.approved_at }]
        : []);

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
            DEMO RECEIPT — synthetic vendor scenario, signed with a stable Ed25519 demo keypair. The full document and public key are returned unauthenticated by <code style={{ margin: '0 4px' }}>GET /api/demo/trust-receipts/tr_example/evidence</code>. The signature below verifies via the &ldquo;Verify it yourself&rdquo; block. Production receipts come from <code style={{ marginLeft: 4 }}>POST /api/v1/trust-receipts</code>.
          </div>
        )}

        {/* ── Header ────────────────────────────────────────────── */}
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

        {/* ── 0. What happened (narrative — demo only) ──────────── */}
        {r.narrative && (
          <section style={{ marginBottom: 48 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 12, color: color.t1 }}>What happened</h2>
            <div style={{
              background: '#FDFCFB',
              border: `1px solid ${color.border}`,
              borderLeft: `3px solid ${color.gold}`,
              borderRadius: radius.base,
              padding: '20px 24px',
            }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 12, lineHeight: 1.5 }}>
                {r.narrative.headline}
              </div>
              <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.7, marginBottom: r.narrative.outcome ? 12 : 0 }}>
                {r.narrative.body}
              </p>
              {r.narrative.outcome && (
                <p style={{ fontSize: 14, color: color.t1, lineHeight: 1.7, fontWeight: 500 }}>
                  {r.narrative.outcome}
                </p>
              )}
            </div>
          </section>
        )}

        {/* ── 1. Risk signals (the "Eye" layer's verdict) ───────── */}
        {Array.isArray(r.risk_signals) && r.risk_signals.length > 0 && (
          <section style={{ marginBottom: 48 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8, color: color.t1 }}>
              Risk signals fired
            </h2>
            <p style={{ fontSize: 13, color: color.t2, marginBottom: 16, lineHeight: 1.6 }}>
              EMILIA&apos;s Eye layer matched these signals against the policy and required signoff before consume.
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {r.risk_signals.map((s, i) => <RiskChip key={i} code={s} />)}
            </div>
          </section>
        )}

        {/* ── 2. The action ─────────────────────────────────────── */}
        <section style={{ marginBottom: 48 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16, color: color.t1 }}>The action</h2>
          <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '8px 24px' }}>
            <Row label="Organization">{r.organization_id || '—'}</Row>
            <Row label="Action type">{r.action_type || '—'}</Row>
            <Row label="Decision"><StatusBadge value={r.decision} /></Row>
            <Row label="Enforcement mode">{r.enforcement_mode || 'enforce'}</Row>
            {r.change_hashes?.before_bank_hash && (
              <Row label="Before (hashed)">
                <span style={{ color: color.t3 }}>{r.change_hashes.before_bank_hash.slice(0, 24)}…</span>
              </Row>
            )}
            {r.change_hashes?.after_bank_hash && (
              <Row label="After (hashed)">
                <span style={{ color: color.t1 }}>{r.change_hashes.after_bank_hash.slice(0, 24)}…</span>
              </Row>
            )}
            {r.payments_at_risk_usd != null && (
              <Row label="Payments held">${r.payments_at_risk_usd.toLocaleString()} pending until both approvals on record</Row>
            )}
            <Row label="Expires at">{r.expires_at ? new Date(r.expires_at).toISOString() : '—'}</Row>
          </div>
        </section>

        {/* ── 3. Accountable signoff (now multi-approver) ───────── */}
        {r.signoff?.required && approvers.length > 0 && (
          <section style={{ marginBottom: 48 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8, color: color.t1 }}>
              Accountable signoff
            </h2>
            <p style={{ fontSize: 13, color: color.t2, marginBottom: 16, lineHeight: 1.6 }}>
              Policy:{' '}
              <code style={{ fontFamily: font.mono, background: '#F5F4F0', padding: '2px 6px', borderRadius: 2 }}>
                {r.signoff.threshold || 'signoff_required'}
              </code>
              . Each approver assumes named, cryptographically bound responsibility for this exact action.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
              {approvers.map((a, i) => (
                <div key={i} style={{
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderTop: `2px solid ${color.green}`,
                  borderRadius: radius.base,
                  padding: '16px 20px',
                }}>
                  <div style={{
                    fontFamily: font.mono, fontSize: 10,
                    color: color.green, letterSpacing: 1.5, textTransform: 'uppercase',
                    marginBottom: 6,
                  }}>
                    Approval {i + 1} of {approvers.length}
                  </div>
                  <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 600, color: color.t1, marginBottom: 4 }}>
                    {a.id}
                  </div>
                  {a.role && (
                    <div style={{ fontSize: 12, color: color.t2, marginBottom: 8 }}>
                      {a.role}
                    </div>
                  )}
                  <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3 }}>
                    {a.approved_at ? new Date(a.approved_at).toISOString() : '— pending —'}
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* ── 4. Execution / consume ────────────────────────────── */}
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

        {/* ── 5. Timeline ───────────────────────────────────────── */}
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

        {/* ── 6. Verify yourself — the killer feature ───────────── */}
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
          }}>{r.is_demo ? `npm install @emilia-protocol/verify@^1.0.1

import { verifyReceipt } from '@emilia-protocol/verify';

// Public unauthenticated endpoint — only serves the demo receipt:
const { document, public_key } = await fetch(
  'https://emiliaprotocol.ai/api/demo/trust-receipts/${r.receipt_id}/evidence'
).then(r => r.json());

const result = verifyReceipt(document, public_key);
// → { valid: true, checks: { version: true, signature: true, anchor: null } }
//
// The deeply-nested claim.context.change.after_bank_hash and every
// risk_signal are bound by the recursive canonical signature.` :
`npm install @emilia-protocol/verify@^1.0.1

// Production endpoint — requires bearer auth (your tenant's evidence)
import { verifyReceipt } from '@emilia-protocol/verify';

const { document, public_key } = await fetch(
  'https://emiliaprotocol.ai/api/v1/trust-receipts/${r.receipt_id}/evidence',
  { headers: { Authorization: 'Bearer <YOUR_API_TOKEN>' } }
).then(r => r.json());

const result = verifyReceipt(document, public_key);`}</pre>
          {r.is_demo && (
            <p style={{ fontSize: 12, color: color.t3, marginTop: 12, fontFamily: font.mono }}>
              Demo public key (stable, hardcoded in <code>lib/demo-receipt.js</code>):{' '}
              <code style={{ wordBreak: 'break-all' }}>{r.public_key.slice(0, 48)}…</code>
              <br />Production receipts use operator keys held in <code>EP_OPERATOR_KEYS</code> (env, never in source).
            </p>
          )}
        </section>

        {/* ── 7. Footer CTA ─────────────────────────────────────── */}
        <section style={{ borderTop: `1px solid ${color.border}`, paddingTop: 32, marginTop: 48, textAlign: 'center' }}>
          <p style={{ fontSize: 14, color: color.t2, marginBottom: 16 }}>
            Want a receipt like this for every high-risk action your team takes?
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
