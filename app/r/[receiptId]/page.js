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
// boot. That is deliberate — the receipt's value is "look at what a real
// EP-signed receipt looks like and verify the signature with our public
// npm package," not "trust this specific demo key forever."
//
// Scenario (per GTM brief, 2026-04-26):
// A vendor self-service portal request attempted to change Acme
// Industrial LLC's deposit account of record. EMILIA's risk engine
// flagged four signals; policy required two-party named approval
// before the change could be applied. Both approvers signed off; the
// change was applied. The receipt below is the cryptographic record.

function buildDemoReceipt() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const issuedAt = new Date('2026-04-15T22:14:08Z').toISOString();
  const expiresAt = new Date('2026-04-16T22:14:08Z').toISOString();

  // We never print the actual routing/account numbers on a public page —
  // only their hashes. Hashes prove the receipt is bound to a specific
  // change without leaking PII. Production receipts use the same pattern.
  const beforeBank = crypto
    .createHash('sha256')
    .update('demo|routing:121000358|account:7421-9933-4421')
    .digest('hex');
  const afterBank = crypto
    .createHash('sha256')
    .update('demo|routing:063100277|account:8884-2210-9988')
    .digest('hex');

  const payload = {
    receipt_id: 'tr_example',
    issuer: 'ep_demo_treasury_v1',
    subject: 'vendor:VEND-9821',
    claim: {
      action_type: 'vendor_bank_account_change',
      outcome: 'allow_with_signoff',
      context: {
        organization: 'demo_treasury',
        vendor_id: 'VEND-9821',
        vendor_name: 'Acme Industrial LLC',
        change: {
          before_bank_hash: `sha256:${beforeBank}`,
          after_bank_hash: `sha256:${afterBank}`,
        },
        submitted_via: 'vendor_self_service_portal',
        submitter_session_hash: 'sha256:8b2f0a1c4e9d…',
        risk_signals: [
          'NEW_DESTINATION',
          'AFTER_HOURS_SUBMISSION',
          'NO_PRIOR_CHANGE_30D',
          'UNUSUAL_SUBMITTER_ASN',
        ],
        approval_policy: 'two_party_independent_approval',
        outbound_payments_pending_usd: 248750,
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
    action_type: 'vendor_bank_account_change',
    decision: 'allow_with_signoff',
    enforcement_mode: 'enforce',
    expires_at: expiresAt,
    // ── Buyer-readable narrative — sits at the top of the page ──
    narrative: {
      headline:
        'Vendor bank-account change — fraud signals tripped, two-party approval required.',
      body:
        'On April 15, 2026 at 22:14 UTC, the vendor self-service portal received a request to change the deposit account of record for Acme Industrial LLC (vendor VEND-9821). EMILIA flagged four risk signals (new destination, after-hours, no change in 30 days, unusual submitter ASN). Policy required two independent named humans to approve before the change could be applied. With $248,750 in vendor payments scheduled to that account, no payment was released until both approvals were on record.',
      outcome:
        'Two named humans approved. Change applied. Cryptographic record below.',
    },
    risk_signals: payload.claim.context.risk_signals,
    change_hashes: payload.claim.context.change,
    payments_at_risk_usd: payload.claim.context.outbound_payments_pending_usd,
    timeline: [
      { event: 'guard.trust_receipt.created',  actor_id: 'vendor_portal_agent',     at: '2026-04-15T22:14:08Z', action: 'submit_change' },
      { event: 'eye.risk.flagged',             actor_id: 'ep_eye',                  at: '2026-04-15T22:14:08Z', action: 'flag_high_risk' },
      { event: 'guard.signoff.requested',      actor_id: 'ep_policy_engine',        at: '2026-04-15T22:14:09Z', action: 'request_two_party_approval' },
      { event: 'guard.signoff.approved',       actor_id: 'ap_controller_jane_park', at: '2026-04-15T22:32:41Z', action: 'approve_1_of_2' },
      { event: 'guard.signoff.approved',       actor_id: 'cfo_delegate_kevin_chen', at: '2026-04-15T22:48:17Z', action: 'approve_2_of_2' },
      { event: 'guard.trust_receipt.consumed', actor_id: 'vendor_master_data_svc',  at: '2026-04-15T22:48:22Z', action: 'apply_change' },
    ],
    signoff: {
      required: true,
      threshold: 'two_party_independent_approval',
      approvers: [
        { id: 'ap_controller_jane_park', role: 'AP Controller',  approved_at: '2026-04-15T22:32:41Z' },
        { id: 'cfo_delegate_kevin_chen', role: 'CFO Delegate',   approved_at: '2026-04-15T22:48:17Z' },
      ],
      // Single-approver fallbacks below preserve back-compat with any
      // older renderer that reads .approver_id / .approved_at scalars.
      approver_id: 'ap_controller_jane_park',
      approved_at: '2026-04-15T22:48:17Z',
    },
    consume: {
      consumed_at: '2026-04-15T22:48:22Z',
      consumed_by_system: 'vendor_master_data_svc',
      execution_reference_id: 'vmd_change_8E2A1F4B',
    },
    is_demo: true,
  };
}

const DEMO_RECEIPT = buildDemoReceipt();

// ─── Real-receipt loader (DB) ─────────────────────────────────────────────

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

async function loadReceipt(receiptId) {
  // Demo: accept both the marketing slug (/r/example) and the canonical
  // receipt_id (/r/tr_example). The receipt itself always carries
  // receipt_id === 'tr_example' regardless of which URL the user hit.
  if (receiptId === 'example' || receiptId === 'tr_example') return DEMO_RECEIPT;
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
            DEMO RECEIPT — synthetic vendor scenario, real Ed25519 signature generated at server boot. The signature below verifies; the public key rotates each cold start. Production receipts come from <code style={{ marginLeft: 4 }}>POST /api/v1/trust-receipts</code> and live forever in the append-only audit log.
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
