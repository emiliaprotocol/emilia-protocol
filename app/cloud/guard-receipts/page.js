// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — receipts dashboard.
//
// Server component. Queries audit_events directly (server components are
// not subject to write-discipline route restrictions; only files under
// app/api/**/route.js need to use getGuardedClient). Replays the
// guard.* event stream to derive each receipt's current status.
//
// AUTH GATE: This page exposes organization_id, action_type, amounts, and
// adapter metadata. Without a valid Bearer token from the request, render
// a "sign-in required" placeholder with NO data. This is the minimum
// guard until /cloud/* gets proper session-cookie auth — browsers
// navigating to this URL without authenticating see only the placeholder.

import Link from 'next/link';
import { headers } from 'next/headers';
import { authenticateRequest } from '@/lib/supabase';
import { getServiceClient } from '@/lib/supabase';
import { logger } from '@/lib/logger.js';

export const metadata = {
  title: 'Guard Receipts — EMILIA Cloud',
  description: 'Recent GovGuard + FinGuard trust receipts and their lifecycle state.',
};

// Pull the last N guard.* events. With 500 events we cover a wide enough
// window to display ~50 receipts including their full timeline (each
// receipt has 1-5 events: created, signoff_requested?, signoff_decided?,
// consumed?). Increase if the page starts truncating active receipts.
const RECENT_EVENT_LIMIT = 500;

async function loadRecentReceipts() {
  try {
    const supabase = getServiceClient();
    const { data: events, error } = await supabase
      .from('audit_events')
      .select('event_type, target_id, actor_id, after_state, created_at')
      .like('event_type', 'guard.%')
      .order('created_at', { ascending: false })
      .limit(RECENT_EVENT_LIMIT);
    if (error) {
      logger.warn('[guard-receipts dashboard] audit_events fetch failed:', error.message);
      return { receipts: [], error: error.message };
    }

    // Group events by target_id (receipt_id) and replay to current state.
    const byReceipt = new Map();
    for (const e of events || []) {
      if (!byReceipt.has(e.target_id)) byReceipt.set(e.target_id, []);
      byReceipt.get(e.target_id).push(e);
    }

    const receipts = [];
    for (const [receiptId, evs] of byReceipt) {
      const eventsAsc = [...evs].reverse(); // chronological
      const created = eventsAsc.find((e) => e.event_type === 'guard.trust_receipt.created');
      if (!created) continue;
      const base = created.after_state || {};

      let status = base.receipt_status || 'issued';
      if (eventsAsc.some((e) => e.event_type === 'guard.trust_receipt.consumed')) status = 'consumed';
      else if (eventsAsc.some((e) => e.event_type === 'guard.signoff.rejected')) status = 'rejected';
      else if (eventsAsc.some((e) => e.event_type === 'guard.signoff.approved')) status = 'approved_pending_consume';

      receipts.push({
        receipt_id: receiptId,
        action_type: base.action_type || 'unknown',
        organization_id: base.organization_id || 'unknown',
        decision: base.decision || 'unknown',
        enforcement_mode: base.enforcement_mode || 'enforce',
        status,
        adapter: base.adapter || null,
        amount: base.amount ?? null,
        currency: base.currency ?? null,
        created_at: created.created_at,
        signoff_required: !!base.signoff_required,
      });
    }

    receipts.sort((a, b) => b.created_at.localeCompare(a.created_at));
    return { receipts, error: null };
  } catch (err) {
    logger.warn('[guard-receipts dashboard] threw:', err?.message);
    return { receipts: [], error: 'Dashboard query failed.' };
  }
}

function statusBadge(status) {
  const colors = {
    issued: { bg: 'rgba(34,197,94,0.12)', fg: '#22C55E' },
    pending_signoff: { bg: 'rgba(176,141,53,0.14)', fg: '#B08D35' },
    approved_pending_consume: { bg: 'rgba(59,130,246,0.14)', fg: '#3B82F6' },
    consumed: { bg: 'rgba(122,128,154,0.14)', fg: '#7a809a' },
    rejected: { bg: 'rgba(248,113,113,0.14)', fg: '#f87171' },
    denied: { bg: 'rgba(248,113,113,0.14)', fg: '#f87171' },
  };
  const c = colors[status] || colors.issued;
  return (
    <span style={{
      display: 'inline-block',
      padding: '3px 10px',
      borderRadius: 12,
      fontSize: 10,
      fontWeight: 600,
      letterSpacing: 1,
      textTransform: 'uppercase',
      fontFamily: "'IBM Plex Mono', monospace",
      background: c.bg,
      color: c.fg,
    }}>{status}</span>
  );
}

function SignInRequired() {
  return (
    <div style={{ minHeight: '100vh', background: '#020617', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" }}>
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '120px 24px', textAlign: 'center' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#7a809a', marginBottom: 16 }}>
          Authentication required
        </div>
        <h1 style={{ fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 }}>Guard Receipts</h1>
        <p style={{ fontSize: 14, color: '#7a809a', maxWidth: 480, margin: '0 auto 32px', lineHeight: 1.7 }}>
          This dashboard exposes pre-action trust receipts including organization,
          action-type, and amount metadata. Provide an EP operator API key to view
          recent activity:
        </p>
        <div style={{ background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '16px 20px', textAlign: 'left', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: '#7a809a', maxWidth: 540, margin: '0 auto' }}>
          <div style={{ color: '#B08D35', marginBottom: 6 }}># Programmatic (curl):</div>
          <div>curl -H &quot;Authorization: Bearer ep_live_...&quot; \</div>
          <div style={{ marginLeft: 12 }}>https://emiliaprotocol.ai/cloud/guard-receipts</div>
          <div style={{ color: '#B08D35', marginTop: 16, marginBottom: 6 }}># Or query the API directly:</div>
          <div>GET /api/v1/trust-receipts/&#123;id&#125;/evidence</div>
        </div>
        <p style={{ fontSize: 12, color: '#4a4f6a', marginTop: 32, fontFamily: "'IBM Plex Mono', monospace" }}>
          Browser-cookie authentication for /cloud/* lands in v1.1. Until then,
          this dashboard is API-key gated.
        </p>
      </div>
    </div>
  );
}

export default async function GuardReceiptsPage() {
  // Auth gate. authenticateRequest expects a Request, but we only have
  // headers() — wrap in a minimal shim so the same RPC validation path runs.
  const h = await headers();
  const authHeader = h.get('authorization') || '';
  if (!authHeader.startsWith('Bearer ep_')) {
    return <SignInRequired />;
  }
  const auth = await authenticateRequest({
    headers: { get: (name) => h.get(name) || null },
  });
  if (auth.error) {
    return <SignInRequired />;
  }

  const { receipts, error } = await loadRecentReceipts();

  // Aggregate stats
  const total = receipts.length;
  const pending = receipts.filter(r => r.status === 'pending_signoff' || r.status === 'approved_pending_consume').length;
  const consumed = receipts.filter(r => r.status === 'consumed').length;
  const denied = receipts.filter(r => r.status === 'rejected' || r.status === 'denied').length;

  return (
    <div style={{ minHeight: '100vh', background: '#020617', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" }}>
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '40px 24px' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 8 }}>
          GovGuard · FinGuard
        </div>
        <h1 style={{ fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8 }}>Guard Receipts</h1>
        <p style={{ fontSize: 14, color: '#7a809a', marginBottom: 32, maxWidth: 640 }}>
          Recent v1 trust receipts created via <code style={{ fontFamily: "'IBM Plex Mono', monospace", color: '#B08D35' }}>/api/v1/trust-receipts</code> or
          a domain adapter. Status replays the audit-event stream — every transition
          is durably recorded in <code style={{ fontFamily: "'IBM Plex Mono', monospace" }}>audit_events</code>.
        </p>

        {error && (
          <div style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 }}>
            {error}
          </div>
        )}

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 }}>
          {[
            { label: 'Total (recent)', value: total, color: '#e8eaf0' },
            { label: 'Pending', value: pending, color: '#B08D35' },
            { label: 'Consumed', value: consumed, color: '#22C55E' },
            { label: 'Rejected/Denied', value: denied, color: '#f87171' },
          ].map((s) => (
            <div key={s.label} style={{ background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '20px 24px' }}>
              <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: '#7a809a', marginBottom: 8 }}>
                {s.label}
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, letterSpacing: -1, color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>

        {/* Table */}
        <div style={{ background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Receipt ID', 'Action type', 'Status', 'Mode', 'Adapter', 'Created', 'Evidence'].map((h) => (
                  <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1.5, textTransform: 'uppercase', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {receipts.length === 0 && !error && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 }}>
                    No guard receipts in the last {RECENT_EVENT_LIMIT} audit events. Create one with{' '}
                    <code style={{ color: '#B08D35' }}>POST /api/v1/trust-receipts</code> or via an adapter.
                  </td>
                </tr>
              )}
              {receipts.map((r) => (
                <tr key={r.receipt_id}>
                  <td style={{ padding: '12px 14px', fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    {r.receipt_id.slice(0, 14)}…
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    {r.action_type}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    {statusBadge(r.status)}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: '#7a809a', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    {r.enforcement_mode}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: '#7a809a', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    {r.adapter || '—'}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: '#7a809a', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    {new Date(r.created_at).toISOString().slice(0, 19).replace('T', ' ')}
                  </td>
                  <td style={{ padding: '12px 14px', fontSize: 12, borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <Link href={`/api/v1/trust-receipts/${r.receipt_id}/evidence`} style={{ color: '#3B82F6', textDecoration: 'none', fontFamily: "'IBM Plex Mono', monospace" }}>
                      packet →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p style={{ fontSize: 12, color: '#4a4f6a', marginTop: 24, fontFamily: "'IBM Plex Mono', monospace" }}>
          Showing the most recent {RECENT_EVENT_LIMIT} guard.* audit events grouped by receipt_id.
          For a deeper query window, hit <code>/api/v1/trust-receipts/&#123;id&#125;/evidence</code> directly.
        </p>
      </div>
    </div>
  );
}
