// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — the approval surface. /signoff/[signoffId]
//
// WYSIWYS (draft §11.3 control 1): every field below renders from the
// canonical action object persisted at mint — the exact bytes the action
// hash commits to — never from a re-described copy. The page records
// rendered_at for pilot telemetry (time-to-sign starts here).

import type { Metadata } from 'next';
import { getServiceClient } from '@/lib/supabase';
import { SIGNOFF_ID_PATTERN } from '@/lib/webauthn';
import { creatorBoundSignoffRequests, decisionMatchesRequest } from '@/lib/guard-signoff-binding.js';
import { renderAction } from '@/lib/wysiwys/render.js';
import SignoffSigner from './signer';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Signoff required — EMILIA Protocol',
  robots: { index: false, follow: false },
};

const wrap = {
  minHeight: '100vh',
  background: '#0E0D0B',
  color: '#F5F2EC',
  fontFamily: "'Inter', -apple-system, system-ui, sans-serif",
  display: 'flex',
  justifyContent: 'center',
  padding: '48px 20px',
};
const card = { width: '100%', maxWidth: 560 };
const label = { fontSize: 11, letterSpacing: '0.14em', textTransform: 'uppercase', color: '#8A857C', marginBottom: 6 };
const mono = { fontFamily: "'JetBrains Mono', ui-monospace, monospace" };

interface RowProps {
  k: string;
  v: string | number;
  monoVal?: boolean;
}

interface AuditEvent {
  event_type: string;
  actor_id: string;
  after_state: any;
  target_id?: string;
  created_at?: string;
}

function Row({ k, v, monoVal }: RowProps) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, padding: '10px 0', borderBottom: '1px solid #26231F' }}>
      <span style={{ color: '#8A857C', fontSize: 13 }}>{k}</span>
      <span style={{ fontSize: 13, textAlign: 'right', wordBreak: 'break-all', ...(monoVal ? mono : null) }}>{v}</span>
    </div>
  );
}

type PageParams = { params: Promise<{ signoffId: string }> };

export default async function SignoffPage({ params }: PageParams) {
  const { signoffId } = await params;

  if (!SIGNOFF_ID_PATTERN.test(signoffId || '')) {
    return (
      <div style={wrap}><div style={card}>
        <h1 style={{ fontSize: 20 }}>Invalid signoff link</h1>
        <p style={{ color: '#8A857C' }}>The signoff id in this link is malformed.</p>
      </div></div>
    );
  }

  const supabase = getServiceClient();
  const { data: requests } = await supabase
    .from('audit_events')
    .select('target_id, actor_id, after_state, created_at')
    .eq('event_type', 'guard.signoff.requested')
    .eq('after_state->>signoff_id', signoffId)
    .limit(1);
  const requestEvent = (requests || [])[0] as AuditEvent | undefined;

  if (!requestEvent) {
    return (
      <div style={wrap}><div style={card}>
        <h1 style={{ fontSize: 20 }}>Signoff not found</h1>
        <p style={{ color: '#8A857C' }}>No pending signoff matches this link.</p>
      </div></div>
    );
  }

  const receiptId = requestEvent.target_id;
  const { data: events } = await supabase
    .from('audit_events')
    .select('event_type, actor_id, after_state')
    .eq('target_type', 'trust_receipt')
    .eq('target_id', receiptId)
    .in('event_type', ['guard.trust_receipt.created', 'guard.signoff.approved', 'guard.signoff.rejected']);
  const typedEvents = (events || []) as AuditEvent[];

  const created = typedEvents.find((e) => e.event_type === 'guard.trust_receipt.created');
  const requestIsCreatorBound = creatorBoundSignoffRequests([requestEvent], created)
    .some((s) => s.signoff_id === signoffId);
  if (!created || !requestIsCreatorBound) {
    return (
      <div style={wrap}><div style={card}>
        <h1 style={{ fontSize: 20 }}>Signoff not found</h1>
        <p style={{ color: '#8A857C' }}>No valid pending signoff matches this link.</p>
      </div></div>
    );
  }

  const decided = requestIsCreatorBound
    ? typedEvents.find(
        (e) => e.event_type !== 'guard.trust_receipt.created'
          && decisionMatchesRequest(e, requestEvent.after_state),
      )
    : null;
  const base = created?.after_state || {};
  const action = base.canonical_action || null;
  const rendered = action ? renderAction(action) : null;
  const intendedApproverId = requestEvent.after_state.approver_id
    || requestEvent.after_state.quorum?.approver_id
    || '';
  const expired = new Date(requestEvent.after_state.expires_at) < new Date();
  const status = decided
    ? (decided.event_type === 'guard.signoff.approved' ? 'approved' : 'rejected')
    : expired ? 'expired' : 'pending';

  // Pilot telemetry: time-to-sign starts at first render. ignoreDuplicates
  // keeps the FIRST render time — refreshes don't reset the clock.
  if (status === 'pending') {
    await supabase.from('signoff_metrics').upsert(
      { signoff_id: signoffId, receipt_id: receiptId, rendered_at: new Date().toISOString() },
      { onConflict: 'signoff_id', ignoreDuplicates: true },
    );
  }

  const amount = typeof action?.amount === 'number' ? action.amount : null;
  const currency = typeof action?.currency === 'string' ? action.currency : null;

  return (
    <div style={wrap}>
      <div style={card}>
        <div style={{ ...label, color: '#C9A554' }}>EMILIA Protocol · signoff {status === 'pending' ? 'required' : status}</div>
        <h1 style={{ fontSize: 24, margin: '0 0 4px', fontWeight: 650 }}>
          {(base.action_type || 'high-risk action').replace(/_/g, ' ')}
        </h1>
        {amount !== null && (
          <div style={{ ...mono, fontSize: 40, fontWeight: 700, margin: '12px 0 4px' }}>
            {currency || 'Amount'} {amount}
          </div>
        )}
        <p style={{ color: '#8A857C', fontSize: 13, marginTop: 4 }}>
          A named human must sign this exact action before it can proceed. Review every field — your signature binds them all.
        </p>

        <div style={{ margin: '20px 0 8px' }}>
          {rendered ? (
            <>
              {rendered.lines.map(({ label: lineLabel, value }) => (
                <Row key={lineLabel} k={lineLabel} v={value} monoVal />
              ))}
              {action.action_caid && (
                <Row k="Canonical action identifier" v={action.action_caid} monoVal />
              )}
              <Row k="Intended approver" v={intendedApproverId || '∅'} monoVal />
              <Row k="Expires" v={requestEvent.after_state.expires_at} monoVal />
              <Row k="Action hash" v={base.action_hash || rendered.action_hash} monoVal />
              <Row k="Display hash" v={rendered.display_hash} monoVal />
              <Row k="Render profile" v={rendered.render_profile} monoVal />
            </>
          ) : (
            <p style={{ color: '#C97954', fontSize: 13 }}>
              This receipt was minted before canonical-action persistence; the
              exact signed bytes cannot be rendered. Hash:{' '}
              <span style={mono}>{(base.action_hash || requestEvent.after_state.action_hash || '').slice(0, 24)}…</span>
            </p>
          )}
        </div>

        {action && (
          <section style={{ margin: '8px 0 20px' }} aria-label="Complete signed action">
            <div style={{ color: '#8A857C', fontSize: 12, marginBottom: 8 }}>
              Complete signed action — every extension field the action hash commits to
            </div>
            <pre style={{ ...mono, fontSize: 11, background: '#16140F', padding: 12, borderRadius: 8, overflowX: 'auto' }}>
              {JSON.stringify(action, null, 2)}
            </pre>
          </section>
        )}

        <SignoffSigner
          signoffId={signoffId}
          intendedApproverId={intendedApproverId}
          status={status}
          expectedActionHash={base.action_hash || ''}
          expectedDisplayHash={rendered?.display_hash || ''}
          expectedRenderProfile={rendered?.render_profile || ''}
        />

        <p style={{ color: '#56524B', fontSize: 11, marginTop: 28, lineHeight: 1.6 }}>
          Signing uses a passkey on this device (Face ID / Touch ID / security
          key). The challenge your authenticator signs is the SHA-256 of the
          canonical authorization context for this exact action — the receipt
          this produces verifies offline with <span style={mono}>@emilia-protocol/verify</span>.
        </p>
      </div>
    </div>
  );
}
