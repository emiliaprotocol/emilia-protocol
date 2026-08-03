'use client';

// SPDX-License-Identifier: Apache-2.0
import { useMemo, useState } from 'react';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import styles from './arena.module.css';

type Example = { label: string; target: string; amount: number; purpose: string };
type ArenaSession = {
  session_id: string;
  token: string;
  allowance: {
    agent_name: string;
    total_amount: number;
    max_amount_per_action: number;
    allowed_targets: string[];
    expires_at: string;
  };
  examples: Example[];
};
type Attempt = {
  attempt_id: string;
  decision: 'allow' | 'refuse';
  reason: string | null;
  remaining_amount: number;
  action: Example & { operation_id: string; action_type: string; currency: string };
  caid: string;
  action_digest: string;
  refusal_digest?: string;
  share_url?: string;
};

const REASON_COPY: Record<string, string> = {
  allowance_per_action_limit_exceeded: 'The request exceeded the maximum allowed for one action.',
  allowance_aggregate_limit_exceeded: 'The request exceeded the remaining allowance.',
  allowance_target_not_allowed: 'The requested destination was not on the approved target list.',
  allowance_currency_mismatch: 'The request used a different unit than the allowance.',
  allowance_expired: 'The allowance was no longer current.',
};

function publicArtifactId(shareUrl?: string): string {
  const id = shareUrl?.split('/').at(-1) ?? '';
  return /^arena_share_[0-9a-f]{40}$/.test(id) ? id : '';
}

export default function ArenaExperience() {
  const [agentName, setAgentName] = useState('Night Shift');
  const [session, setSession] = useState<ArenaSession | null>(null);
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [leadOpen, setLeadOpen] = useState(false);
  const [leadState, setLeadState] = useState<'idle' | 'sending' | 'sent'>('idle');
  const [leadError, setLeadError] = useState('');
  const [copied, setCopied] = useState('');

  const remaining = attempts.length
    ? attempts[attempts.length - 1].remaining_amount
    : session?.allowance.total_amount ?? 0;
  const used = session ? session.allowance.total_amount - remaining : 0;
  const ratio = session ? Math.max(0, Math.min(100, used / session.allowance.total_amount * 100)) : 0;

  const provision = async () => {
    setBusy('claim'); setError(''); setAttempts([]);
    try {
      const response = await fetch('/api/arena/sessions', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ agent_name: agentName }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Could not open the Arena.');
      setSession(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not open the Arena.');
    } finally { setBusy(''); }
  };

  const run = async (example: Example) => {
    if (!session) return;
    setBusy(example.label); setError('');
    try {
      const operationId = `arena-op-${crypto.randomUUID()}`;
      const response = await fetch(`/api/arena/sessions/${session.session_id}/attempts`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({
          operation_id: operationId,
          target: example.target,
          amount: example.amount,
          purpose: example.purpose,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'The challenge could not run.');
      setAttempts((current) => [...current, data]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The challenge could not run.');
    } finally { setBusy(''); }
  };

  const publish = async (attempt: Attempt) => {
    if (!session) return;
    const consent = window.confirm(
      'Create an unlisted public integrity record?\n\nThis publishes the synthetic action, target, amount, refusal reason, fingerprints, and the session public key. It does not publish your private session label. Anyone with the link can view it.',
    );
    if (!consent) return;
    setBusy(`publish:${attempt.attempt_id}`); setError('');
    try {
      const response = await fetch(
        `/api/arena/sessions/${session.session_id}/attempts/${attempt.attempt_id}/publish`,
        { method: 'POST', headers: { authorization: `Bearer ${session.token}` } },
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Could not publish the refusal.');
      setAttempts((current) => current.map((item) => item.attempt_id === attempt.attempt_id
        ? { ...item, share_url: data.share_url } : item));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not publish the refusal.');
    } finally { setBusy(''); }
  };

  const copyShare = async (url: string) => {
    await navigator.clipboard.writeText(new URL(url, window.location.origin).toString());
    setCopied(url);
    window.setTimeout(() => setCopied((current) => current === url ? '' : current), 1800);
  };

  const submitLead = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLeadState('sending'); setLeadError('');
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch('/api/pilot/request', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          offer_id: PROTECTED_WORKFLOW_PILOT.id,
          name: form.get('name'), org: form.get('org'), email: form.get('email'),
          workflow: 'other',
          artifact_id: publicArtifactId([...attempts].reverse().find((attempt) => attempt.share_url)?.share_url),
          message: `Workflow to protect: ${form.get('workflow')}. Current system of record: ${form.get('system') || 'not specified'}.`,
          website: '',
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Could not send your request.');
      setLeadState('sent');
    } catch (cause) {
      setLeadState('idle');
      setLeadError(cause instanceof Error ? cause.message : 'Could not send your request.');
    }
  };

  const stages = useMemo(() => [
    ['01', 'Start', session ? 'complete' : 'current'],
    ['02', 'Bound allowance', session ? 'complete' : 'idle'],
    ['03', 'Attempt', attempts.length ? 'complete' : session ? 'current' : 'idle'],
    ['04', 'Refuse or allow', attempts.length ? 'complete' : 'idle'],
    ['05', 'Verify & share', attempts.some((a) => a.share_url) ? 'complete' : attempts.some((a) => a.decision === 'refuse') ? 'current' : 'idle'],
  ], [session, attempts]);

  return (
    <main className={styles.page}>
      <section className={styles.hero}>
        <div>
          <p className={styles.eyebrow}>EMILIA ARENA · PUBLIC SYNTHETIC CHALLENGE</p>
          <h1>Give your agent an allowance.<br /><em>Not your account.</em></h1>
          <p className={styles.lede}>
            Label a private synthetic session. Give it 1,000 credits. Then watch EMILIA permit what fits,
            refuse what does not, and seal the refusal into a portable integrity record.
          </p>
          <div className={styles.boundary}>No signup · no money · no provider credentials · no production execution</div>
        </div>
        <div className={styles.claimCard}>
          <label htmlFor="agent-name">Private session label</label>
          <input id="agent-name" value={agentName} maxLength={64} disabled={Boolean(session)}
            onChange={(event) => setAgentName(event.target.value)} />
          <button onClick={provision} disabled={Boolean(session) || busy === 'claim'}>
            {busy === 'claim' ? 'Opening Arena…' : session ? 'Session ready' : 'Start a synthetic session →'}
          </button>
          <p>The Arena key works only here and expires in 24 hours.</p>
        </div>
      </section>

      <section className={styles.stageRail} aria-label="Arena progress">
        {stages.map(([number, label, state]) => (
          <div key={number} className={`${styles.stage} ${styles[state]}`}>
            <span>{number}</span><strong>{label}</strong><i />
          </div>
        ))}
      </section>

      {error && <div className={styles.error} role="alert">{error}</div>}

      <section className={styles.workspace}>
        <div className={styles.allowancePanel}>
          <div className={styles.panelLabel}>THE BOUNDARY</div>
          <div className={styles.balanceRow}>
            <div><span>remaining</span><strong>{session ? remaining.toLocaleString() : '—'}</strong><small>credits</small></div>
            <div className={styles.ring} style={{ '--used': `${ratio}%` } as React.CSSProperties}><span>{Math.round(ratio)}%</span><small>used</small></div>
          </div>
          <div className={styles.meter}><span style={{ width: `${ratio}%` }} /></div>
          <dl className={styles.constraints}>
            <div><dt>Total</dt><dd>{session ? '1,000 credits' : '—'}</dd></div>
            <div><dt>Per action</dt><dd>{session ? '250 credits' : '—'}</dd></div>
            <div><dt>Targets</dt><dd>{session ? 'vendor.demo · compute.batch' : '—'}</dd></div>
            <div><dt>Execution</dt><dd>synthetic · no egress</dd></div>
          </dl>
          <p className={styles.smallPrint}>This challenge demonstrates a bounded decision. It is not money, identity, certification, or production authority.</p>
        </div>

        <div className={styles.challengePanel}>
          <div className={styles.panelLabel}>CHOOSE AN ATTEMPT</div>
          <h2>What should {session?.allowance.agent_name || 'your agent'} try?</h2>
          <p>Each request is constructed on the server. You cannot submit a verdict, score, digest, or refusal reason.</p>
          <div className={styles.actionGrid}>
            {(session?.examples || [
              { label: 'Routine vendor job', target: 'vendor.demo', amount: 80, purpose: '' },
              { label: 'Oversized transfer', target: 'vendor.demo', amount: 900, purpose: '' },
              { label: 'Unapproved production target', target: 'production.database', amount: 20, purpose: '' },
            ]).map((example) => (
              <button key={example.label} disabled={!session || Boolean(busy)} onClick={() => run(example)}>
                <span><strong>{example.label}</strong><small>{example.target}</small></span>
                <b>{example.amount} CR</b>
              </button>
            ))}
          </div>
          {!session && <div className={styles.empty}>Start a synthetic session to activate the challenge.</div>}
        </div>

        <div className={styles.resultPanel} aria-live="polite">
          <div className={styles.panelLabel}>LIVE DECISION LOG</div>
          {attempts.length === 0 ? (
            <div className={styles.emptyResult}><span>◇</span><p>No attempts yet.</p><small>Gate evaluates exact actions before anything can leave the Arena.</small></div>
          ) : (
            <div className={styles.resultList}>
              {[...attempts].reverse().map((attempt) => (
                <article key={attempt.attempt_id} className={attempt.decision === 'refuse' ? styles.refused : styles.allowed}>
                  <header><span>{attempt.decision === 'refuse' ? 'REFUSED' : 'ALLOWED'}</span><b>{attempt.action.amount} CR</b></header>
                  <h3>{attempt.action.purpose.replaceAll('-', ' ')}</h3>
                  <p>{attempt.decision === 'refuse' ? REASON_COPY[attempt.reason || ''] || 'The action was outside the allowance.' : 'Inside the target, per-action, and remaining-balance limits.'}</p>
                  <details className={styles.technicalDetails}>
                    <summary>Technical action fingerprint</summary>
                    <code>{attempt.caid.slice(0, 42)}…</code>
                  </details>
                  {attempt.decision === 'refuse' && (
                    attempt.share_url ? (
                      <div className={styles.shareActions}>
                        <a href={attempt.share_url}>Open public integrity checker ↗</a>
                        <button onClick={() => copyShare(attempt.share_url!)}>{copied === attempt.share_url ? 'Copied' : 'Copy link'}</button>
                      </div>
                    ) : (
                      <button className={styles.publishButton} onClick={() => publish(attempt)} disabled={Boolean(busy)}>
                        {busy === `publish:${attempt.attempt_id}` ? 'Publishing…' : 'Create unlisted public record →'}
                      </button>
                    )
                  )}
                </article>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className={styles.howItWorks}>
        <div><span>01</span><h3>Bound</h3><p>One agent, one time window, named targets, aggregate and per-action limits.</p></div>
        <div><span>02</span><h3>Refuse</h3><p>The decision is made before an out-of-envelope action can enter an executor.</p></div>
        <div><span>03</span><h3>Record</h3><p>A signed refusal binds the exact synthetic action under the included session key. It does not establish identity, authority, or correctness.</p></div>
        <div><span>04</span><h3>Pilot</h3><p>A separately scoped engagement protects one buyer-selected workflow at its real executor boundary.</p></div>
      </section>

      <section className={styles.conversion}>
        <div>
          <p className={styles.eyebrow}>FROM SYNTHETIC TO ONE LIVE WORKFLOW</p>
          <h2>Protect the action that can actually cost you.</h2>
          <p>{PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · {PROTECTED_WORKFLOW_PILOT.workflowLabel}. First profile: {PROTECTED_WORKFLOW_PILOT.firstProfileLabel}. {PROTECTED_WORKFLOW_PILOT.eligibilityLabel}. Sandbox and read-only validation come first; production waits for a buyer-approved executor boundary. EMILIA does not verify identity, certify a deployment, take custody, settle funds, or judge the underlying decision.</p>
        </div>
        {!leadOpen ? <button onClick={() => setLeadOpen(true)}>Scope the design-partner pilot →</button> : leadState === 'sent' ? (
          <div className={styles.sent}>Request received. Iman will reply personally within one business day.</div>
        ) : (
          <form onSubmit={submitLead} className={styles.leadForm}>
            <label><span>Your name</span><input name="name" autoComplete="name" required maxLength={120} /></label>
            <label><span>Work email</span><input name="email" type="email" autoComplete="email" required maxLength={160} /></label>
            <label><span>Organization</span><input name="org" autoComplete="organization" required maxLength={160} /></label>
            <label><span>Workflow to protect</span><input name="workflow" required maxLength={180} /></label>
            <label><span>Current system of record <small>optional</small></span><input name="system" maxLength={180} /></label>
            {leadError && <div className={styles.leadError} role="alert" tabIndex={-1}>{leadError}</div>}
            <button disabled={leadState === 'sending'}>{leadState === 'sending' ? 'Sending…' : 'Request scope →'}</button>
          </form>
        )}
      </section>
    </main>
  );
}
