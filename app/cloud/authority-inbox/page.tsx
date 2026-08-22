// SPDX-License-Identifier: Apache-2.0
'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import {
  blindRetryNotice,
  buildAuthorityNotification,
  simulateAuthorityPolicy,
  type AuthorityInboxEntry,
  type AuthorityInboxMetrics,
  type AuthorityInboxState,
  type AuthorityNotification,
} from '@/lib/cloud/authority-inbox.js';
import styles from './authority-inbox.module.css';

const ENDPOINT = '/api/cloud/approvals';

const STATE_LABELS: Record<AuthorityInboxState, string> = {
  RECEIPT_REQUIRED: 'Receipt required',
  WAITING_FOR_APPROVER: 'Waiting for approver',
  AUTHORIZED_NOT_ADMITTED: 'Authorized, not admitted',
  ADMITTED: 'Admitted',
  EXECUTED: 'Executed',
  FAILED_BEFORE_EFFECT: 'Failed before effect',
  INDETERMINATE: 'Indeterminate',
  RECONCILED: 'Reconciled',
};

interface InboxResponse {
  tenant_id: string;
  authority_inbox: AuthorityInboxEntry[];
  authority_metrics: AuthorityInboxMetrics;
  authority_inbox_profile: string;
  implementation_status: string;
}

function short(value: string | null, length = 18): string {
  if (!value) return 'Not established';
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function money(entry: AuthorityInboxEntry): string {
  const { amount, currency } = entry.exact_action;
  if (typeof amount !== 'number') return 'Amount not established';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency || 'USD',
    maximumFractionDigits: 2,
  }).format(amount);
}

function duration(value: number | null): string {
  if (value === null) return 'Not measured';
  if (value < 60_000) return `${Math.round(value / 1_000)} sec`;
  if (value < 3_600_000) return `${Math.round(value / 60_000)} min`;
  return `${(value / 3_600_000).toFixed(1)} hr`;
}

function when(value: string | null): string {
  if (!value) return 'Not established';
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Invalid timestamp';
}

export default function AuthorityInboxPage(): React.ReactElement {
  const [apiKey, setApiKey] = useState('');
  const [data, setData] = useState<InboxResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<'ALL' | AuthorityInboxState>('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [notification, setNotification] = useState<AuthorityNotification | null>(null);
  const [simulationAmount, setSimulationAmount] = useState('125000');
  const [simulationThreshold, setSimulationThreshold] = useState('100000');

  const items = data?.authority_inbox ?? [];
  const visible = filter === 'ALL' ? items : items.filter((item) => item.state === filter);
  const selected = items.find((item) => item.receipt_id === selectedId) ?? visible[0] ?? null;
  const priorIndeterminate = selected ? blindRetryNotice(selected) : null;
  const states = [...new Set(items.map((item) => item.state))];

  const simulation = useMemo(() => simulateAuthorityPolicy({
    action_type: 'large_payment_release',
    amount: Number(simulationAmount),
    policy: {
      protected_action_types: ['large_payment_release'],
      approval_threshold: Number(simulationThreshold),
      required_assurance: 'A',
    },
  }), [simulationAmount, simulationThreshold]);

  async function loadInbox(): Promise<void> {
    setLoading(true);
    setError(null);
    setNotification(null);
    try {
      const response = await fetch(ENDPOINT, {
        headers: { authorization: `Bearer ${apiKey.trim()}` },
        cache: 'no-store',
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(body?.detail || body?.title || `Request failed (${response.status})`);
      }
      setData(body as InboxResponse);
      setSelectedId((body as InboxResponse).authority_inbox?.[0]?.receipt_id ?? null);
    } catch (loadError) {
      setData(null);
      setError(loadError instanceof Error ? loadError.message : 'Authority Inbox failed to load.');
    } finally {
      setLoading(false);
    }
  }

  function previewNotification(): void {
    if (!selected) return;
    setNotification(buildAuthorityNotification(
      selected,
      selected.state === 'INDETERMINATE' ? 'reconciliation_required' : 'state_changed',
    ));
  }

  return (
    <main className={styles.page}>
      <section className={styles.hero}>
        <div>
          <p className={styles.eyebrow}>Operational authority</p>
          <h1>Authority Inbox</h1>
          <p className={styles.lede}>
            One operational view of exact actions, human decisions, one-time authority,
            consequence entry, and unresolved outcomes. The interface reports only states
            established by the connected evidence.
          </p>
        </div>
        <div className={styles.scopeNote}>
          <strong>Evidence boundary</strong>
          Receipt consumption alone does not prove provider entry or execution. Without a
          separately authenticated outcome, the action remains indeterminate.
        </div>
      </section>

      <section className={styles.connection} aria-labelledby="connection-heading">
        <div>
          <p className={styles.sectionLabel}>Connected prototype</p>
          <h2 id="connection-heading">Load your tenant timeline</h2>
          <p>The Cloud key stays in this browser tab and is sent only to the authenticated tenant endpoint.</p>
        </div>
        <div className={styles.keyControl}>
          <label htmlFor="authority-inbox-key">Cloud API key</label>
          <div className={styles.keyRow}>
            <input
              id="authority-inbox-key"
              type="password"
              autoComplete="off"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              placeholder="ep_live_…"
            />
            <button type="button" onClick={loadInbox} disabled={loading || apiKey.trim().length === 0}>
              {loading ? 'Loading' : data ? 'Refresh' : 'Connect'}
            </button>
          </div>
          {error ? <p className={styles.error} role="alert">{error}</p> : null}
        </div>
      </section>

      {data ? (
        <>
          <section className={styles.metrics} aria-label="Authority metrics">
            <article>
              <span>Open actions</span>
              <strong>{data.authority_metrics.total}</strong>
            </article>
            <article>
              <span>Median approval</span>
              <strong>{duration(data.authority_metrics.approval_latency_ms)}</strong>
            </article>
            <article>
              <span>Expired</span>
              <strong>{data.authority_metrics.expired_count}</strong>
            </article>
            <article>
              <span>Indeterminate</span>
              <strong>{data.authority_metrics.indeterminate_count}</strong>
            </article>
            <article>
              <span>Oldest unresolved</span>
              <strong>{duration(data.authority_metrics.oldest_indeterminate_age_ms)}</strong>
            </article>
            <article>
              <span>Median reconciliation</span>
              <strong>{duration(data.authority_metrics.reconciliation_time_ms)}</strong>
            </article>
          </section>

          <section className={styles.workspace}>
            <div className={styles.queuePane}>
              <div className={styles.sectionHeading}>
                <div>
                  <p className={styles.sectionLabel}>Protected workflow</p>
                  <h2>Consequential actions</h2>
                </div>
                <Link href="/cloud/signoffs">Open signoff console</Link>
              </div>

              <div className={styles.filters} aria-label="Filter by state">
                <button
                  type="button"
                  className={filter === 'ALL' ? styles.filterActive : ''}
                  onClick={() => setFilter('ALL')}
                >
                  All {items.length}
                </button>
                {states.map((state) => (
                  <button
                    type="button"
                    key={state}
                    className={filter === state ? styles.filterActive : ''}
                    onClick={() => setFilter(state)}
                  >
                    {STATE_LABELS[state]}
                  </button>
                ))}
              </div>

              <div className={styles.queue}>
                {visible.length === 0 ? (
                  <div className={styles.empty}>
                    No tenant-owned actions are established for this filter.
                  </div>
                ) : visible.map((item) => (
                  <button
                    type="button"
                    key={item.receipt_id}
                    className={`${styles.actionCard} ${selected?.receipt_id === item.receipt_id ? styles.actionCardSelected : ''}`}
                    onClick={() => {
                      setSelectedId(item.receipt_id);
                      setNotification(null);
                    }}
                  >
                    <span className={`${styles.state} ${styles[`state${item.state}`]}`}>
                      {STATE_LABELS[item.state]}
                    </span>
                    <span className={styles.actionTitle}>
                      {item.exact_action.counterparty_name || item.exact_action.action_type}
                    </span>
                    <strong>{money(item)}</strong>
                    <span className={styles.actionMeta}>
                      {short(item.exact_action.target_resource_id, 30)} · {when(item.created_at)}
                    </span>
                    {item.named_refusal ? (
                      <code className={styles.refusal}>{item.named_refusal}</code>
                    ) : null}
                  </button>
                ))}
              </div>
            </div>

            <aside className={styles.detailPane} aria-live="polite">
              {selected ? (
                <>
                  <div className={styles.detailHeader}>
                    <div>
                      <p className={styles.sectionLabel}>Exact action</p>
                      <h2>{selected.exact_action.action_type}</h2>
                    </div>
                    <span className={`${styles.state} ${styles[`state${selected.state}`]}`}>
                      {STATE_LABELS[selected.state]}
                    </span>
                  </div>

                  {priorIndeterminate ? (
                    <div className={styles.blindRetryWarning} role="alert">
                      <strong>Reconcile this attempt before issuing new authority</strong>
                      <p>
                        The prior provider outcome is indeterminate and retry-safe is false.
                        A fresh approval could authorize the same effect twice. Complete an
                        authenticated reconciliation first.
                      </p>
                      <code>{priorIndeterminate.prior_receipt_id}</code>
                    </div>
                  ) : null}

                  <dl className={styles.facts}>
                    <div><dt>CAID</dt><dd><code>{short(selected.exact_action.action_caid, 34)}</code></dd></div>
                    <div><dt>Action digest</dt><dd><code>{short(selected.exact_action.action_hash, 34)}</code></dd></div>
                    <div><dt>Destination digest</dt><dd><code>{short(selected.exact_action.payment_destination_hash, 34)}</code></dd></div>
                    <div><dt>Authority</dt><dd>{selected.authority_source}</dd></div>
                    <div><dt>Approver role</dt><dd>{selected.approver_role || 'Not established'}</dd></div>
                    <div><dt>Assurance</dt><dd>{selected.required_assurance || 'Not established'}</dd></div>
                    <div><dt>Expires</dt><dd>{when(selected.expires_at)}</dd></div>
                    <div><dt>One-time status</dt><dd>{selected.one_time_status}</dd></div>
                    <div><dt>Outcome source</dt><dd>{selected.outcome_source || 'Not established'}</dd></div>
                    <div><dt>Profile digest</dt><dd><code>{short(selected.profile_digest, 34)}</code></dd></div>
                  </dl>

                  <div className={styles.materialChanges}>
                    <h3>Material changes</h3>
                    {selected.material_changes.length > 0
                      ? <ul>{selected.material_changes.map((change) => <li key={change}>{change}</li>)}</ul>
                      : <p>No material-change evidence is present in this timeline.</p>}
                  </div>

                  <div className={styles.timeline}>
                    <h3>Governance timeline</h3>
                    {selected.timeline.map((step) => (
                      <div className={styles.timelineRow} key={step.state}>
                        <span className={`${styles.timelineDot} ${styles[`timeline${step.status}`]}`} />
                        <div>
                          <strong>{STATE_LABELS[step.state]}</strong>
                          <span>{step.status.replaceAll('_', ' ').toLowerCase()}</span>
                        </div>
                        <time>{step.at ? when(step.at) : 'No evidence'}</time>
                      </div>
                    ))}
                  </div>

                  <div className={styles.notificationBlock}>
                    <div>
                      <h3>Notification preview</h3>
                      <p>Creates no receipt, sends no message, and authorizes nothing.</p>
                    </div>
                    <button type="button" onClick={previewNotification}>Preview</button>
                  </div>
                  {notification ? (
                    <pre className={styles.notification}>{JSON.stringify(notification, null, 2)}</pre>
                  ) : null}
                </>
              ) : <div className={styles.empty}>Select an action to inspect its evidence.</div>}
            </aside>
          </section>
        </>
      ) : null}

      <section className={styles.simulator} aria-labelledby="simulator-heading">
        <div>
          <p className={styles.sectionLabel}>Non-authorizing preview</p>
          <h2 id="simulator-heading">Policy simulation</h2>
          <p>
            Test how the pinned example policy would classify an action. The preview never
            creates a receipt, reserves authority, admits an effect, or contacts a provider.
          </p>
        </div>
        <div className={styles.simulatorControls}>
          <label>
            Action amount
            <input value={simulationAmount} inputMode="decimal" onChange={(event) => setSimulationAmount(event.target.value)} />
          </label>
          <label>
            Approval threshold
            <input value={simulationThreshold} inputMode="decimal" onChange={(event) => setSimulationThreshold(event.target.value)} />
          </label>
        </div>
        <div className={styles.simulationResult}>
          <strong>{simulation.verdict.replaceAll('_', ' ')}</strong>
          <span>{simulation.reason}</span>
          <code>authorizes=false · consumes_authority=false</code>
        </div>
      </section>
    </main>
  );
}
