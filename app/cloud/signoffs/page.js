// SPDX-License-Identifier: Apache-2.0
'use client';

import { useState } from 'react';

const APPROVALS_ENDPOINT = '/api/cloud/approvals';
const STATUS_NAMES = ['pending', 'approved', 'rejected', 'expired', 'consumed'];

/** @type {Record<string, { bg: string, fg: string }>} */
const STATUS_TONES = {
  pending: { bg: 'rgba(176,141,53,0.14)', fg: '#D4AF52' },
  approved: { bg: 'rgba(59,130,246,0.14)', fg: '#60A5FA' },
  rejected: { bg: 'rgba(248,113,113,0.14)', fg: '#F87171' },
  expired: { bg: 'rgba(122,128,154,0.14)', fg: '#9CA3AF' },
  consumed: { bg: 'rgba(34,197,94,0.14)', fg: '#22C55E' },
};

/** @type {Record<string, import('react').CSSProperties>} */
const s = {
  page: {
    minHeight: '100vh',
    background: '#020617',
    color: '#e8eaf0',
    fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
  },
  container: { maxWidth: 1180, margin: '0 auto', padding: '40px 24px 80px' },
  eyebrow: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 11,
    letterSpacing: 3,
    textTransform: 'uppercase',
    color: '#22C55E',
    marginBottom: 8,
  },
  titleRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: 16,
  },
  h1: {
    fontSize: 30,
    fontWeight: 700,
    letterSpacing: -0.6,
    margin: 0,
    color: '#e8eaf0',
  },
  subtitle: {
    fontSize: 14,
    lineHeight: 1.7,
    color: '#7a809a',
    margin: '10px 0 30px',
    maxWidth: 760,
  },
  prototypeBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '7px 11px',
    borderRadius: 999,
    background: 'rgba(176,141,53,0.12)',
    border: '1px solid rgba(176,141,53,0.28)',
    color: '#D4AF52',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  card: {
    background: '#0F172A',
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 10,
    padding: 24,
    marginBottom: 24,
  },
  cardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    flexWrap: 'wrap',
    gap: 12,
    marginBottom: 18,
  },
  cardTitle: { fontSize: 16, fontWeight: 650, margin: 0, color: '#e8eaf0' },
  cardHint: { fontSize: 12, lineHeight: 1.6, color: '#7a809a', margin: '5px 0 0' },
  connectionState: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  keyRow: {
    display: 'grid',
    gridTemplateColumns: 'minmax(240px, 1fr) auto',
    gap: 12,
    alignItems: 'end',
  },
  formGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
    gap: 16,
  },
  field: { display: 'flex', flexDirection: 'column', gap: 7 },
  label: {
    color: '#9CA3AF',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  input: {
    width: '100%',
    boxSizing: 'border-box',
    padding: '11px 13px',
    borderRadius: 8,
    border: '1px solid rgba(255,255,255,0.1)',
    background: '#020617',
    color: '#e8eaf0',
    fontSize: 14,
    fontFamily: "'IBM Plex Sans', sans-serif",
    outline: 'none',
  },
  primaryButton: {
    padding: '11px 18px',
    borderRadius: 8,
    border: 'none',
    background: '#3B82F6',
    color: '#fff',
    cursor: 'pointer',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: 0.8,
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
  },
  secondaryButton: {
    padding: '9px 13px',
    borderRadius: 8,
    border: '1px solid rgba(255,255,255,0.1)',
    background: '#111C31',
    color: '#D1D5DB',
    cursor: 'pointer',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: 0.5,
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
  },
  consumeButton: {
    padding: '9px 13px',
    borderRadius: 8,
    border: '1px solid rgba(34,197,94,0.35)',
    background: 'rgba(34,197,94,0.12)',
    color: '#22C55E',
    cursor: 'pointer',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: 0.5,
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
  },
  formFooter: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 16,
    marginTop: 20,
  },
  securityNote: {
    color: '#64748B',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    lineHeight: 1.6,
  },
  error: {
    background: 'rgba(248,113,113,0.08)',
    border: '1px solid rgba(248,113,113,0.2)',
    borderRadius: 8,
    padding: '12px 16px',
    color: '#f87171',
    fontSize: 13,
    marginBottom: 20,
  },
  notice: {
    background: 'rgba(34,197,94,0.08)',
    border: '1px solid rgba(34,197,94,0.2)',
    borderRadius: 8,
    padding: '12px 16px',
    color: '#86EFAC',
    fontSize: 13,
    marginBottom: 20,
  },
  stats: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))',
    gap: 12,
    marginBottom: 24,
  },
  stat: {
    background: '#0F172A',
    border: '1px solid rgba(255,255,255,0.06)',
    borderRadius: 8,
    padding: '16px 18px',
  },
  statLabel: {
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    fontWeight: 700,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
    marginBottom: 7,
  },
  statValue: { fontSize: 24, fontWeight: 700, letterSpacing: -0.7 },
  filterRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    flexWrap: 'wrap',
    marginBottom: 16,
  },
  tabs: { display: 'flex', gap: 8, flexWrap: 'wrap' },
  tab: {
    padding: '7px 11px',
    borderRadius: 999,
    border: '1px solid rgba(255,255,255,0.08)',
    background: '#0F172A',
    color: '#7a809a',
    cursor: 'pointer',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    textTransform: 'capitalize',
  },
  tabActive: {
    border: '1px solid rgba(59,130,246,0.4)',
    background: 'rgba(59,130,246,0.12)',
    color: '#93C5FD',
  },
  queue: { display: 'grid', gap: 14 },
  approval: {
    background: '#0F172A',
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 10,
    padding: 20,
  },
  approvalTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    flexWrap: 'wrap',
    gap: 12,
    marginBottom: 18,
  },
  reference: {
    color: '#e8eaf0',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 13,
    fontWeight: 700,
    overflowWrap: 'anywhere',
  },
  amount: { color: '#e8eaf0', fontSize: 21, fontWeight: 700, marginTop: 6 },
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '5px 10px',
    borderRadius: 999,
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    fontWeight: 700,
    letterSpacing: 0.8,
    textTransform: 'uppercase',
  },
  details: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: 14,
    marginBottom: 17,
  },
  detailLabel: {
    display: 'block',
    color: '#4a4f6a',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 9,
    fontWeight: 700,
    letterSpacing: 1,
    textTransform: 'uppercase',
    marginBottom: 5,
  },
  detailValue: {
    color: '#B8BECD',
    fontSize: 12,
    lineHeight: 1.5,
    overflowWrap: 'anywhere',
  },
  hash: {
    display: 'block',
    padding: '10px 12px',
    borderRadius: 7,
    background: '#020617',
    color: '#7DD3FC',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 10,
    lineHeight: 1.5,
    overflowWrap: 'anywhere',
    marginBottom: 16,
  },
  actions: {
    display: 'flex',
    alignItems: 'center',
    gap: 9,
    flexWrap: 'wrap',
  },
  reviewLink: {
    color: '#60A5FA',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 11,
    textDecoration: 'none',
  },
  empty: {
    background: '#0F172A',
    border: '1px dashed rgba(255,255,255,0.1)',
    borderRadius: 10,
    padding: 48,
    textAlign: 'center',
    color: '#64748B',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: 12,
    lineHeight: 1.7,
  },
};

/**
 * @typedef {Object} Approval
 * @property {string} receipt_id
 * @property {string | null} [action_hash]
 * @property {string | null} [action_caid]
 * @property {number | null} [amount]
 * @property {string | null} [currency]
 * @property {string | null} [counterparty_name]
 * @property {string | null} [target_resource_id]
 * @property {string | null} [payment_destination_hash]
 * @property {string | null} [approver_id]
 * @property {string | null} [signoff_id]
 * @property {string | null} [review_path]
 * @property {string} status
 * @property {string | null} [created_at]
 * @property {string | null} [expires_at]
 * @property {string | null} [consumed_at]
 */

/**
 * @typedef {Object} ApprovalForm
 * @property {string} approver_id
 * @property {string} amount
 * @property {string} currency
 * @property {string} counterparty_name
 * @property {string} payment_reference
 * @property {string} payment_destination_hash
 */

/** @type {ApprovalForm} */
const EMPTY_FORM = {
  approver_id: '',
  amount: '',
  currency: 'USD',
  counterparty_name: '',
  payment_reference: '',
  payment_destination_hash: '',
};

/**
 * @param {string} apiKey
 * @param {boolean} [json]
 * @returns {Record<string, string>}
 */
function cloudHeaders(apiKey, json = false) {
  return {
    authorization: `Bearer ${apiKey.trim()}`,
    ...(json ? { 'content-type': 'application/json' } : {}),
  };
}

/** @param {Response} response */
async function responsePayload(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

/**
 * @param {any} payload
 * @param {string} fallback
 */
function responseError(payload, fallback) {
  return payload?.detail || payload?.title || payload?.error || fallback;
}

/** @param {Approval[]} approvals */
function summarize(approvals) {
  const counts = Object.fromEntries(STATUS_NAMES.map((status) => [status, 0]));
  for (const approval of approvals) {
    if (Object.hasOwn(counts, approval.status)) counts[approval.status] += 1;
  }
  return counts;
}

/** @param {Approval} approval */
function reviewPathFor(approval) {
  if (!approval.signoff_id) return null;
  return `/signoff/${encodeURIComponent(approval.signoff_id)}`;
}

/** @param {number | null | undefined} amount @param {string | null | undefined} currency */
function formatAmount(amount, currency) {
  if (typeof amount !== 'number' || !Number.isFinite(amount)) return 'Amount unavailable';
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency: currency || 'USD',
      maximumFractionDigits: 2,
    }).format(amount);
  } catch {
    return `${currency || ''} ${amount}`.trim();
  }
}

/** @param {string | null | undefined} value */
function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function SignoffsPage() {
  const [apiKey, setApiKey] = useState('');
  const [connected, setConnected] = useState(false);
  const [approvals, setApprovals] = useState(/** @type {Approval[]} */ ([]));
  const [form, setForm] = useState(/** @type {ApprovalForm} */ ({ ...EMPTY_FORM }));
  const [activeStatus, setActiveStatus] = useState('all');
  const [busy, setBusy] = useState(/** @type {string | null} */ (null));
  const [error, setError] = useState(/** @type {string | null} */ (null));
  const [notice, setNotice] = useState(/** @type {string | null} */ (null));

  const counts = summarize(approvals);
  const filtered = activeStatus === 'all'
    ? approvals
    : approvals.filter((approval) => approval.status === activeStatus);

  /** @param {string} [key] */
  async function loadApprovals(key = apiKey) {
    const inMemoryKey = key.trim();
    if (!inMemoryKey) {
      setError('Enter a Cloud API key before connecting.');
      return;
    }

    setBusy('refresh');
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(APPROVALS_ENDPOINT, {
        method: 'GET',
        headers: cloudHeaders(inMemoryKey),
        cache: 'no-store',
      });
      const payload = await responsePayload(response);
      if (!response.ok) {
        throw new Error(responseError(payload, `Approval queue request failed (${response.status}).`));
      }
      const queue = Array.isArray(payload.approvals)
        ? payload.approvals
        : (Array.isArray(payload.requests) ? payload.requests : []);
      setApprovals(queue);
      setConnected(true);
      setNotice(`Connected. Loaded ${queue.length} approval request${queue.length === 1 ? '' : 's'}.`);
    } catch (err) {
      setApprovals([]);
      setConnected(false);
      setError(err instanceof Error ? err.message : 'Unable to load the approval queue.');
    } finally {
      setBusy(null);
    }
  }

  /** @param {import('react').FormEvent<HTMLFormElement>} event */
  async function connect(event) {
    event.preventDefault();
    await loadApprovals();
  }

  /** @param {import('react').ChangeEvent<HTMLInputElement>} event */
  function updateForm(event) {
    const { name, value } = event.target;
    setForm((current) => ({
      ...current,
      [name]: name === 'currency' ? value.toUpperCase() : value,
    }));
  }

  /** @param {import('react').FormEvent<HTMLFormElement>} event */
  async function createApproval(event) {
    event.preventDefault();
    if (!apiKey.trim()) {
      setError('Enter a Cloud API key before creating an approval.');
      return;
    }

    setBusy('create');
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(APPROVALS_ENDPOINT, {
        method: 'POST',
        headers: cloudHeaders(apiKey, true),
        body: JSON.stringify({
          approver_id: form.approver_id.trim(),
          amount: Number(form.amount),
          currency: form.currency.trim().toUpperCase(),
          counterparty_name: form.counterparty_name.trim(),
          payment_reference: form.payment_reference.trim(),
          payment_destination_hash: form.payment_destination_hash.trim(),
        }),
      });
      const payload = await responsePayload(response);
      if (!response.ok) {
        throw new Error(responseError(payload, `Approval request failed (${response.status}).`));
      }

      /** @type {Approval} */
      const created = {
        ...payload,
        amount: Number(form.amount),
        currency: form.currency.trim().toUpperCase(),
        counterparty_name: form.counterparty_name.trim(),
        target_resource_id: form.payment_reference.trim(),
        payment_destination_hash: form.payment_destination_hash.trim(),
        approver_id: payload.approver_id || form.approver_id.trim(),
        status: payload.status || 'pending',
        created_at: new Date().toISOString(),
      };
      setApprovals((current) => [
        created,
        ...current.filter((approval) => approval.receipt_id !== created.receipt_id),
      ]);
      setConnected(true);
      setForm((current) => ({
        ...EMPTY_FORM,
        approver_id: current.approver_id,
        currency: current.currency,
      }));
      setNotice('Approval requested. Send the WebAuthn/WYSIWYS review link to the named approver.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create the approval request.');
    } finally {
      setBusy(null);
    }
  }

  /** @param {Approval} approval */
  async function consumeApproval(approval) {
    if (approval.status !== 'approved') return;
    const confirmed = window.confirm(
      `Consume ${approval.receipt_id} once and authorize the exact approved payment release?`,
    );
    if (!confirmed) return;

    setBusy(`consume:${approval.receipt_id}`);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(
        `${APPROVALS_ENDPOINT}/${encodeURIComponent(approval.receipt_id)}/consume`,
        {
          method: 'POST',
          headers: cloudHeaders(apiKey, true),
          body: JSON.stringify({ action_hash: approval.action_hash }),
        },
      );
      const payload = await responsePayload(response);
      if (!response.ok) {
        throw new Error(responseError(payload, `One-time consumption failed (${response.status}).`));
      }
      setApprovals((current) => current.map((item) => (
        item.receipt_id === approval.receipt_id
          ? { ...item, status: 'consumed', consumed_at: new Date().toISOString() }
          : item
      )));
      setNotice(`Receipt ${approval.receipt_id} was consumed once.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to consume the approved receipt.');
    } finally {
      setBusy(null);
    }
  }

  /** @param {Approval} approval */
  async function exportEvidence(approval) {
    setBusy(`evidence:${approval.receipt_id}`);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(
        `${APPROVALS_ENDPOINT}/${encodeURIComponent(approval.receipt_id)}/evidence`,
        {
          method: 'GET',
          headers: cloudHeaders(apiKey),
          cache: 'no-store',
        },
      );
      const payload = await responsePayload(response);
      if (!response.ok) {
        throw new Error(responseError(payload, `Evidence export failed (${response.status}).`));
      }

      const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${approval.receipt_id}-evidence.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setNotice(`JSON evidence exported for ${approval.receipt_id}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to export JSON evidence.');
    } finally {
      setBusy(null);
    }
  }

  /** @param {Approval} approval */
  async function copyReviewLink(approval) {
    const path = reviewPathFor(approval);
    if (!path) return;
    setError(null);
    try {
      if (!navigator.clipboard) throw new Error('Clipboard access is unavailable in this browser.');
      await navigator.clipboard.writeText(new URL(path, window.location.origin).toString());
      setNotice('Review link copied.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to copy the review link.');
    }
  }

  return (
    <main style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Approval endpoint</div>
        <div style={s.titleRow}>
          <h1 style={s.h1}>High-risk payment release</h1>
          <span style={s.prototypeBadge}>Implementation prototype</span>
        </div>
        <p style={s.subtitle}>
          Request one exact payment approval, route it through a Class-A
          WebAuthn/WYSIWYS review, and consume the approved authorization once.
          This console calls the real Cloud approval API.
        </p>

        {error && <div role="alert" style={s.error}>{error}</div>}
        {notice && <div role="status" aria-live="polite" style={s.notice}>{notice}</div>}

        <section style={s.card} aria-labelledby="connection-title">
          <div style={s.cardHeader}>
            <div>
              <h2 id="connection-title" style={s.cardTitle}>Cloud connection</h2>
              <p style={s.cardHint}>
                The key needs the <code>approval_request</code> permission.
              </p>
            </div>
            <span
              style={{
                ...s.connectionState,
                color: connected ? '#22C55E' : '#7a809a',
              }}
            >
              {connected ? 'Connected' : 'Not connected'}
            </span>
          </div>
          <form onSubmit={connect}>
            <div style={s.keyRow}>
              <div style={s.field}>
                <label htmlFor="cloud-api-key" style={s.label}>Cloud API key</label>
                <input
                  id="cloud-api-key"
                  type="password"
                  value={apiKey}
                  onChange={(event) => {
                    setApiKey(event.target.value);
                    setConnected(false);
                    setApprovals([]);
                    setError(null);
                    setNotice(null);
                  }}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="ept_live_…"
                  style={s.input}
                  aria-describedby="key-memory-note"
                />
              </div>
              <button
                type="submit"
                style={s.primaryButton}
                disabled={busy === 'refresh'}
              >
                {busy === 'refresh' ? 'Connecting…' : 'Connect & refresh'}
              </button>
            </div>
            <p id="key-memory-note" style={s.securityNote}>
              Cloud API key stays in React memory only. It is cleared when you reload or leave this page.
            </p>
          </form>
        </section>

        <section style={s.card} aria-labelledby="request-title">
          <div style={s.cardHeader}>
            <div>
              <h2 id="request-title" style={s.cardTitle}>Request payment approval</h2>
              <p style={s.cardHint}>
                Amount, currency, counterparty, reference, beneficiary digest, and the
                server-computed CAID are bound into the action hash.
              </p>
            </div>
            <span style={s.prototypeBadge}>WebAuthn/WYSIWYS review</span>
          </div>

          <form onSubmit={createApproval}>
            <div style={s.formGrid}>
              <div style={s.field}>
                <label htmlFor="approval-approver" style={s.label}>Approver ID</label>
                <input
                  id="approval-approver"
                  name="approver_id"
                  value={form.approver_id}
                  onChange={updateForm}
                  required
                  minLength={3}
                  maxLength={128}
                  placeholder="approver:cfo@company.com"
                  style={s.input}
                />
              </div>
              <div style={s.field}>
                <label htmlFor="approval-amount" style={s.label}>Amount</label>
                <input
                  id="approval-amount"
                  name="amount"
                  type="number"
                  inputMode="decimal"
                  min="0.01"
                  max="1000000000000"
                  step="0.01"
                  value={form.amount}
                  onChange={updateForm}
                  required
                  placeholder="82000.00"
                  style={s.input}
                />
              </div>
              <div style={s.field}>
                <label htmlFor="approval-currency" style={s.label}>Currency</label>
                <input
                  id="approval-currency"
                  name="currency"
                  value={form.currency}
                  onChange={updateForm}
                  required
                  minLength={3}
                  maxLength={3}
                  pattern="[A-Z]{3}"
                  title="Three-letter uppercase currency code"
                  style={s.input}
                />
              </div>
              <div style={s.field}>
                <label htmlFor="approval-counterparty" style={s.label}>Counterparty</label>
                <input
                  id="approval-counterparty"
                  name="counterparty_name"
                  value={form.counterparty_name}
                  onChange={updateForm}
                  required
                  maxLength={160}
                  placeholder="Example medical supplier"
                  style={s.input}
                />
              </div>
              <div style={s.field}>
                <label htmlFor="approval-reference" style={s.label}>Payment/reference ID</label>
                <input
                  id="approval-reference"
                  name="payment_reference"
                  value={form.payment_reference}
                  onChange={updateForm}
                  required
                  minLength={3}
                  maxLength={200}
                  placeholder="payment:invoice-1842"
                  style={s.input}
                />
              </div>
              <div style={s.field}>
                <label htmlFor="approval-destination" style={s.label}>Beneficiary account digest</label>
                <input
                  id="approval-destination"
                  name="payment_destination_hash"
                  value={form.payment_destination_hash}
                  onChange={updateForm}
                  required
                  pattern="sha256:[a-f0-9]{64}"
                  title="sha256 followed by 64 lowercase hexadecimal characters"
                  placeholder="sha256:…"
                  style={s.input}
                />
              </div>
            </div>
            <div style={s.formFooter}>
              <span style={s.securityNote}>
                One workflow only: <code>large_payment_release</code> · one-hour approval window.
              </span>
              <button
                type="submit"
                style={s.primaryButton}
                disabled={busy === 'create'}
              >
                {busy === 'create' ? 'Requesting…' : 'Request approval'}
              </button>
            </div>
          </form>
        </section>

        <section aria-labelledby="queue-title">
          <div style={s.stats}>
            {STATUS_NAMES.map((status) => (
              <div key={status} style={s.stat}>
                <div style={{ ...s.statLabel, color: STATUS_TONES[status].fg }}>{status}</div>
                <div style={s.statValue}>{counts[status]}</div>
              </div>
            ))}
          </div>

          <div style={s.filterRow}>
            <div>
              <h2 id="queue-title" style={s.cardTitle}>Approval queue</h2>
              <p style={s.cardHint}>Refresh after the approver completes or rejects review.</p>
            </div>
            <button
              type="button"
              style={s.secondaryButton}
              onClick={() => loadApprovals()}
              disabled={!apiKey.trim() || busy === 'refresh'}
            >
              {busy === 'refresh' ? 'Refreshing…' : 'Refresh queue'}
            </button>
          </div>

          <div style={s.tabs} aria-label="Filter approvals by status">
            {['all', ...STATUS_NAMES].map((status) => {
              const active = activeStatus === status;
              return (
                <button
                  key={status}
                  type="button"
                  onClick={() => setActiveStatus(status)}
                  aria-pressed={active}
                  style={{ ...s.tab, ...(active ? s.tabActive : {}) }}
                >
                  {status}
                </button>
              );
            })}
          </div>

          <div style={{ height: 16 }} />

          {filtered.length === 0 ? (
            <div style={s.empty}>
              {connected
                ? 'No approval requests match this status.'
                : 'Connect with a Cloud API key to load the tenant approval queue.'}
            </div>
          ) : (
            <div style={s.queue}>
              {filtered.map((approval) => {
                const tone = STATUS_TONES[approval.status] || STATUS_TONES.expired;
                const reviewPath = reviewPathFor(approval);
                const consuming = busy === `consume:${approval.receipt_id}`;
                const exporting = busy === `evidence:${approval.receipt_id}`;
                return (
                  <article key={approval.receipt_id} style={s.approval}>
                    <div style={s.approvalTop}>
                      <div>
                        <div style={s.reference}>
                          {approval.target_resource_id || approval.receipt_id}
                        </div>
                        <div style={s.amount}>
                          {formatAmount(approval.amount, approval.currency)}
                        </div>
                      </div>
                      <span style={{ ...s.badge, background: tone.bg, color: tone.fg }}>
                        {approval.status}
                      </span>
                    </div>

                    <div style={s.details}>
                      <div>
                        <span style={s.detailLabel}>Counterparty</span>
                        <span style={s.detailValue}>{approval.counterparty_name || '—'}</span>
                      </div>
                      <div>
                        <span style={s.detailLabel}>Approver ID</span>
                        <span style={s.detailValue}>{approval.approver_id || '—'}</span>
                      </div>
                      <div>
                        <span style={s.detailLabel}>Beneficiary account digest</span>
                        <span style={s.detailValue}>{approval.payment_destination_hash || '—'}</span>
                      </div>
                      <div>
                        <span style={s.detailLabel}>Receipt ID</span>
                        <span style={s.detailValue}>{approval.receipt_id}</span>
                      </div>
                      <div>
                        <span style={s.detailLabel}>Created</span>
                        <span style={s.detailValue}>{formatDate(approval.created_at)}</span>
                      </div>
                      <div>
                        <span style={s.detailLabel}>
                          {approval.status === 'consumed' ? 'Consumed' : 'Expires'}
                        </span>
                        <span style={s.detailValue}>
                          {formatDate(
                            approval.status === 'consumed'
                              ? approval.consumed_at
                              : approval.expires_at,
                          )}
                        </span>
                      </div>
                    </div>

                    <span style={s.detailLabel}>Action hash</span>
                    <code style={s.hash}>{approval.action_hash || 'Unavailable'}</code>
                    {approval.action_caid && (
                      <>
                        <span style={s.detailLabel}>Canonical action identifier</span>
                        <code style={s.hash}>{approval.action_caid}</code>
                      </>
                    )}

                    <div style={s.actions}>
                      {reviewPath && (
                        <>
                          <a
                            href={reviewPath}
                            target="_blank"
                            rel="noreferrer"
                            style={s.reviewLink}
                            aria-label={`Open WebAuthn/WYSIWYS review for ${approval.receipt_id}`}
                          >
                            Review {reviewPath} ↗
                          </a>
                          <button
                            type="button"
                            style={s.secondaryButton}
                            onClick={() => copyReviewLink(approval)}
                          >
                            Copy link
                          </button>
                        </>
                      )}
                      <button
                        type="button"
                        style={s.secondaryButton}
                        onClick={() => exportEvidence(approval)}
                        disabled={exporting}
                      >
                        {exporting ? 'Exporting…' : 'Export JSON evidence'}
                      </button>
                      {approval.status === 'approved' && (
                        <button
                          type="button"
                          style={s.consumeButton}
                          onClick={() => consumeApproval(approval)}
                          disabled={consuming || !approval.action_hash}
                          title={approval.action_hash
                            ? 'Authorize the exact approved payment release once'
                            : 'Action hash unavailable'}
                        >
                          {consuming ? 'Consuming…' : 'Consume once'}
                        </button>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
