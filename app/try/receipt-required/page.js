'use client';

// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, cta, font, radius } from '@/lib/tokens';

const FALLBACK_ACTIONS = [
  {
    id: 'release_funds',
    label: 'Release funds',
    action: 'payment.release:wire:vendor-acme-250000',
    action_type: 'payment.release',
    target: 'wire:vendor-acme-250000',
    assurance_class: 'class_a',
    policy_id: 'demo.payment-release.class-a.v1',
  },
  {
    id: 'delete_repo',
    label: 'Delete repository',
    action: 'github.repo.delete:repo:emilia/prod-ledger',
    action_type: 'github.repo.delete',
    target: 'repo:emilia/prod-ledger',
    assurance_class: 'quorum',
    policy_id: 'demo.github-repo-delete.quorum.v1',
  },
  {
    id: 'change_bank_account',
    label: 'Change bank account',
    action: 'payment.bank_details.change:vendor:acme-routing-9124',
    action_type: 'payment.bank_details.change',
    target: 'vendor:acme-routing-9124',
    assurance_class: 'class_a',
    policy_id: 'demo.vendor-bank-change.class-a.v1',
  },
];

const STEPS = [
  { id: 'missing', label: 'No receipt', expect: '428 Receipt Required' },
  { id: 'sign', label: 'Sign exact action', expect: 'EP-RECEIPT-v1' },
  { id: 'run', label: 'Present receipt', expect: 'Action runs' },
  { id: 'replay', label: 'Replay same receipt', expect: 'replay_refused' },
  { id: 'forge', label: 'Forge receipt', expect: 'signature refused' },
  { id: 'evidence', label: 'Export evidence', expect: 'offline packet' },
];

const ACTION_COPY = {
  release_funds: {
    amount: '$250,000',
    target: 'ACME vendor wire',
    risk: 'money movement',
    prompt: 'agent> release pending vendor payment now',
  },
  delete_repo: {
    amount: 'prod-ledger',
    target: 'repository deletion',
    risk: 'code state',
    prompt: 'agent> delete repository to remove leaked data',
  },
  change_bank_account: {
    amount: 'last4 9124',
    target: 'vendor payout destination',
    risk: 'bank detail change',
    prompt: 'agent> update ACME payment routing',
  },
};

const initialStepState = () =>
  Object.fromEntries(STEPS.map((step) => [step.id, { status: 'idle', detail: step.expect }]));

function ts() {
  return new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return '{}';
  }
}

function tamperReceipt(receipt) {
  const forged = JSON.parse(JSON.stringify(receipt));
  forged.payload.claim.action_type = 'payment.release:wire:attacker-controlled';
  return forged;
}

async function postDemo(body) {
  const res = await fetch('/api/demo/require-receipt', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return {
    ok: res.ok,
    status: res.status,
    data,
    receiptRequired: res.headers.get('receipt-required'),
  };
}

export default function ReceiptRequiredTryPage() {
  const [actions, setActions] = useState(FALLBACK_ACTIONS);
  const [selectedId, setSelectedId] = useState('release_funds');
  const [steps, setSteps] = useState(initialStepState);
  const [log, setLog] = useState([
    { at: ts(), tone: 'info', text: 'ready: choose an action, then try to break the gate' },
  ]);
  const [receipt, setReceipt] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [lastChallenge, setLastChallenge] = useState(null);
  const [busy, setBusy] = useState(null);
  const [copied, setCopied] = useState(false);

  const selected = useMemo(
    () => actions.find((action) => action.id === selectedId) || actions[0] || FALLBACK_ACTIONS[0],
    [actions, selectedId],
  );
  const actionCopy = ACTION_COPY[selected.id] || ACTION_COPY.release_funds;

  useEffect(() => {
    fetch('/api/demo/require-receipt')
      .then((res) => res.json())
      .then((body) => {
        if (Array.isArray(body.actions) && body.actions.length > 0) setActions(body.actions);
      })
      .catch(() => {});
  }, []);

  function reset(nextId = selectedId) {
    setSelectedId(nextId);
    setSteps(initialStepState());
    setReceipt(null);
    setEvidence(null);
    setLastChallenge(null);
    setCopied(false);
    setLog([{ at: ts(), tone: 'info', text: `reset: target=${nextId}` }]);
  }

  function append(tone, text) {
    setLog((items) => [...items.slice(-10), { at: ts(), tone, text }]);
  }

  function mark(id, status, detail) {
    setSteps((current) => ({ ...current, [id]: { status, detail } }));
  }

  async function attemptMissing(action = selected) {
    setBusy('missing');
    mark('missing', 'running', 'calling endpoint without X-EMILIA-Receipt');
    append('cmd', `${actionCopy.prompt} | receipt=null`);
    const out = await postDemo({ demo: action.id });
    setLastChallenge(out.data);
    if (out.status === 428) {
      mark('missing', 'pass', 'blocked before mutation: 428');
      append('block', `gate> ${out.status} ${out.data.title}`);
    } else {
      mark('missing', 'fail', `unexpected status ${out.status}`);
      append('bad', `gate> unexpected status ${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function signExact(action = selected) {
    setBusy('sign');
    mark('sign', 'running', 'minting demo receipt for the exact action');
    append('cmd', `human> sign ${action.action}`);
    const out = await postDemo({
      demo: action.id,
      sign_demo_receipt: true,
      approver: 'ep:approver:demo-human',
    });
    if (out.status === 200 && out.data?.receipt) {
      setReceipt(out.data.receipt);
      mark('sign', 'pass', out.data.signed.receipt_id);
      append('ok', `receipt> ${out.data.signed.receipt_id} bound=${out.data.signed.action}`);
      setBusy(null);
      return out.data.receipt;
    }
    mark('sign', 'fail', `unexpected status ${out.status}`);
    append('bad', `signer> unexpected status ${out.status}`);
    setBusy(null);
    return null;
  }

  async function presentReceipt(doc = receipt, action = selected) {
    if (!doc) return null;
    setBusy('run');
    mark('run', 'running', 'presenting exact-action receipt');
    append('cmd', `agent> retry with ${doc.payload.receipt_id}`);
    const out = await postDemo({ demo: action.id, emilia_receipt: doc });
    if (out.status === 200) {
      setEvidence(out.data.evidence_packet);
      mark('run', 'pass', 'mutation reached executor');
      mark('evidence', 'pass', out.data.evidence_packet.policy_id);
      append('ok', `executor> ran simulated ${action.id}`);
      append('ok', `evidence> ${out.data.evidence_packet.receipt_id}`);
    } else {
      mark('run', 'fail', `unexpected status ${out.status}`);
      append('bad', `executor> refused status ${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function replayReceipt(doc = receipt, action = selected) {
    if (!doc) return null;
    setBusy('replay');
    mark('replay', 'running', 'submitting the same receipt again');
    append('cmd', `attacker> replay ${doc.payload.receipt_id}`);
    const out = await postDemo({ demo: action.id, emilia_receipt: doc });
    if (out.status === 428 && out.data?.rejected?.reason === 'replay_refused') {
      mark('replay', 'pass', 'same receipt cannot run twice');
      append('block', 'gate> replay_refused');
    } else {
      mark('replay', 'fail', `unexpected ${out.status}`);
      append('bad', `gate> replay result ${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function forgeReceipt(doc = receipt, action = selected) {
    if (!doc) return null;
    setBusy('forge');
    mark('forge', 'running', 'changing the signed action after signature');
    const forged = tamperReceipt(doc);
    append('cmd', `attacker> rewrite action_type=${forged.payload.claim.action_type}`);
    const out = await postDemo({ demo: action.id, emilia_receipt: forged });
    if (out.status === 428 && out.data?.rejected?.reason === 'untrusted_or_invalid_signature') {
      mark('forge', 'pass', 'signature no longer verifies');
      append('block', 'gate> untrusted_or_invalid_signature');
    } else {
      mark('forge', 'fail', `unexpected ${out.status}`);
      append('bad', `gate> forged result ${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function runFull() {
    reset(selected.id);
    const action = selected;
    await new Promise((resolve) => setTimeout(resolve, 60));
    await attemptMissing(action);
    const doc = await signExact(action);
    if (!doc) return;
    await presentReceipt(doc, action);
    await replayReceipt(doc, action);
    await forgeReceipt(doc, action);
  }

  async function copyEvidence() {
    if (!evidence) return;
    await navigator.clipboard?.writeText(safeJson(evidence));
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  function downloadEvidence() {
    if (!evidence) return;
    const blob = new Blob([safeJson(evidence)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${evidence.receipt_id || 'emilia'}-evidence-packet.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={s.page}>
      <SiteNav activePage="Try it" />
      <main>
        <section style={s.stage}>
          <div style={s.stageInner} className="rr-stage-grid">
            <div style={s.heroCopy}>
              <div style={s.eyebrow}>RECEIPT REQUIRED · LIVE BREAK TEST</div>
              <h1 style={s.h1}>Try to make the agent act without a receipt.</h1>
              <p style={s.lead}>
                Pick a dangerous action. The gate refuses it, accepts only an exact-action
                receipt, consumes that receipt once, and exports evidence an auditor can replay.
              </p>
              <div style={s.heroActions}>
                <button type="button" onClick={runFull} disabled={Boolean(busy)} style={s.primaryBtn}>
                  {busy ? 'Running...' : 'Run full break attempt'}
                </button>
                <button type="button" onClick={() => reset()} disabled={Boolean(busy)} style={s.darkSecondaryBtn}>
                  Reset
                </button>
              </div>
            </div>

            <div style={s.commandPanel}>
              <div style={s.panelHeader}>
                <span>agent action</span>
                <strong>{selected.action_type}</strong>
              </div>
              <div style={s.bigMetric}>{actionCopy.amount}</div>
              <div style={s.metricGrid}>
                <Metric label="Target" value={actionCopy.target} />
                <Metric label="Risk" value={actionCopy.risk} />
                <Metric label="Policy" value={selected.policy_id} />
              </div>
              <div style={s.selector}>
                {actions.map((action) => (
                  <button
                    type="button"
                    key={action.id}
                    onClick={() => reset(action.id)}
                    disabled={Boolean(busy)}
                    data-active={action.id === selected.id ? 'true' : undefined}
                    style={{
                      ...s.actionBtn,
                      ...(action.id === selected.id ? s.actionBtnActive : null),
                    }}
                  >
                    {action.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section style={s.workbench}>
          <div style={s.workbenchGrid} className="rr-grid">
            <div style={s.leftColumn}>
              <div style={s.rail}>
                {STEPS.map((step, idx) => (
                  <StepRow
                    key={step.id}
                    index={idx + 1}
                    step={step}
                    state={steps[step.id]}
                    busy={busy === step.id}
                  />
                ))}
              </div>

              <div style={s.manualControls}>
                <button type="button" onClick={() => attemptMissing()} disabled={Boolean(busy)} style={s.toolBtn}>
                  Test missing
                </button>
                <button type="button" onClick={() => signExact()} disabled={Boolean(busy)} style={s.toolBtn}>
                  Sign exact action
                </button>
                <button type="button" onClick={() => presentReceipt()} disabled={Boolean(busy) || !receipt} style={s.toolBtn}>
                  Run with receipt
                </button>
                <button type="button" onClick={() => replayReceipt()} disabled={Boolean(busy) || !receipt} style={s.toolBtn}>
                  Replay
                </button>
                <button type="button" onClick={() => forgeReceipt()} disabled={Boolean(busy) || !receipt} style={s.toolBtn}>
                  Forge
                </button>
              </div>
            </div>

            <div style={s.consolePanel}>
              <div style={s.lightPanelHeader}>
                <span>live console</span>
                <strong>{busy ? busy : 'idle'}</strong>
              </div>
              <div style={s.console}>
                {log.map((line, idx) => (
                  <motion.div
                    key={`${line.at}-${idx}-${line.text}`}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    style={{ ...s.logLine, color: logColor(line.tone) }}
                  >
                    <span style={s.logAt}>{line.at}</span>
                    <span>{line.text}</span>
                  </motion.div>
                ))}
              </div>
              <div style={s.challengeStrip}>
                <div style={s.stripLabel}>last challenge</div>
                <code style={s.stripCode}>
                  {lastChallenge?.required?.action || selected.action}
                </code>
              </div>
            </div>

            <div style={s.receiptPanel}>
              <div style={s.lightPanelHeader}>
                <span>receipt</span>
                <strong>{receipt?.payload?.receipt_id || 'not signed'}</strong>
              </div>
              <pre style={s.jsonBox}>{receipt ? safeJson({
                '@version': receipt['@version'],
                receipt_id: receipt.payload.receipt_id,
                action_type: receipt.payload.claim.action_type,
                policy_id: receipt.payload.claim.policy_id,
                assurance_class: receipt.payload.claim.assurance_class,
                signature: `${receipt.signature.value.slice(0, 32)}...`,
              }) : 'No receipt yet.'}</pre>
            </div>

            <div style={s.evidencePanel}>
              <div style={s.panelHeader}>
                <span>evidence packet</span>
                <strong>{evidence ? 'exportable' : 'waiting'}</strong>
              </div>
              <pre style={s.jsonBox}>{evidence ? safeJson(evidence) : 'Evidence appears only after a valid receipt reaches execution.'}</pre>
              <div style={s.evidenceActions}>
                <button type="button" onClick={copyEvidence} disabled={!evidence} style={{ ...s.lightSecondaryBtn, opacity: evidence ? 1 : 0.45, cursor: evidence ? 'pointer' : 'default' }}>
                  {copied ? 'Copied' : 'Copy evidence'}
                </button>
                <button type="button" onClick={downloadEvidence} disabled={!evidence} style={{ ...s.lightSecondaryBtn, opacity: evidence ? 1 : 0.45, cursor: evidence ? 'pointer' : 'default' }}>
                  Download JSON
                </button>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
      <style>{`
        @media (max-width: 980px) {
          .rr-grid,
          .rr-stage-grid { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 640px) {
          .rr-stage-grid { padding-left: 18px !important; padding-right: 18px !important; }
        }
      `}</style>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div style={s.metric}>
      <div style={s.metricLabel}>{label}</div>
      <div style={s.metricValue}>{value}</div>
    </div>
  );
}

function StepRow({ index, step, state, busy }) {
  const status = busy ? 'running' : state.status;
  return (
    <div style={s.stepRow}>
      <div style={{ ...s.stepIndex, ...stepTone(status) }}>{String(index).padStart(2, '0')}</div>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={s.stepTitle}>{step.label}</div>
        <div style={s.stepDetail}>{state.detail}</div>
      </div>
      <div style={{ ...s.stepStatus, ...stepTone(status) }}>{status}</div>
    </div>
  );
}

function stepTone(status) {
  if (status === 'pass') return { color: '#86EFAC', borderColor: 'rgba(134,239,172,0.45)', background: 'rgba(22,163,74,0.12)' };
  if (status === 'fail') return { color: '#FCA5A5', borderColor: 'rgba(252,165,165,0.45)', background: 'rgba(220,38,38,0.12)' };
  if (status === 'running') return { color: '#93C5FD', borderColor: 'rgba(147,197,253,0.45)', background: 'rgba(59,130,246,0.12)' };
  return { color: '#A8A29E', borderColor: 'rgba(168,162,158,0.25)', background: 'rgba(255,255,255,0.03)' };
}

function logColor(tone) {
  if (tone === 'ok') return '#86EFAC';
  if (tone === 'block') return '#FBBF24';
  if (tone === 'bad') return '#FCA5A5';
  if (tone === 'cmd') return '#93C5FD';
  return '#D6D3D1';
}

const s = {
  page: {
    minHeight: '100vh',
    background: color.bg,
    color: color.t1,
    fontFamily: font.sans,
  },
  stage: {
    background: '#111827',
    color: '#FAFAF9',
    borderBottom: '1px solid rgba(255,255,255,0.12)',
  },
  stageInner: {
    maxWidth: 1180,
    margin: '0 auto',
    padding: '78px 28px 54px',
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1.05fr) minmax(360px, 0.95fr)',
    gap: 32,
    alignItems: 'stretch',
  },
  heroCopy: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
  },
  eyebrow: {
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 2,
    textTransform: 'uppercase',
    color: '#FBBF24',
    marginBottom: 18,
  },
  h1: {
    fontFamily: font.sans,
    fontSize: 'clamp(42px, 6vw, 76px)',
    lineHeight: 0.95,
    letterSpacing: 0,
    margin: '0 0 22px',
    maxWidth: 720,
  },
  lead: {
    fontSize: 18,
    lineHeight: 1.65,
    color: 'rgba(250,250,249,0.76)',
    maxWidth: 680,
    margin: 0,
  },
  heroActions: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 12,
    marginTop: 30,
  },
  primaryBtn: {
    ...cta.primary,
    background: '#FAFAF9',
    color: '#111827',
    minHeight: 46,
  },
  darkSecondaryBtn: {
    ...cta.secondary,
    color: '#FAFAF9',
    border: '1px solid rgba(250,250,249,0.24)',
    minHeight: 42,
  },
  lightSecondaryBtn: {
    ...cta.secondary,
    color: color.t1,
    background: '#FFFFFF',
    border: `1px solid ${color.borderHover}`,
    minHeight: 42,
  },
  commandPanel: {
    border: '1px solid rgba(255,255,255,0.16)',
    borderRadius: radius.base,
    background: 'rgba(15,23,42,0.72)',
    padding: 22,
    minHeight: 360,
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
  },
  panelHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: 16,
    alignItems: 'center',
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: 'rgba(250,250,249,0.55)',
  },
  lightPanelHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: 16,
    alignItems: 'center',
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: color.t3,
  },
  bigMetric: {
    fontFamily: font.sans,
    fontSize: 'clamp(40px, 5vw, 68px)',
    fontWeight: 700,
    lineHeight: 1,
    letterSpacing: 0,
    marginTop: 34,
    color: '#FAFAF9',
  },
  metricGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
    gap: 10,
    marginTop: 26,
  },
  metric: {
    borderTop: '1px solid rgba(255,255,255,0.16)',
    paddingTop: 12,
    minWidth: 0,
  },
  metricLabel: {
    fontFamily: font.mono,
    fontSize: 10,
    color: 'rgba(250,250,249,0.48)',
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
  metricValue: {
    fontSize: 14,
    color: 'rgba(250,250,249,0.82)',
    marginTop: 8,
    lineHeight: 1.35,
    overflowWrap: 'anywhere',
  },
  selector: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
    gap: 8,
    marginTop: 28,
  },
  actionBtn: {
    minHeight: 46,
    borderRadius: radius.sm,
    border: '1px solid rgba(255,255,255,0.14)',
    background: 'rgba(255,255,255,0.04)',
    color: 'rgba(250,250,249,0.72)',
    fontFamily: font.mono,
    fontSize: 11,
    cursor: 'pointer',
  },
  actionBtnActive: {
    borderColor: '#FBBF24',
    color: '#FAFAF9',
    background: 'rgba(251,191,36,0.14)',
  },
  workbench: {
    maxWidth: 1180,
    margin: '0 auto',
    padding: '34px 28px 84px',
  },
  workbenchGrid: {
    display: 'grid',
    gridTemplateColumns: 'minmax(280px, 0.9fr) minmax(320px, 1.1fr)',
    gap: 18,
  },
  leftColumn: {
    display: 'grid',
    gap: 18,
    alignContent: 'start',
  },
  rail: {
    border: `1px solid ${color.border}`,
    borderRadius: radius.base,
    background: '#FFFFFF',
    overflow: 'hidden',
  },
  stepRow: {
    display: 'flex',
    gap: 14,
    alignItems: 'center',
    padding: '16px 16px',
    borderBottom: `1px solid ${color.border}`,
  },
  stepIndex: {
    width: 34,
    height: 34,
    borderRadius: radius.sm,
    border: '1px solid',
    display: 'grid',
    placeItems: 'center',
    fontFamily: font.mono,
    fontSize: 11,
    flexShrink: 0,
  },
  stepTitle: {
    fontWeight: 700,
    color: color.t1,
    fontSize: 15,
  },
  stepDetail: {
    fontSize: 13,
    color: color.t2,
    marginTop: 4,
    lineHeight: 1.35,
    overflowWrap: 'anywhere',
  },
  stepStatus: {
    minWidth: 78,
    textAlign: 'center',
    border: '1px solid',
    borderRadius: radius.sm,
    padding: '6px 8px',
    fontFamily: font.mono,
    fontSize: 10,
    textTransform: 'uppercase',
  },
  manualControls: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: 8,
  },
  toolBtn: {
    minHeight: 42,
    borderRadius: radius.sm,
    border: `1px solid ${color.borderHover}`,
    background: '#FFFFFF',
    color: color.t1,
    fontFamily: font.mono,
    fontSize: 12,
    cursor: 'pointer',
  },
  consolePanel: {
    borderRadius: radius.base,
    border: '1px solid #1F2937',
    background: '#111827',
    color: '#FAFAF9',
    padding: 18,
    minHeight: 340,
  },
  console: {
    marginTop: 18,
    display: 'grid',
    gap: 9,
    minHeight: 232,
    alignContent: 'start',
  },
  logLine: {
    display: 'grid',
    gridTemplateColumns: '72px minmax(0, 1fr)',
    gap: 10,
    fontFamily: font.mono,
    fontSize: 12,
    lineHeight: 1.45,
    overflowWrap: 'anywhere',
  },
  logAt: {
    color: 'rgba(250,250,249,0.38)',
  },
  challengeStrip: {
    borderTop: '1px solid rgba(255,255,255,0.12)',
    marginTop: 18,
    paddingTop: 14,
  },
  stripLabel: {
    fontFamily: font.mono,
    fontSize: 10,
    letterSpacing: 1,
    color: 'rgba(250,250,249,0.46)',
    textTransform: 'uppercase',
    marginBottom: 8,
  },
  stripCode: {
    display: 'block',
    fontFamily: font.mono,
    fontSize: 12,
    color: '#FBBF24',
    overflowWrap: 'anywhere',
  },
  receiptPanel: {
    borderRadius: radius.base,
    border: `1px solid ${color.border}`,
    background: '#FFFFFF',
    padding: 18,
    minHeight: 320,
  },
  evidencePanel: {
    borderRadius: radius.base,
    border: `1px solid ${color.border}`,
    background: '#FFFFFF',
    padding: 18,
    minHeight: 320,
  },
  jsonBox: {
    margin: '16px 0 0',
    padding: 16,
    minHeight: 220,
    maxHeight: 380,
    overflow: 'auto',
    borderRadius: radius.sm,
    border: `1px solid ${color.border}`,
    background: '#F5F5F4',
    color: color.t2,
    fontFamily: font.mono,
    fontSize: 11,
    lineHeight: 1.55,
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
  },
  evidenceActions: {
    display: 'flex',
    gap: 10,
    flexWrap: 'wrap',
    marginTop: 14,
  },
};
