'use client';

// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color, cta, font, radius } from '@/lib/tokens';
import { postReceiptRequiredDemo as postDemo } from './post-demo';

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

const ACTION_COPY = {
  release_funds: {
    headline: 'Move $250,000',
    target: 'ACME vendor wire',
    command: 'release pending vendor payment now',
    consequence: 'Funds leave treasury',
    blast: '$250,000 at risk',
  },
  delete_repo: {
    headline: 'Delete prod-ledger',
    target: 'emilia/prod-ledger',
    command: 'delete repository to remove leaked data',
    consequence: 'Production code state destroyed',
    blast: 'repo deletion',
  },
  change_bank_account: {
    headline: 'Change bank routing',
    target: 'ACME payout destination',
    command: 'update vendor payment routing',
    consequence: 'Future payments redirect',
    blast: 'bank detail change',
  },
};

const STRIKES = [
  { id: 'missing', title: 'No receipt reaches the gate', short: 'will be blocked' },
  { id: 'sign', title: 'Human signs exact action', short: 'receipt will bind action' },
  { id: 'run', title: 'Receipt reaches actuator', short: 'allowed once' },
  { id: 'replay', title: 'Same receipt replayed', short: 'will be blocked' },
  { id: 'forge', title: 'Signed action rewritten', short: 'will be rejected' },
  { id: 'evidence', title: 'Evidence packet exported', short: 'auditable proof' },
];

const ATTACK_PATH = [
  ['1', 'No receipt', 'BLOCKED'],
  ['2', 'Exact receipt', 'RUNS ONCE'],
  ['3', 'Replay', 'BLOCKED'],
  ['4', 'Forgery', 'REJECTED'],
];

const initialStrikes = () =>
  Object.fromEntries(STRIKES.map((s) => [s.id, { status: 'idle', detail: s.short }]));

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const now = () => new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

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

function sceneFrom(strikes, busy, evidence) {
  if (busy === 'missing') return { label: 'ATTACK INBOUND', tone: 'warn', sub: 'No receipt attached' };
  if (busy === 'sign') return { label: 'HUMAN AUTHORIZING', tone: 'blue', sub: 'Exact action is being signed' };
  if (busy === 'run') return { label: 'GATE VERIFYING', tone: 'blue', sub: 'Receipt is checked offline' };
  if (busy === 'replay') return { label: 'REPLAY ATTEMPT', tone: 'warn', sub: 'Same receipt tries to run twice' };
  if (busy === 'forge') return { label: 'FORGERY ATTEMPT', tone: 'danger', sub: 'Signed payload was rewritten' };
  if (strikes.forge.status === 'rejected') return { label: 'FORGERY REJECTED', tone: 'danger', sub: 'Signature no longer verifies' };
  if (strikes.replay.status === 'blocked') return { label: 'REPLAY BLOCKED', tone: 'warn', sub: 'Receipt consumed once' };
  if (evidence) return { label: 'EXECUTED WITH PROOF', tone: 'safe', sub: 'Evidence packet exported' };
  if (strikes.run.status === 'allowed') return { label: 'EXECUTED ONCE', tone: 'safe', sub: 'Receipt reached the actuator' };
  if (strikes.sign.status === 'signed') return { label: 'RECEIPT READY', tone: 'blue', sub: 'Bound to the exact action' };
  if (strikes.missing.status === 'blocked') return { label: '428 RECEIPT REQUIRED', tone: 'warn', sub: 'Mutation never reached the system' };
  return { label: 'ACTUATOR LOCKED', tone: 'idle', sub: 'No receipt, no execution' };
}

/**
 * @typedef {{
 *   payload: {
 *     receipt_id: string,
 *     claim: { action_type: string, [key: string]: any },
 *     [key: string]: any,
 *   },
 *   [key: string]: any,
 * }} DemoReceipt
 */
/** @typedef {{ receipt_id: string, [key: string]: any }} DemoEvidence */
/** @typedef {{ required?: { action?: string, [key: string]: any }, [key: string]: any }} DemoChallenge */

export default function ReceiptRequiredTryPage() {
  const [actions, setActions] = useState(FALLBACK_ACTIONS);
  const [selectedId, setSelectedId] = useState('release_funds');
  const [strikes, setStrikes] = useState(initialStrikes);
  const [busy, setBusy] = useState(/** @type {'missing'|'sign'|'run'|'replay'|'forge'|null} */ (null));
  const [receipt, setReceipt] = useState(/** @type {DemoReceipt|null} */ (null));
  const [evidence, setEvidence] = useState(/** @type {DemoEvidence|null} */ (null));
  const [challenge, setChallenge] = useState(/** @type {DemoChallenge|null} */ (null));
  const [copied, setCopied] = useState(false);
  const [feed, setFeed] = useState([
    { at: now(), kind: 'idle', text: 'actuator armed; waiting for agent command' },
  ]);

  const selected = useMemo(
    () => actions.find((a) => a.id === selectedId) || actions[0] || FALLBACK_ACTIONS[0],
    [actions, selectedId],
  );
  const copy = ACTION_COPY[selected.id] || ACTION_COPY.release_funds;
  const scene = sceneFrom(strikes, busy, evidence);

  useEffect(() => {
    fetch('/api/demo/require-receipt')
      .then((r) => r.json())
      .then((body) => {
        if (Array.isArray(body.actions) && body.actions.length) setActions(body.actions);
      })
      .catch(() => {});
  }, []);

  function write(kind, text) {
    setFeed((old) => [...old.slice(-12), { at: now(), kind, text }]);
  }

  function mark(id, status, detail) {
    setStrikes((old) => ({ ...old, [id]: { status, detail } }));
  }

  function reset(nextId = selectedId) {
    setSelectedId(nextId);
    setStrikes(initialStrikes());
    setBusy(null);
    setReceipt(null);
    setEvidence(null);
    setChallenge(null);
    setCopied(false);
    setFeed([{ at: now(), kind: 'idle', text: `actuator reset; selected=${nextId}` }]);
  }

  async function fireMissing(action = selected) {
    setBusy('missing');
    mark('missing', 'running', 'agent is trying to cross the boundary');
    write('cmd', `agent.command("${copy.command}")`);
    const out = await postDemo({ demo: action.id });
    setChallenge(out.data);
    if (out.status === 428) {
      mark('missing', 'blocked', '428 before the write');
      write('block', `gate.response=${out.status} ${out.data.title}`);
    } else {
      mark('missing', 'fail', `unexpected ${out.status}`);
      write('bad', `unexpected status=${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function signExact(action = selected) {
    setBusy('sign');
    mark('sign', 'running', 'signing the canonical action digest');
    write('cmd', `human.sign("${action.action}")`);
    const out = await postDemo({
      demo: action.id,
      sign_demo_receipt: true,
      approver: 'ep:approver:demo-human',
    });
    if (out.status === 200 && out.data?.receipt) {
      setReceipt(out.data.receipt);
      mark('sign', 'signed', out.data.signed.receipt_id);
      write('ok', `receipt.bound=${out.data.signed.action}`);
      setBusy(null);
      return out.data.receipt;
    }
    mark('sign', 'fail', `unexpected ${out.status}`);
    write('bad', `signer.status=${out.status}`);
    setBusy(null);
    return null;
  }

  async function runWithReceipt(doc = receipt, action = selected) {
    if (!doc) return null;
    setBusy('run');
    mark('run', 'running', 'gate verifies and reserves receipt');
    write('cmd', `agent.retry(receipt=${doc.payload.receipt_id})`);
    const out = await postDemo({ demo: action.id, emilia_receipt: doc });
    if (out.status === 200) {
      setEvidence(out.data.evidence_packet);
      mark('run', 'allowed', 'mutated exactly once');
      mark('evidence', 'exported', out.data.evidence_packet.policy_id);
      write('ok', `actuator.execute("${action.id}")`);
      write('ok', `evidence.export=${out.data.evidence_packet.receipt_id}`);
    } else {
      mark('run', 'fail', `unexpected ${out.status}`);
      write('bad', `executor.status=${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function replay(doc = receipt, action = selected) {
    if (!doc) return null;
    setBusy('replay');
    mark('replay', 'running', 'attacker reuses consumed receipt');
    write('cmd', `attacker.replay(${doc.payload.receipt_id})`);
    const out = await postDemo({ demo: action.id, emilia_receipt: doc });
    if (out.status === 428 && out.data?.rejected?.reason === 'replay_refused') {
      mark('replay', 'blocked', 'same receipt cannot authorize twice');
      write('block', 'gate.reject("replay_refused")');
    } else {
      mark('replay', 'fail', `unexpected ${out.status}`);
      write('bad', `replay.status=${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function forge(doc = receipt, action = selected) {
    if (!doc) return null;
    setBusy('forge');
    mark('forge', 'running', 'payload is changed after signing');
    const forged = tamperReceipt(doc);
    write('cmd', `attacker.patch(action="${forged.payload.claim.action_type}")`);
    const out = await postDemo({ demo: action.id, emilia_receipt: forged });
    if (out.status === 428 && out.data?.rejected?.reason === 'untrusted_or_invalid_signature') {
      mark('forge', 'rejected', 'canonical bytes no longer verify');
      write('block', 'gate.reject("untrusted_or_invalid_signature")');
    } else {
      mark('forge', 'fail', `unexpected ${out.status}`);
      write('bad', `forge.status=${out.status}`);
    }
    setBusy(null);
    return out;
  }

  async function runSequence() {
    reset(selected.id);
    const action = selected;
    await pause(100);
    await fireMissing(action);
    await pause(380);
    const doc = await signExact(action);
    if (!doc) return;
    await pause(380);
    await runWithReceipt(doc, action);
    await pause(380);
    await replay(doc, action);
    await pause(380);
    await forge(doc, action);
  }

  async function copyEvidence() {
    if (!evidence) return;
    await navigator.clipboard?.writeText(safeJson(evidence));
    setCopied(true);
    setTimeout(() => setCopied(false), 1100);
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
      <main style={s.main}>
        <section style={s.hero}>
          <div style={s.heroInner} className="rr-hero">
            <div style={s.leftIntro}>
              <div style={s.eyebrow}>LIVE ATTACK SIMULATOR</div>
              <h1 style={s.h1}>Break the action layer.</h1>
              <p style={s.lead}>
                One run shows the invariant: no receipt is blocked, an exact receipt runs once,
                replay is blocked, and a forged receipt is rejected. The page calls the real
                Receipt Required API.
              </p>
              <div style={s.heroButtons}>
                <button type="button" onClick={runSequence} disabled={Boolean(busy)} style={s.primaryBtn}>
                  {busy ? 'Attack running...' : 'Launch attack sequence'}
                </button>
                <button type="button" onClick={() => reset()} disabled={Boolean(busy)} style={s.darkBtn}>
                  Reset bay
                </button>
              </div>
              <div style={s.attackPath} className="rr-attack-path">
                {ATTACK_PATH.map(([n, label, result]) => (
                  <div key={label} style={s.attackPathItem}>
                    <span style={s.attackPathNum}>{n}</span>
                    <strong style={s.attackPathLabel}>{label}</strong>
                    <em style={s.attackPathResult}>{result}</em>
                  </div>
                ))}
              </div>
            </div>

            <div style={s.selectorCard}>
              <div style={s.selectorLabel}>choose the blast radius</div>
              <div style={s.actionTabs}>
                {actions.map((action) => (
                  <button
                    key={action.id}
                    type="button"
                    onClick={() => reset(action.id)}
                    disabled={Boolean(busy)}
                    style={{
                      ...s.actionTab,
                      ...(selected.id === action.id ? s.actionTabActive : null),
                    }}
                  >
                    <span>{action.label}</span>
                    <small>{action.assurance_class}</small>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section style={s.bay}>
          <div style={s.sceneHeader}>
            <div>
              <div style={s.sceneKicker}>ACTUATOR BAY</div>
              <h2 style={s.sceneTitle}>{scene.label}</h2>
              <p style={s.sceneSub}>{scene.sub}</p>
            </div>
            <div style={{ ...s.sceneBadge, ...tone(scene.tone) }}>{selected.action_type}</div>
          </div>

          <div style={s.arena} className="rr-arena">
            <motion.div layout style={s.agentPane}>
              <PanelTop label="agent intent" value={copy.blast} />
              <div style={s.terminal}>
                <Line muted>$ autonomous-agent</Line>
                <Line>intent: {selected.action_type}</Line>
                <Line>target: {copy.target}</Line>
                <Line>command: {copy.command}</Line>
                <Line danger>receipt: null</Line>
              </div>
              <div style={s.consequence}>
                <span>Consequence</span>
                <strong>{copy.consequence}</strong>
              </div>
            </motion.div>

            <motion.div layout style={{ ...s.gatePane, ...gateShadow(scene.tone) }}>
              <PanelTop label="emilia gate" value="fail closed" />
              <div style={s.gateCore}>
                <motion.div
                  animate={{ rotate: busy ? 360 : 0 }}
                  transition={{ duration: 1.8, repeat: busy ? Infinity : 0, ease: 'linear' }}
                  style={{ ...s.outerRing, ...ringTone(scene.tone) }}
                />
                <div style={s.innerLock}>
                  <div style={s.lockBar} />
                  <div style={s.lockBody}>{scene.tone === 'safe' ? 'RUN' : 'LOCK'}</div>
                </div>
              </div>
              <div style={s.gateReadout}>
                <span>{challenge?.required?.action || selected.action}</span>
              </div>
            </motion.div>

            <motion.div layout style={s.systemPane}>
              <PanelTop label="system of record" value={evidence ? 'mutated once' : 'protected'} />
              <div style={s.amount}>{copy.headline}</div>
              <div style={s.systemGrid}>
                <Fact label="Policy" value={selected.policy_id} />
                <Fact label="Target" value={selected.target} />
                <Fact label="Assurance" value={selected.assurance_class} />
              </div>
              <div style={{ ...s.actuatorStatus, ...tone(evidence ? 'safe' : strikes.missing.status === 'blocked' ? 'warn' : 'idle') }}>
                {evidence
                  ? strikes.forge.status === 'rejected'
                    ? 'EXECUTED ONCE; ATTACKS REFUSED'
                    : 'EXECUTED WITH RECEIPT'
                  : strikes.missing.status === 'blocked' ? 'MUTATION BLOCKED' : 'WAITING'}
              </div>
            </motion.div>
          </div>

          <div style={s.controls} className="rr-controls">
            <button type="button" onClick={() => fireMissing()} disabled={Boolean(busy)} style={s.controlBtn}>No receipt</button>
            <button type="button" onClick={() => signExact()} disabled={Boolean(busy)} style={s.controlBtn}>Sign exact</button>
            <button type="button" onClick={() => runWithReceipt()} disabled={Boolean(busy) || !receipt} style={s.controlBtn}>Run once</button>
            <button type="button" onClick={() => replay()} disabled={Boolean(busy) || !receipt} style={s.controlBtn}>Replay</button>
            <button type="button" onClick={() => forge()} disabled={Boolean(busy) || !receipt} style={s.controlBtn}>Forge</button>
          </div>
        </section>

        <section style={s.after}>
          <div style={s.afterGrid} className="rr-after">
            <div style={s.attackRail}>
              <div style={s.sectionLabel}>attack chain</div>
              {STRIKES.map((strike, index) => (
                <Strike key={strike.id} strike={strike} state={strikes[strike.id]} index={index + 1} active={busy === strike.id} />
              ))}
            </div>

            <div style={s.feedPanel}>
              <div style={s.sectionLabel}>live trace</div>
              <div style={s.feedBox}>
                {feed.map((item, index) => (
                  <motion.div
                    key={`${item.at}-${index}-${item.text}`}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    style={{ ...s.feedLine, color: feedColor(item.kind) }}
                  >
                    <span>{item.at}</span>
                    <code>{item.text}</code>
                  </motion.div>
                ))}
              </div>
            </div>

            <div style={s.evidenceVault}>
              <div style={s.vaultTop}>
                <div>
                  <div style={s.sectionLabel}>black-box evidence</div>
                  <h3 style={s.vaultTitle}>{evidence ? 'Packet exported' : 'Waiting for a valid run'}</h3>
                </div>
                <div style={{ ...s.vaultSeal, ...tone(evidence ? 'safe' : 'idle') }}>
                  {evidence ? 'VERIFY OFFLINE' : 'SEALED'}
                </div>
              </div>
              <pre style={s.json}>{evidence ? safeJson(evidence) : 'A valid receipt creates a packet here. Replay and forgery never do.'}</pre>
              <div style={s.vaultButtons}>
                <button type="button" onClick={copyEvidence} disabled={!evidence} style={{ ...s.lightBtn, opacity: evidence ? 1 : 0.45 }}>
                  {copied ? 'Copied' : 'Copy packet'}
                </button>
                <button type="button" onClick={downloadEvidence} disabled={!evidence} style={{ ...s.lightBtn, opacity: evidence ? 1 : 0.45 }}>
                  Download JSON
                </button>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
      <style>{`
        @media (max-width: 1050px) {
          .rr-hero,
          .rr-arena,
          .rr-after { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 640px) {
          .rr-arena,
          .rr-after { gap: 12px !important; }
          .rr-hero { padding: 52px 20px 26px !important; }
          .rr-controls { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
          .rr-attack-path { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
        }
      `}</style>
    </div>
  );
}

function PanelTop({ label, value }) {
  return (
    <div style={s.panelTop}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

/** @param {{ children: any, muted?: boolean, danger?: boolean }} props */
function Line({ children, muted, danger }) {
  return (
    <div style={{ color: danger ? '#FCA5A5' : muted ? 'rgba(245,245,244,0.42)' : '#E7E5E4' }}>
      {children}
    </div>
  );
}

function Fact({ label, value }) {
  return (
    <div style={s.fact}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Strike({ strike, state, index, active }) {
  const status = active ? 'running' : state.status;
  return (
    <div style={{ ...s.strike, ...strikeTone(status) }}>
      <div style={s.strikeNum}>{String(index).padStart(2, '0')}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={s.strikeTitle}>{strike.title}</div>
        <div style={s.strikeDetail}>{state.detail}</div>
      </div>
      <div style={s.strikeStatus}>{status}</div>
    </div>
  );
}

/** @returns {import('react').CSSProperties} */
function tone(kind) {
  if (kind === 'safe') return { color: '#14532D', borderColor: '#86EFAC', background: '#DCFCE7' };
  if (kind === 'danger') return { color: '#7F1D1D', borderColor: '#FCA5A5', background: '#FEE2E2' };
  if (kind === 'warn') return { color: '#713F12', borderColor: '#FBBF24', background: '#FEF3C7' };
  if (kind === 'blue') return { color: '#1E3A8A', borderColor: '#93C5FD', background: '#DBEAFE' };
  return { color: '#44403C', borderColor: color.borderHover, background: '#F5F5F4' };
}

/** @returns {import('react').CSSProperties} */
function gateShadow(kind) {
  if (kind === 'safe') return { boxShadow: '0 0 0 1px rgba(134,239,172,0.28), 0 30px 80px rgba(22,163,74,0.22)' };
  if (kind === 'danger') return { boxShadow: '0 0 0 1px rgba(252,165,165,0.32), 0 30px 80px rgba(220,38,38,0.22)' };
  if (kind === 'warn') return { boxShadow: '0 0 0 1px rgba(251,191,36,0.32), 0 30px 80px rgba(180,83,9,0.22)' };
  return { boxShadow: '0 24px 70px rgba(0,0,0,0.28)' };
}

/** @returns {import('react').CSSProperties} */
function ringTone(kind) {
  if (kind === 'safe') return { borderColor: '#86EFAC', borderTopColor: '#16A34A' };
  if (kind === 'danger') return { borderColor: '#FCA5A5', borderTopColor: '#DC2626' };
  if (kind === 'warn') return { borderColor: '#FBBF24', borderTopColor: '#B08D35' };
  if (kind === 'blue') return { borderColor: '#93C5FD', borderTopColor: '#3B82F6' };
  return { borderColor: '#78716C', borderTopColor: '#E7E5E4' };
}

/** @returns {import('react').CSSProperties} */
function strikeTone(status) {
  if (status === 'allowed' || status === 'exported') return { borderColor: '#86EFAC', background: '#F0FDF4' };
  if (status === 'signed') return { borderColor: '#93C5FD', background: '#EFF6FF' };
  if (status === 'blocked') return { borderColor: '#FBBF24', background: '#FFFBEB' };
  if (status === 'rejected') return { borderColor: '#FCA5A5', background: '#FEF2F2' };
  if (status === 'fail') return { borderColor: '#FCA5A5', background: '#FEF2F2' };
  if (status === 'running') return { borderColor: '#93C5FD', background: '#EFF6FF' };
  return { borderColor: color.border, background: '#FFFFFF' };
}

function feedColor(kind) {
  if (kind === 'ok') return '#86EFAC';
  if (kind === 'block') return '#FBBF24';
  if (kind === 'bad') return '#FCA5A5';
  if (kind === 'cmd') return '#93C5FD';
  return '#D6D3D1';
}

/** @type {Record<string, import('react').CSSProperties>} */
const s = {
  page: {
    minHeight: '100vh',
    background: '#F7F5F0',
    color: color.t1,
    fontFamily: font.sans,
  },
  main: {
    background: '#F7F5F0',
  },
  hero: {
    background: '#171412',
    color: '#FAFAF9',
    borderBottom: '1px solid rgba(255,255,255,0.12)',
  },
  heroInner: {
    maxWidth: 1220,
    margin: '0 auto',
    padding: '72px 28px 30px',
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1fr) minmax(320px, 420px)',
    gap: 28,
    alignItems: 'end',
  },
  leftIntro: {
    maxWidth: 780,
  },
  eyebrow: {
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 2.4,
    textTransform: 'uppercase',
    color: color.gold,
    marginBottom: 16,
  },
  h1: {
    margin: 0,
    fontSize: 'clamp(52px, 8vw, 104px)',
    lineHeight: 0.88,
    letterSpacing: 0,
    maxWidth: 760,
  },
  lead: {
    margin: '24px 0 0',
    maxWidth: 720,
    fontSize: 18,
    lineHeight: 1.62,
    color: 'rgba(250,250,249,0.74)',
  },
  heroButtons: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 12,
    marginTop: 28,
  },
  attackPath: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
    gap: 8,
    marginTop: 18,
    maxWidth: 720,
  },
  attackPathItem: {
    border: '1px solid rgba(250,250,249,0.16)',
    borderRadius: radius.sm,
    padding: '10px 11px',
    minHeight: 72,
    display: 'grid',
    alignContent: 'space-between',
    background: 'rgba(250,250,249,0.045)',
    fontFamily: font.mono,
  },
  attackPathNum: {
    fontSize: 10,
    color: 'rgba(250,250,249,0.46)',
  },
  attackPathLabel: {
    fontSize: 12,
    color: '#FAFAF9',
  },
  attackPathResult: {
    fontStyle: 'normal',
    fontSize: 10,
    color: color.gold,
    letterSpacing: 1,
  },
  primaryBtn: {
    ...cta.primary,
    minHeight: 48,
    background: '#FAFAF9',
    color: '#171412',
  },
  darkBtn: {
    ...cta.secondary,
    minHeight: 48,
    color: '#FAFAF9',
    border: '1px solid rgba(250,250,249,0.24)',
  },
  selectorCard: {
    border: '1px solid rgba(250,250,249,0.16)',
    borderRadius: radius.base,
    background: 'rgba(250,250,249,0.06)',
    padding: 16,
  },
  selectorLabel: {
    fontFamily: font.mono,
    fontSize: 10,
    color: 'rgba(250,250,249,0.5)',
    letterSpacing: 1.5,
    textTransform: 'uppercase',
    marginBottom: 12,
  },
  actionTabs: {
    display: 'grid',
    gap: 8,
  },
  actionTab: {
    minHeight: 54,
    borderRadius: radius.sm,
    border: '1px solid rgba(250,250,249,0.14)',
    background: 'rgba(250,250,249,0.04)',
    color: '#FAFAF9',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
    padding: '0 14px',
    fontFamily: font.mono,
    fontSize: 12,
    cursor: 'pointer',
  },
  actionTabActive: {
    background: 'rgba(176,141,53,0.18)',
    borderColor: color.gold,
  },
  bay: {
    background: '#171412',
    color: '#FAFAF9',
    padding: '28px 28px 44px',
  },
  sceneHeader: {
    maxWidth: 1220,
    margin: '0 auto 18px',
    display: 'flex',
    alignItems: 'end',
    justifyContent: 'space-between',
    gap: 20,
    flexWrap: 'wrap',
  },
  sceneKicker: {
    fontFamily: font.mono,
    fontSize: 10,
    letterSpacing: 1.7,
    textTransform: 'uppercase',
    color: 'rgba(250,250,249,0.48)',
  },
  sceneTitle: {
    margin: '6px 0 0',
    fontSize: 'clamp(28px, 4vw, 48px)',
    letterSpacing: 0,
    lineHeight: 1,
  },
  sceneSub: {
    margin: '8px 0 0',
    color: 'rgba(250,250,249,0.62)',
  },
  sceneBadge: {
    border: '1px solid',
    borderRadius: radius.sm,
    padding: '10px 12px',
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 0.6,
    textTransform: 'uppercase',
  },
  arena: {
    maxWidth: 1220,
    margin: '0 auto',
    display: 'grid',
    gridTemplateColumns: 'minmax(260px, 0.95fr) minmax(270px, 0.9fr) minmax(300px, 1fr)',
    gap: 16,
    alignItems: 'stretch',
  },
  agentPane: {
    borderRadius: radius.base,
    border: '1px solid rgba(250,250,249,0.14)',
    background: '#211D1A',
    padding: 18,
    minHeight: 390,
  },
  gatePane: {
    borderRadius: radius.base,
    border: '1px solid rgba(250,250,249,0.16)',
    background: '#0F0D0B',
    padding: 18,
    minHeight: 390,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'stretch',
  },
  systemPane: {
    borderRadius: radius.base,
    border: '1px solid rgba(250,250,249,0.14)',
    background: '#FAFAF9',
    color: color.t1,
    padding: 18,
    minHeight: 390,
  },
  panelTop: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: 12,
    alignItems: 'center',
    fontFamily: font.mono,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
    color: 'rgba(250,250,249,0.5)',
  },
  terminal: {
    marginTop: 28,
    borderRadius: radius.sm,
    border: '1px solid rgba(250,250,249,0.12)',
    background: '#0B0A09',
    padding: 18,
    fontFamily: font.mono,
    fontSize: 12,
    lineHeight: 1.9,
    minHeight: 168,
  },
  consequence: {
    borderTop: '1px solid rgba(250,250,249,0.14)',
    marginTop: 28,
    paddingTop: 18,
    display: 'grid',
    gap: 8,
  },
  gateCore: {
    position: 'relative',
    width: 190,
    height: 190,
    margin: '46px auto 28px',
    display: 'grid',
    placeItems: 'center',
  },
  outerRing: {
    position: 'absolute',
    inset: 0,
    borderRadius: '50%',
    border: '10px solid',
    borderTopColor: color.gold,
  },
  innerLock: {
    position: 'relative',
    width: 100,
    height: 118,
    display: 'grid',
    justifyItems: 'center',
    alignContent: 'end',
  },
  lockBar: {
    width: 58,
    height: 42,
    border: '8px solid #FAFAF9',
    borderBottom: 0,
    borderRadius: '32px 32px 0 0',
  },
  lockBody: {
    width: 100,
    height: 72,
    borderRadius: radius.base,
    background: '#FAFAF9',
    color: '#171412',
    display: 'grid',
    placeItems: 'center',
    fontFamily: font.mono,
    fontWeight: 700,
    letterSpacing: 1,
  },
  gateReadout: {
    borderTop: '1px solid rgba(250,250,249,0.12)',
    paddingTop: 14,
    fontFamily: font.mono,
    fontSize: 11,
    color: color.gold,
    lineHeight: 1.55,
    overflowWrap: 'anywhere',
  },
  amount: {
    marginTop: 38,
    fontSize: 'clamp(42px, 5vw, 70px)',
    fontWeight: 700,
    letterSpacing: 0,
    lineHeight: 1,
  },
  systemGrid: {
    display: 'grid',
    gap: 12,
    marginTop: 34,
  },
  fact: {
    borderTop: `1px solid ${color.border}`,
    paddingTop: 12,
    display: 'grid',
    gap: 5,
  },
  actuatorStatus: {
    marginTop: 28,
    border: '1px solid',
    borderRadius: radius.sm,
    minHeight: 48,
    display: 'grid',
    placeItems: 'center',
    fontFamily: font.mono,
    fontWeight: 700,
    fontSize: 12,
    letterSpacing: 1,
  },
  controls: {
    maxWidth: 1220,
    margin: '16px auto 0',
    display: 'grid',
    gridTemplateColumns: 'repeat(5, minmax(0, 1fr))',
    gap: 8,
  },
  controlBtn: {
    minHeight: 44,
    borderRadius: radius.sm,
    border: '1px solid rgba(250,250,249,0.16)',
    background: 'rgba(250,250,249,0.07)',
    color: '#FAFAF9',
    fontFamily: font.mono,
    fontSize: 12,
    cursor: 'pointer',
  },
  after: {
    maxWidth: 1220,
    margin: '0 auto',
    padding: '30px 28px 88px',
  },
  afterGrid: {
    display: 'grid',
    gridTemplateColumns: 'minmax(280px, 0.82fr) minmax(320px, 1fr) minmax(320px, 1fr)',
    gap: 16,
    alignItems: 'start',
  },
  attackRail: {
    display: 'grid',
    gap: 10,
  },
  sectionLabel: {
    fontFamily: font.mono,
    fontSize: 10,
    letterSpacing: 1.7,
    textTransform: 'uppercase',
    color: color.t3,
    marginBottom: 2,
  },
  strike: {
    border: '1px solid',
    borderRadius: radius.base,
    padding: 13,
    display: 'flex',
    gap: 12,
    alignItems: 'center',
  },
  strikeNum: {
    width: 32,
    height: 32,
    borderRadius: radius.sm,
    display: 'grid',
    placeItems: 'center',
    background: '#171412',
    color: '#FAFAF9',
    fontFamily: font.mono,
    fontSize: 11,
    flexShrink: 0,
  },
  strikeTitle: {
    fontWeight: 700,
    fontSize: 14,
  },
  strikeDetail: {
    marginTop: 3,
    fontSize: 12,
    color: color.t2,
    overflowWrap: 'anywhere',
  },
  strikeStatus: {
    fontFamily: font.mono,
    fontSize: 10,
    color: color.t3,
    textTransform: 'uppercase',
  },
  feedPanel: {
    borderRadius: radius.base,
    border: `1px solid ${color.border}`,
    background: '#171412',
    padding: 18,
    minHeight: 470,
  },
  feedBox: {
    marginTop: 14,
    display: 'grid',
    gap: 9,
  },
  feedLine: {
    display: 'grid',
    gridTemplateColumns: '66px minmax(0, 1fr)',
    gap: 10,
    fontFamily: font.mono,
    fontSize: 12,
    lineHeight: 1.45,
  },
  evidenceVault: {
    borderRadius: radius.base,
    border: `1px solid ${color.border}`,
    background: '#FFFFFF',
    padding: 18,
    minHeight: 470,
  },
  vaultTop: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: 16,
    alignItems: 'start',
  },
  vaultTitle: {
    margin: '4px 0 0',
    fontSize: 22,
  },
  vaultSeal: {
    border: '1px solid',
    borderRadius: radius.sm,
    padding: '8px 10px',
    fontFamily: font.mono,
    fontSize: 10,
    whiteSpace: 'nowrap',
  },
  json: {
    margin: '18px 0 0',
    border: `1px solid ${color.border}`,
    borderRadius: radius.sm,
    background: '#F5F5F4',
    minHeight: 310,
    maxHeight: 390,
    overflow: 'auto',
    padding: 15,
    fontFamily: font.mono,
    fontSize: 11,
    lineHeight: 1.55,
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
    color: color.t2,
  },
  vaultButtons: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 10,
    marginTop: 14,
  },
  lightBtn: {
    ...cta.secondary,
    background: '#FFFFFF',
    color: color.t1,
    border: `1px solid ${color.borderHover}`,
  },
};
