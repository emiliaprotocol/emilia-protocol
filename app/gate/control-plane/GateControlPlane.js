'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  Activity,
  Check,
  CircleDollarSign,
  Eye,
  Network,
  RefreshCw,
  Router,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import styles from './control-plane.module.css';

function short(value, start = 15, end = 10) {
  if (typeof value !== 'string' || value.length <= start + end + 3) return value || 'not available';
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

function State({ good, children }) {
  const Icon = good ? Check : X;
  return <span className={good ? styles.good : styles.bad}><Icon size={13} aria-hidden="true" />{children}</span>;
}

export default function GateControlPlane() {
  const [mode, setMode] = useState('complete');
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('loading');
  const [error, setError] = useState('');

  const loadScenario = useCallback(async (nextMode) => {
    const response = await fetch(`/api/v1/gate/control-plane-scenario?mode=${encodeURIComponent(nextMode)}`, {
      cache: 'no-store', headers: { accept: 'application/json' },
    });
    const body = await response.json();
    if (!response.ok || body.ok !== true) throw new Error(body.error || 'control_plane_reference_failed');
    return body;
  }, []);

  const run = useCallback(async (nextMode) => {
    setStatus('loading');
    setError('');
    try {
      setData(await loadScenario(nextMode));
      setStatus('ready');
    } catch (caught) {
      setStatus('error');
      setError(caught instanceof Error ? caught.message : 'control_plane_reference_failed');
    }
  }, [loadScenario]);

  useEffect(() => {
    let active = true;
    loadScenario(mode).then((body) => {
      if (!active) return;
      setData(body);
      setStatus('ready');
    }).catch((caught) => {
      if (!active) return;
      setStatus('error');
      setError(caught instanceof Error ? caught.message : 'control_plane_reference_failed');
    });
    return () => { active = false; };
  }, [mode, loadScenario]);
  const setScenario = (nextMode) => { if (nextMode !== mode) setMode(nextMode); else run(nextMode); };
  const gated = data?.planes?.enforcement?.state === 'gated';
  const eligible = data?.planes?.control?.settlement_eligible === true;

  return (
    <main className={styles.page}>
      <header className={styles.header}>
        <div>
          <div className={styles.kicker}>EMILIA GATE / THREE-PLANE PROOF</div>
          <h1>Enforce. Witness. Settle.</h1>
          <p>A control plane that cannot confuse seeing traffic with stopping an action.</p>
        </div>
        <div className={styles.reference}><span />Reference lab · no production effect</div>
      </header>

      <section className={styles.toolbar} aria-label="Reference scenario">
        <div className={styles.segmented}>
          <button type="button" className={mode === 'complete' ? styles.active : ''} onClick={() => setScenario('complete')}>
            <ShieldCheck size={16} aria-hidden="true" />Complete view
          </button>
          <button type="button" className={mode === 'witness_only' ? styles.active : ''} onClick={() => setScenario('witness_only')}>
            <ShieldAlert size={16} aria-hidden="true" />Remove the Gate
          </button>
        </div>
        <button type="button" className={styles.refresh} onClick={() => run(mode)} disabled={status === 'loading'} title="Run a new reference transaction">
          <RefreshCw size={16} aria-hidden="true" className={status === 'loading' ? styles.spin : undefined} />
          Run again
        </button>
      </section>

      {status === 'error' ? <div className={styles.error} role="alert">Reference run failed: {error}</div> : null}

      <section className={styles.actionBand} aria-live="polite">
        <div>
          <span>Protected consequence</span>
          <h2>Grid curtailment · {data?.action?.target_kw?.toLocaleString() || '...'} kW</h2>
          <p>{data?.action?.site_id || 'loading'} · {data?.action?.duration_seconds || '...'} seconds</p>
        </div>
        <dl>
          <div><dt>Action digest</dt><dd>{short(data?.action_digest)}</dd></div>
          <div><dt>Coverage</dt><dd>{data?.planes?.enforcement?.state || 'loading'}</dd></div>
          <div><dt>Settlement</dt><dd>{data?.planes?.control?.settlement_verdict || 'loading'}</dd></div>
        </dl>
        <State good={eligible}>{eligible ? 'Evidence complete' : 'Settlement refused'}</State>
      </section>

      <section className={styles.planes}>
        <article className={styles.plane}>
          <div className={styles.planeHead}><Router size={20} aria-hidden="true" /><span>01</span></div>
          <p className={styles.eyebrow}>ENFORCEMENT PLANE</p>
          <h2>Executor-side Gate</h2>
          <p className={styles.summary}>The only plane allowed to call the actuator. Missing proof is refused before mutation.</p>
          <dl className={styles.facts}>
            <div><dt>State</dt><dd><State good={gated}>{data?.planes?.enforcement?.state || 'checking'}</State></dd></div>
            <div><dt>Workload</dt><dd>{data?.planes?.enforcement?.deployment_attested ? 'attested' : 'not proven'}</dd></div>
            <div><dt>Canary</dt><dd>{data?.planes?.enforcement?.refusal_probe_verified ? '428 verified' : 'not verified'}</dd></div>
            <div><dt>Bypass</dt><dd>{data?.planes?.enforcement?.bypass_probe_verified ? 'found' : 'none observed'}</dd></div>
          </dl>
        </article>

        <article className={styles.plane}>
          <div className={styles.planeHead}><Network size={20} aria-hidden="true" /><span>02</span></div>
          <p className={styles.eyebrow}>WITNESS PLANE</p>
          <h2>Independent observation</h2>
          <p className={styles.summary}>A pinned TAP or observer signs what it saw. Visibility remains evidence, never authorization.</p>
          <dl className={styles.facts}>
            <div><dt>Signature</dt><dd>{data?.planes?.witness?.verified ? 'verified' : 'absent'}</dd></div>
            <div><dt>Capture point</dt><dd>{data?.planes?.witness?.capture_point_id || 'checking'}</dd></div>
            <div><dt>Sequence</dt><dd>{data?.planes?.witness?.sequence || 'checking'}</dd></div>
            <div><dt>Payload</dt><dd>{data?.planes?.witness?.payload_captured === false ? 'not captured' : 'unknown'}</dd></div>
          </dl>
        </article>

        <article className={styles.plane}>
          <div className={styles.planeHead}><Activity size={20} aria-hidden="true" /><span>03</span></div>
          <p className={styles.eyebrow}>CONTROL PLANE</p>
          <h2>Coverage and reliance</h2>
          <p className={styles.summary}>Pinned policy composes proof rows and refuses incomplete settlement. No hidden trust score.</p>
          <dl className={styles.facts}>
            <div><dt>Inventory</dt><dd>{data?.planes?.control?.coverage_bps ?? 0} bps covered</dd></div>
            <div><dt>Settlement</dt><dd><State good={eligible}>{data?.planes?.control?.settlement_verdict || 'checking'}</State></dd></div>
            <div><dt>Metering</dt><dd>{data?.planes?.control?.protected_actions ?? 0} protected action</dd></div>
            <div><dt>Usage record</dt><dd>{data?.planes?.control?.usage_complete ? 'complete' : 'refused'}</dd></div>
          </dl>
        </article>
      </section>

      <section className={styles.resultBand}>
        <div className={styles.resultIcon}>{gated ? <CircleDollarSign size={22} aria-hidden="true" /> : <Eye size={22} aria-hidden="true" />}</div>
        <div>
          <span>{gated ? 'COMPLETE THREE-PLANE VIEW' : 'THE HONEST NEGATIVE'}</span>
          <h2>{gated ? 'The evidence profile is complete enough to settle.' : 'Traffic was observed. Enforcement was not proven.'}</h2>
          <p>{gated
            ? 'Attestation, active refusal, independent observation, execution, and measured outcome join on the same action digest.'
            : 'The witness is healthy, but a passive observer cannot block the actuator. Coverage becomes witness_only and settlement fails closed.'}</p>
        </div>
      </section>

      <section className={styles.hashes}>
        <div className={styles.sectionHead}><div><span>REPRODUCIBLE ARTIFACTS</span><h2>Every decision has a digest.</h2></div><p>These are outputs from the running reference kernels, not hand-authored status labels.</p></div>
        <dl>
          {Object.entries(data?.hashes || {}).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value || 'not produced'}</dd></div>)}
        </dl>
      </section>
    </main>
  );
}
