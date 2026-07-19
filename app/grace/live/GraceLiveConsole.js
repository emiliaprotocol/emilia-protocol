'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  AlertTriangle,
  BadgeDollarSign,
  CheckCircle2,
  FileCheck2,
  Gauge,
  Radio,
  RefreshCw,
  Send,
  ShieldCheck,
  Smartphone,
  XCircle,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import styles from './live.module.css';

const STAGES = [
  { id: 'authorize', label: 'Authorize', Icon: Smartphone },
  { id: 'verify', label: 'Verify', Icon: ShieldCheck },
  { id: 'dispatch', label: 'Dispatch', Icon: Send },
  { id: 'measure', label: 'Measure', Icon: Gauge },
  { id: 'record', label: 'Record', Icon: FileCheck2 },
  { id: 'settle', label: 'Settle', Icon: BadgeDollarSign },
];

const PHASE_DELAY_MS = 720;

function short(value, start = 12, end = 8) {
  if (typeof value !== 'string' || value.length <= start + end + 3) return value || 'not available';
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'not available' : date.toISOString().slice(11, 19);
}

function powerPoints(data) {
  if (!data?.meter_statement) return [];
  return [
    { label: 'Baseline', value: Number(data.meter_statement.baseline_mw) },
    ...data.meter_statement.intervals.map((sample) => ({
      label: formatTime(sample.at),
      value: Number(sample.load_mw),
    })),
  ];
}

function stageDetail(id, data) {
  if (!data) return 'Waiting for a reference run.';
  const members = data.authorization?.members || [];
  const details = {
    authorize: `${members.length} distinct Class-A mobile handshakes signed the exact action.`,
    verify: `All ${Object.values(data.authorization?.checks || {}).filter(Boolean).length} authorization checks passed under pinned inputs.`,
    dispatch: `${data.acknowledgment?.adapter || 'adapter'} returned a signed, idempotent acknowledgment.`,
    measure: `${data.compliance?.delivered_mw ?? 'not available'} MW independently measured; ${Math.round((data.compliance?.compliance_ratio || 0) * 1000) / 10}% delivered.`,
    record: `Action State ${short(data.action_state?.capsule?.capsule_id, 10, 8)} binds authorization, dispatch, and meter evidence.`,
    settle: data.settlement?.settled ? 'The measured entitlement was consumed exactly once.' : 'No settlement was issued.',
  };
  return details[id];
}

function Verdict({ pass, children }) {
  const Icon = pass ? CheckCircle2 : XCircle;
  return (
    <span className={pass ? styles.passVerdict : styles.refuseVerdict}>
      <Icon aria-hidden="true" size={15} strokeWidth={2.2} />
      {children}
    </span>
  );
}

export default function GraceLiveConsole() {
  const [data, setData] = useState(null);
  const [phase, setPhase] = useState(-1);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState('');
  const timers = useRef([]);

  const clearTimers = useCallback(() => {
    for (const timer of timers.current) window.clearTimeout(timer);
    timers.current = [];
  }, []);

  const run = useCallback(async () => {
    clearTimers();
    setStatus('loading');
    setError('');
    setData(null);
    setPhase(-1);
    try {
      const response = await fetch('/api/v1/grace/reference-scenario', {
        cache: 'no-store',
        headers: { accept: 'application/json' },
      });
      const body = await response.json();
      if (!response.ok || body.ok !== true) throw new Error(body.error || 'reference_scenario_failed');
      setData(body);
      setStatus('running');
      STAGES.forEach((_, index) => {
        timers.current.push(window.setTimeout(() => {
          setPhase(index);
          if (index === STAGES.length - 1) setStatus('complete');
        }, 180 + index * PHASE_DELAY_MS));
      });
    } catch (caught) {
      setStatus('error');
      setError(caught instanceof Error ? caught.message : 'reference_scenario_failed');
    }
  }, [clearTimers]);

  useEffect(() => {
    const initialRun = window.setTimeout(run, 0);
    return () => {
      window.clearTimeout(initialRun);
      clearTimers();
    };
  }, [clearTimers, run]);

  const points = useMemo(() => powerPoints(data), [data]);
  const maxPower = Math.max(...points.map((point) => point.value), 1);
  const currentPower = phase >= 3 && points.length ? points.at(-1).value : points[0]?.value;
  const runComplete = status === 'complete';

  return (
    <main className={styles.page}>
      <section className={styles.header}>
        <div>
          <div className={styles.kicker}>GRACE GRID CONTROL LAB</div>
          <h1>One bounded grid action. Two humans. One physical-effect record.</h1>
          <p>
            This reference run exercises the production verification and one-time state machine
            with synthetic COSA and meter adapters. Every cryptographic check is real. No physical
            grid event is claimed.
          </p>
        </div>
        <div className={styles.runControls}>
          <div className={styles.simulationFlag}>
            <Radio aria-hidden="true" size={15} />
            Reference simulation
          </div>
          <button type="button" className={styles.runButton} onClick={run} disabled={status === 'loading' || status === 'running'}>
            <RefreshCw aria-hidden="true" size={17} className={status === 'loading' ? styles.spin : undefined} />
            Run again
          </button>
        </div>
      </section>

      {status === 'error' ? (
        <section className={styles.errorBand} role="alert">
          <AlertTriangle aria-hidden="true" size={20} />
          <div>
            <strong>Reference run unavailable.</strong>
            <span>{error}</span>
          </div>
        </section>
      ) : null}

      <section className={styles.stageRail} data-testid="grace-stage-rail" aria-label="Curtailment evidence sequence" aria-live="polite">
        {STAGES.map(({ id, label, Icon }, index) => {
          const complete = phase >= index;
          const active = phase === index && !runComplete;
          return (
            <div className={`${styles.stage} ${complete ? styles.stageComplete : ''} ${active ? styles.stageActive : ''}`} key={id}>
              <div className={styles.stageIcon}><Icon aria-hidden="true" size={19} /></div>
              <div>
                <span className={styles.stageNumber}>{String(index + 1).padStart(2, '0')}</span>
                <h2>{label}</h2>
                <p>{complete ? stageDetail(id, data) : 'Pending'}</p>
              </div>
            </div>
          );
        })}
      </section>

      <section className={styles.controlGrid} data-testid="grace-control-grid">
        <div className={styles.powerPanel}>
          <div className={styles.panelHeading}>
            <div>
              <span>Facility load</span>
              <h2>{Number.isFinite(currentPower) ? currentPower.toFixed(3) : '--.---'} MW</h2>
            </div>
            <Verdict pass={phase >= 3 && data?.compliance?.compliant === true}>
              {phase >= 3 ? 'Measured' : 'Awaiting meter'}
            </Verdict>
          </div>
          <div className={styles.powerChart} aria-label="Reference power readings in megawatts">
            {points.length ? points.map((point, index) => (
              <div className={styles.barColumn} key={`${point.label}-${index}`}>
                <div className={styles.barTrack}>
                  <div
                    className={`${styles.bar} ${index === 0 ? styles.baselineBar : styles.measuredBar}`}
                    style={{ height: `${Math.max(6, (point.value / maxPower) * 100)}%`, opacity: phase >= 3 || index === 0 ? 1 : 0.16 }}
                  />
                </div>
                <strong>{point.value.toFixed(3)}</strong>
                <span>{point.label}</span>
              </div>
            )) : (
              <div className={styles.chartLoading}>Preparing signed meter evidence...</div>
            )}
          </div>
          <div className={styles.powerFacts}>
            <div><span>Ordered</span><strong>{data ? (Number(data.action.target_delta_kw) / 1000).toFixed(3) : '--'} MW</strong></div>
            <div><span>Delivered</span><strong>{data?.compliance?.delivered_mw ?? '--'} MW</strong></div>
            <div><span>Compliance</span><strong>{data ? `${(data.compliance.compliance_ratio * 100).toFixed(1)}%` : '--'}</strong></div>
          </div>
        </div>

        <div className={styles.evidencePanel}>
          <div className={styles.panelHeading}>
            <div>
              <span>Evidence packet</span>
              <h2>Trust transitions</h2>
            </div>
            <Verdict pass={runComplete}>{runComplete ? 'Closed' : 'Building'}</Verdict>
          </div>
          <dl className={styles.evidenceList}>
            <div><dt>Action</dt><dd>{short(data?.action_hash)}</dd></div>
            <div><dt>Authorization</dt><dd>{phase >= 1 ? `${data?.authorization?.members?.length || 0}-of-${data?.authorization?.members?.length || 0} Class A` : 'pending'}</dd></div>
            <div><dt>COSA acknowledgment</dt><dd>{phase >= 2 ? short(data?.acknowledgment?.request_digest) : 'pending'}</dd></div>
            <div><dt>Meter statement</dt><dd>{phase >= 3 ? data?.meter_statement?.measurement_class : 'pending'}</dd></div>
            <div><dt>Action State</dt><dd>{phase >= 4 ? short(data?.action_state?.capsule?.capsule_id) : 'pending'}</dd></div>
            <div><dt>Settlement</dt><dd>{phase >= 5 ? (data?.settlement?.settled ? 'consumed once' : 'not issued') : 'pending'}</dd></div>
          </dl>
        </div>
      </section>

      <section className={styles.attackSection} data-testid="grace-attacks">
        <div className={styles.sectionHeading}>
          <div>
            <span>Hostile replay</span>
            <h2>The happy path is not the test. These are.</h2>
          </div>
          <p>Each refusal is generated by the same implementation that produced the positive proof.</p>
        </div>
        <div className={styles.attackGrid}>
          {[
            ['replay', 'Replay', 'The exact authorization is presented a second time.', data?.attacks?.replay],
            ['substitution', 'Action substitution', '18 MW authorization is reused for a different target.', data?.attacks?.action_substitution],
            ['meter-rule', 'Meter rule smuggling', 'A meter tries to inject the settlement rule it is supposed to measure.', data?.attacks?.meter_rule_smuggling],
          ].map(([id, title, body, result]) => (
            <article className={styles.attackItem} data-testid={`grace-attack-${id}`} key={id}>
              <Verdict pass={result?.refused === true}>{result?.refused ? 'Refused' : 'Pending'}</Verdict>
              <h3>{title}</h3>
              <p>{body}</p>
              <code>{result?.verdict || 'not_run'}</code>
            </article>
          ))}
        </div>
      </section>

      <section className={styles.boundaryBand}>
        <AlertTriangle aria-hidden="true" size={20} />
        <div>
          <strong>Honest boundary</strong>
          <p>
            COSA and meter integrations on this page are signed reference adapters, not production
            grid connections. GRACE proves authorization, adapter acknowledgment, evidence integrity,
            and one-time settlement. It does not prove sensor truth or that no bypass path exists.
          </p>
        </div>
      </section>
    </main>
  );
}
