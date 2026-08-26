'use client';

// SPDX-License-Identifier: Apache-2.0
import type React from 'react';
import {
  AlertTriangle,
  BadgeDollarSign,
  CheckCircle2,
  FileCheck2,
  Gauge,
  Play,
  Radio,
  RefreshCw,
  Send,
  ShieldCheck,
  Smartphone,
  XCircle,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import styles from './live.module.css';

interface StageItem {
  id: string;
  label: string;
  technical: string;
  Icon: React.ComponentType<Record<string, unknown>>;
}

const STAGES: StageItem[] = [
  { id: 'authorize', label: 'Two roles approve', technical: 'Authorize', Icon: Smartphone },
  { id: 'verify', label: 'Gate checks the order', technical: 'Verify', Icon: ShieldCheck },
  { id: 'dispatch', label: 'Adapter acknowledges', technical: 'Dispatch', Icon: Send },
  { id: 'measure', label: 'Meter reports', technical: 'Measure', Icon: Gauge },
  { id: 'record', label: 'Receipt seals', technical: 'Record', Icon: FileCheck2 },
  { id: 'settle', label: 'Settlement admission consumed', technical: 'Settle', Icon: BadgeDollarSign },
];

const PHASE_DELAY_MS = 720;

interface GraceReferenceScenario {
  ok: boolean;
  reference_only: boolean;
  physical_claim: boolean;
  description: string;
  action: { target_delta_kw: string; [key: string]: unknown };
  action_hash: string;
  authorization: { valid: boolean; checks: Record<string, boolean>; members: unknown[] };
  acknowledgment: { adapter?: string; request_digest?: string; [key: string]: unknown };
  meter_statement: {
    baseline_mw: string;
    intervals: Array<{ at: string; load_mw: string }>;
    measurement_class?: string;
    [key: string]: unknown;
  };
  compliance: { delivered_mw?: number; compliance_ratio: number; compliant: boolean; [key: string]: unknown };
  action_state: { capsule?: { capsule_id?: string }; [key: string]: unknown };
  settlement: { settled: boolean; key: unknown; result: unknown };
  attacks: {
    replay: { refused: boolean; verdict: string };
    action_substitution: { refused: boolean; verdict: string };
    meter_rule_smuggling: { refused: boolean; verdict: string };
  };
  pins?: unknown;
}

interface PowerPoint {
  label: string;
  value: number;
}

function short(value: unknown, start = 12, end = 8): string {
  if (typeof value !== 'string' || value.length <= start + end + 3) return (value as string) || 'not available';
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'not available' : date.toISOString().slice(11, 19);
}

function powerPoints(data: GraceReferenceScenario | null): PowerPoint[] {
  if (!data?.meter_statement) return [];
  return [
    { label: 'Baseline', value: Number(data.meter_statement.baseline_mw) },
    ...data.meter_statement.intervals.map((sample) => ({
      label: formatTime(sample.at),
      value: Number(sample.load_mw),
    })),
  ];
}

function stageDetail(id: string, data: GraceReferenceScenario | null): string {
  if (!data) return 'Waiting for a reference run.';
  const members = data.authorization?.members || [];
  const details: Record<string, string> = {
    authorize: `${members.length} distinct reference approver roles signed the exact facility, reduction, and time window.`,
    verify: `Gate passed ${Object.values(data.authorization?.checks || {}).filter(Boolean).length} checks under pinned rules.`,
    dispatch: `${data.acknowledgment?.adapter || 'The reference adapter'} returned a signed, idempotent acknowledgment.`,
    measure: `GRACE computed ${data.compliance?.delivered_mw ?? 'not available'} MW delivered from a separately keyed meter statement.`,
    record: `Receipt ${short(data.action_state?.capsule?.capsule_id, 10, 8)} binds the order, acknowledgment, and meter evidence.`,
    settle: data.settlement?.settled ? 'Settlement admission was consumed once in the reference state machine.' : 'No settlement admission was issued.',
  };
  return details[id] || '';
}

interface VerdictProps {
  pass: boolean;
  children: React.ReactNode;
}

function Verdict({ pass, children }: VerdictProps): React.ReactElement {
  const Icon = pass ? CheckCircle2 : XCircle;
  return (
    <span className={pass ? styles.passVerdict : styles.refuseVerdict}>
      <Icon aria-hidden="true" size={15} strokeWidth={2.2} />
      {children}
    </span>
  );
}

export default function GraceLiveConsole(): React.ReactElement {
  const [data, setData] = useState<GraceReferenceScenario | null>(null);
  const [phase, setPhase] = useState<number>(-1);
  const [status, setStatus] = useState<string>('idle');
  const [error, setError] = useState<string>('');
  const timers = useRef<number[]>([]);

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

  useEffect(() => clearTimers, [clearTimers]);

  const points = useMemo(() => powerPoints(data), [data]);
  const maxPower = Math.max(...points.map((point) => point.value), 1);
  const currentPower = phase >= 3 && points.length ? points.at(-1)!.value : points[0]?.value;
  const runComplete = status === 'complete';
  const orderedMw = data ? Number(data.action.target_delta_kw) / 1000 : 18;
  const baselineMw = data ? Number(data.meter_statement.baseline_mw) : 64;
  const targetMw = baselineMw - orderedMw;
  const announcedStageIndex = Math.max(phase, 0);
  let liveStatus = `Step ${announcedStageIndex + 1} of ${STAGES.length}: ${STAGES[announcedStageIndex].label}.`;
  if (status === 'idle') liveStatus = 'Ready to run the reference curtailment.';
  if (status === 'loading') liveStatus = 'Loading the reference curtailment.';
  if (status === 'error') liveStatus = 'The reference curtailment is unavailable.';
  if (runComplete) liveStatus = `Reference curtailment complete. ${STAGES.length} of ${STAGES.length} stages complete.`;

  return (
    <main className={styles.page}>
      <section className={styles.header}>
        <div className={styles.headerCopy}>
          <div className={styles.kicker}>LIVE GRID CURTAILMENT DEMO</div>
          <h1>The grid needs {orderedMw.toFixed(0)} MW back. Which agent is allowed to act?</h1>
          <p>
            When demand spikes, the grid may ask one facility to use less power for a fixed window.
            If an agent changes the site, amount, or timing, the wrong equipment can move and the
            settlement can be wrong.
          </p>
          <p className={styles.solutionLine}>
            GRACE binds one reference request to one facility, a {orderedMw.toFixed(0)} MW
            reduction, a 90-minute window, two distinct reference approver signatures, a separately
            keyed meter statement, and one settlement admission.
          </p>
          <div className={styles.riskRow} aria-label="What can go wrong without a bounded order">
            <span>Wrong site</span>
            <span>Wrong amount</span>
            <span>Blind retry</span>
          </div>
          <div className={styles.plainFlow} aria-label="Curtailment proof flow">
            <span>Grid asks</span><i>→</i><span>Two roles approve</span><i>→</i><span>Gate admits once</span><i>→</i><span>Meter checks</span><i>→</i><span>Admit settlement once</span>
          </div>
          <div className={styles.runControls}>
            <button type="button" className={styles.runButton} onClick={run} disabled={status === 'loading' || status === 'running'}>
              {status === 'loading' || status === 'running' ? (
                <RefreshCw aria-hidden="true" size={17} className={styles.spin} />
              ) : (
                <Play aria-hidden="true" size={16} fill="currentColor" />
              )}
              {status === 'loading' || status === 'running' ? 'Running the reference flow' : runComplete ? 'Run again' : 'Run the curtailment demo'}
            </button>
            <a href="#grace-attacks">See what gets blocked</a>
          </div>
          <div className={styles.heroBoundary}>
            <Radio aria-hidden="true" size={15} />
            Signed reference simulation. No physical grid event is claimed.
          </div>
        </div>

        <div className={styles.curtailmentVisual}>
          <div className={styles.curtailmentHeader}>
            <span>REFERENCE CURTAILMENT</span>
            <strong>90 MINUTES</strong>
          </div>
          <div className={styles.gridAlert}>
            <span>GRID STRESS</span>
            <strong>Reduce this facility now</strong>
          </div>
          <svg viewBox="0 0 640 270" role="img" aria-labelledby="grace-curve-title grace-curve-description">
            <title id="grace-curve-title">Reference facility demand curtailment</title>
            <desc id="grace-curve-description">
              Facility load starts at {baselineMw.toFixed(0)} megawatts. A bounded order requests a {orderedMw.toFixed(0)} megawatt reduction for a target near {targetMw.toFixed(0)} megawatts.
            </desc>
            <defs>
              <linearGradient id="grace-stress-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ffb45e" stopOpacity="0.42" />
                <stop offset="100%" stopColor="#ffb45e" stopOpacity="0" />
              </linearGradient>
              <linearGradient id="grace-safe-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#6fd0a0" stopOpacity="0.34" />
                <stop offset="100%" stopColor="#6fd0a0" stopOpacity="0" />
              </linearGradient>
            </defs>
            <g className={styles.curveGrid}>
              <path d="M46 50H606M46 110H606M46 170H606M46 230H606" />
              <path d="M46 30V230M186 30V230M326 30V230M466 30V230M606 30V230" />
            </g>
            <path className={styles.targetLine} d="M46 176H606" />
            <text className={styles.targetLabel} x="50" y="168">{targetMw.toFixed(0)} MW TARGET</text>
            <path className={styles.stressFill} d="M46 230V69C124 64 169 75 232 68C283 62 314 68 341 92L341 230Z" />
            <path className={styles.safeFill} d="M341 230V92C376 131 402 165 449 174C502 184 544 177 606 179V230Z" />
            <path className={styles.stressCurve} d="M46 69C124 64 169 75 232 68C283 62 314 68 341 92" />
            <path className={styles.safeCurve} d="M341 92C376 131 402 165 449 174C502 184 544 177 606 179" />
            <circle className={styles.orderPoint} cx="341" cy="92" r="7" />
            <text className={styles.orderLabel} x="356" y="80">ORDER ADMITTED ONCE</text>
          </svg>
          <div className={styles.curtailmentMetrics}>
            <div><span>Before</span><strong>{baselineMw.toFixed(0)} MW</strong></div>
            <div data-tone="amber"><span>Requested</span><strong>−{orderedMw.toFixed(0)} MW</strong></div>
            <div data-tone="green"><span>Target</span><strong>{targetMw.toFixed(0)} MW</strong></div>
          </div>
          <div className={styles.facilityLine}>facility:us-west-dc-17 · exact window · reference only</div>
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

      <p className={styles.srOnly} role="status">
        {liveStatus}
      </p>
      <section className={styles.stageRail} data-testid="grace-stage-rail" aria-label="Curtailment evidence sequence">
        {STAGES.map(({ id, label, technical, Icon }, index) => {
          const complete = phase >= index;
          const active = phase === index && !runComplete;
          return (
            <div className={`${styles.stage} ${complete ? styles.stageComplete : ''} ${active ? styles.stageActive : ''}`} key={id}>
              <div className={styles.stageIcon}><Icon aria-hidden="true" size={19} /></div>
              <div>
                <span className={styles.stageNumber}>{String(index + 1).padStart(2, '0')} / {technical}</span>
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
              <span>Reference load</span>
              <h2>{Number.isFinite(currentPower) ? currentPower!.toFixed(3) : '--.---'} MW</h2>
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
              <h2>What the customer can prove</h2>
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

      <section id="grace-attacks" className={styles.attackSection} data-testid="grace-attacks">
        <div className={styles.sectionHeading}>
          <div>
            <span>Hostile replay</span>
            <h2>Now try to cheat it.</h2>
          </div>
          <p>Each refusal is generated by the same implementation that produced the positive proof.</p>
        </div>
        <div className={styles.attackGrid}>
          {([
            ['replay', 'Replay', 'The exact authorization is presented a second time.', data?.attacks?.replay],
            ['substitution', 'Action substitution', `${orderedMw.toFixed(0)} MW authorization is reused for a different target.`, data?.attacks?.action_substitution],
            ['meter-rule', 'Meter rule smuggling', 'A meter tries to inject the settlement rule it is supposed to measure.', data?.attacks?.meter_rule_smuggling],
          ] as const).map(([id, title, body, result]) => (
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
            and one-time settlement admission in the reference state machine. It does not prove
            sensor truth, physical payment, or that no bypass path exists.
          </p>
        </div>
      </section>
    </main>
  );
}
