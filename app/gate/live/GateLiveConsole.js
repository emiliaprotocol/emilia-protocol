'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  AlertTriangle,
  Check,
  CircleDollarSign,
  Database,
  FileCheck2,
  Fingerprint,
  HeartPulse,
  KeyRound,
  LockKeyhole,
  Play,
  RefreshCw,
  Rocket,
  ShieldCheck,
  Smartphone,
  X,
  Zap,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import styles from './live.module.css';

const PROFILES = [
  { id: 'treasury', label: 'Treasury', Icon: CircleDollarSign },
  { id: 'production', label: 'Production', Icon: Rocket },
  { id: 'data', label: 'Data', Icon: Database },
  { id: 'healthcare', label: 'Healthcare', Icon: HeartPulse },
];

const STAGES = [
  { id: 'challenge', label: 'Challenge', Icon: LockKeyhole },
  { id: 'ceremony', label: 'Authorize', Icon: Smartphone },
  { id: 'authorization', label: 'Verify', Icon: ShieldCheck },
  { id: 'execution', label: 'Execute', Icon: Play },
  { id: 'reliance', label: 'Seal', Icon: FileCheck2 },
];

const STAGE_DELAY_MS = 520;

function short(value, start = 12, end = 8) {
  if (typeof value !== 'string' || value.length <= start + end + 3) return value || 'not available';
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

function stageSentence(stage, data) {
  if (!data) return 'Pending';
  const sentences = {
    challenge: `${data.challenge.status} ${data.challenge.reason}`,
    ceremony: `${data.ceremony.threshold}-of-${data.ceremony.participants.length} device-bound approval${data.ceremony.threshold > 1 ? 's' : ''}`,
    authorization: `${data.authorization.required_tier} satisfied under pinned keys`,
    execution: data.execution.bound ? 'Effect bound to the authorization decision' : 'Execution binding failed',
    reliance: `${data.reliance.verdict}; evidence chain ${data.evidence.ok ? 'intact' : 'invalid'}`,
  };
  return sentences[stage] || 'Complete';
}

function Status({ pass, children }) {
  const Icon = pass ? Check : X;
  return (
    <span className={pass ? styles.pass : styles.refuse}>
      <Icon aria-hidden="true" size={13} strokeWidth={2.5} />
      {children}
    </span>
  );
}

export default function GateLiveConsole() {
  const [profile, setProfile] = useState('treasury');
  const [data, setData] = useState(null);
  const [stage, setStage] = useState(-1);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState('');
  const timers = useRef([]);

  const clearTimers = useCallback(() => {
    for (const timer of timers.current) window.clearTimeout(timer);
    timers.current = [];
  }, []);

  const run = useCallback(async (nextProfile = 'treasury') => {
    clearTimers();
    setStatus('loading');
    setError('');
    setData(null);
    setStage(-1);
    try {
      const response = await fetch(`/api/v1/gate/reference-scenario?profile=${encodeURIComponent(nextProfile)}`, {
        cache: 'no-store',
        headers: { accept: 'application/json' },
      });
      const body = await response.json();
      if (!response.ok || body.ok !== true) throw new Error(body.error || 'gate_reference_scenario_failed');
      setData(body);
      setStatus('running');
      STAGES.forEach((_, index) => {
        timers.current.push(window.setTimeout(() => {
          setStage(index);
          if (index === STAGES.length - 1) setStatus('complete');
        }, 160 + index * STAGE_DELAY_MS));
      });
    } catch (caught) {
      setStatus('error');
      setError(caught instanceof Error ? caught.message : 'gate_reference_scenario_failed');
    }
  }, [clearTimers]);

  useEffect(() => {
    const initial = window.setTimeout(() => run('treasury'), 0);
    return () => {
      window.clearTimeout(initial);
      clearTimers();
    };
  }, [clearTimers, run]);

  const chooseProfile = useCallback((id) => {
    setProfile(id);
    run(id);
  }, [run]);

  const completed = status === 'complete';
  const applicableChecks = useMemo(
    () => data?.reliance?.checks?.filter((check) => check.ok !== null) || [],
    [data],
  );
  const checksPassed = applicableChecks.filter((check) => check.ok === true).length;

  return (
    <main className={styles.page}>
      <header className={styles.header}>
        <div>
          <div className={styles.kicker}>EMILIA GATE / REFERENCE CONTROL ROOM</div>
          <h1>Consequential action control</h1>
          <p>Challenge, accountable approval, execution, and evidence in one transaction.</p>
        </div>
        <div className={styles.headerStatus}>
          <span className={styles.referenceDot} />
          Reference lab · no production effect
        </div>
      </header>

      <section className={styles.profileBar} aria-label="Action profile">
        <div className={styles.segmented}>
          {PROFILES.map(({ id, label, Icon }) => (
            <button
              type="button"
              key={id}
              className={profile === id ? styles.segmentActive : styles.segment}
              onClick={() => chooseProfile(id)}
              disabled={status === 'loading' || status === 'running'}
              aria-pressed={profile === id}
            >
              <Icon aria-hidden="true" size={16} />
              <span>{label}</span>
            </button>
          ))}
        </div>
        <div className={styles.profileActions}>
          <a className={styles.energyLink} href="/grace/live">
            <Zap aria-hidden="true" size={15} />
            Energy control
          </a>
          <button
            type="button"
            className={styles.runButton}
            onClick={() => run(profile)}
            disabled={status === 'loading' || status === 'running'}
          >
            <RefreshCw aria-hidden="true" size={16} className={status === 'loading' ? styles.spin : undefined} />
            New transaction
          </button>
        </div>
      </section>

      {status === 'error' ? (
        <section className={styles.errorBand} role="alert">
          <AlertTriangle aria-hidden="true" size={19} />
          <div><strong>Reference transaction unavailable.</strong><span>{error}</span></div>
        </section>
      ) : null}

      <section className={styles.actionBand} data-testid="gate-action-band">
        <div className={styles.actionIdentity}>
          <span>Pending consequence</span>
          <h2>{data?.profile?.headline || 'Preparing protected action'}</h2>
          <p>{data?.profile?.consequence || 'Loading the system-of-record action.'}</p>
        </div>
        <dl className={styles.actionMeta}>
          <div><dt>Policy</dt><dd>{data?.profile?.policy || 'pending'}</dd></div>
          <div><dt>Assurance floor</dt><dd>{data?.profile?.tier || 'pending'}</dd></div>
          <div><dt>Action digest</dt><dd>{short(data?.action_hash)}</dd></div>
        </dl>
        <Status pass={completed}>{completed ? 'Executed once' : 'Blocked pending proof'}</Status>
      </section>

      <section className={styles.stageRail} aria-label="Gate enforcement sequence" aria-live="polite">
        {STAGES.map(({ id, label, Icon }, index) => {
          const done = stage >= index;
          const active = stage === index && !completed;
          return (
            <div className={`${styles.stage} ${done ? styles.stageDone : ''} ${active ? styles.stageCurrent : ''}`} key={id}>
              <div className={styles.stageIcon}><Icon aria-hidden="true" size={18} /></div>
              <span>{String(index + 1).padStart(2, '0')}</span>
              <h3>{label}</h3>
              <p>{done ? stageSentence(id, data) : 'Pending'}</p>
            </div>
          );
        })}
      </section>

      <section className={styles.workspace} data-testid="gate-live-workspace">
        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div><span>System of record</span><h2>Material fields</h2></div>
            <KeyRound aria-hidden="true" size={20} />
          </div>
          <dl className={styles.fieldList}>
            {(data?.profile?.material || []).map(([label, value]) => (
              <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
            ))}
            {!data ? <div><dt>Status</dt><dd>Loading action...</dd></div> : null}
          </dl>
          <div className={styles.boundaryNote}>
            <Fingerprint aria-hidden="true" size={17} />
            <p>Fields are executor-observed and bound to the signed action.</p>
          </div>
        </div>

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div><span>Human ceremony</span><h2>{data?.ceremony?.threshold || '-'} of {data?.ceremony?.participants?.length || '-'}</h2></div>
            <Status pass={stage >= 1}>{stage >= 1 ? 'Verified' : 'Waiting'}</Status>
          </div>
          <div className={styles.participants}>
            {(data?.ceremony?.participants || []).map((participant, index) => (
              <div className={styles.participant} key={`${participant.approver}-${index}`}>
                <div className={styles.avatar}>{String(index + 1).padStart(2, '0')}</div>
                <div><strong>{participant.role.replaceAll('_', ' ')}</strong><span>{participant.approver}</span></div>
                <Smartphone aria-hidden="true" size={17} />
              </div>
            ))}
            {!data ? <div className={styles.placeholder}>Preparing device-bound ceremony...</div> : null}
          </div>
          <dl className={styles.compactFacts}>
            <div><dt>Origin</dt><dd>{data?.ceremony?.origin || 'pending'}</dd></div>
            <div><dt>Proof</dt><dd>WebAuthn P-256 · UP + UV</dd></div>
          </dl>
        </div>

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div><span>Reliance packet</span><h2>{data?.reliance?.verdict || 'pending'}</h2></div>
            <Status pass={completed}>{completed ? 'Closed' : 'Building'}</Status>
          </div>
          <dl className={styles.packetFacts}>
            <div><dt>Decision</dt><dd>{short(data?.authorization?.decision_hash)}</dd></div>
            <div><dt>Execution</dt><dd>{short(data?.execution?.execution_hash)}</dd></div>
            <div><dt>Evidence head</dt><dd>{data?.evidence?.head_short || 'pending'}</dd></div>
            <div><dt>Applicable checks</dt><dd>{checksPassed}/{applicableChecks.length}</dd></div>
          </dl>
          <div className={styles.packetFooter}>
            <FileCheck2 aria-hidden="true" size={17} />
            <span>{data?.execution?.bound ? 'Execution proof binds to the authorization decision.' : 'Awaiting bound execution proof.'}</span>
          </div>
        </div>
      </section>

      <section className={styles.hostileSection} data-testid="gate-hostile-results">
        <div className={styles.sectionHeading}>
          <div><span>Hostile paths</span><h2>The control is the refusal.</h2></div>
          <p>Same runtime. Same pinned policy. Five attempts that never reach execution.</p>
        </div>
        <div className={styles.attackGrid}>
          {(data?.attacks || []).map((attack) => (
            <div className={styles.attack} key={attack.id}>
              <Status pass={attack.refused}>{attack.refused ? 'Refused' : 'Failed open'}</Status>
              <h3>{attack.label}</h3>
              <code>{attack.status || '--'} · {attack.reason || 'not_run'}</code>
            </div>
          ))}
          {!data ? PROFILES.concat(PROFILES[0]).map((item, index) => (
            <div className={styles.attack} key={`${item.id}-${index}`}><span className={styles.skeleton} /></div>
          )) : null}
        </div>
      </section>

      <section className={styles.honestBand}>
        <AlertTriangle aria-hidden="true" size={19} />
        <div>
          <strong>Reference boundary</strong>
          <p>Every cryptographic and enforcement check is real. Keys and effects are generated for this run; no production system or physical actuator is touched.</p>
        </div>
      </section>
    </main>
  );
}
