'use client';

// SPDX-License-Identifier: Apache-2.0
import type React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CircleDollarSign,
  Clock,
  Download,
  FileCheck2,
  Fingerprint,
  HeartPulse,
  LockKeyhole,
  Play,
  RefreshCw,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import styles from './program-integrity.module.css';
import { SCENARIOS, STAGES } from './scenarios';

const STEP_DELAY_MS = 240;

function shortDigest(value: string | undefined, start = 22, end = 14): string {
  if (!value || value.length <= start + end + 3) return value || '';
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

interface StatusMarkProps {
  status: string;
  children: React.ReactNode;
}

function StatusMark({ status, children }: StatusMarkProps): React.ReactElement {
  const pass = status === 'pass';
  const Icon = pass ? Check : X;
  return (
    <span className={pass ? styles.checkPass : styles.checkFail}>
      <Icon aria-hidden="true" size={14} strokeWidth={2.5} />
      {children}
    </span>
  );
}

interface ResultBadgeProps {
  scenario: typeof SCENARIOS[0];
}

function ResultBadge({ scenario }: ResultBadgeProps): React.ReactElement {
  const Icon =
    scenario.tone === 'authorized'
      ? Check
      : scenario.tone === 'refused'
        ? X
        : Clock;

  return (
    <span className={`${styles.verdict} ${styles[scenario.tone]}`}>
      <Icon aria-hidden="true" size={16} strokeWidth={2.5} />
      {scenario.initialVerdict}
    </span>
  );
}

export default function ProgramIntegrityGate(): React.ReactElement {
  const [selectedId, setSelectedId] = useState<string>('valid');
  const [runState, setRunState] = useState<string>('idle');
  const [activeStage, setActiveStage] = useState<number>(-1);
  const [downloaded, setDownloaded] = useState<boolean>(false);
  const timers = useRef<number[]>([]);

  const scenario = useMemo(
    () => SCENARIOS.find((item) => item.id === selectedId) || SCENARIOS[0],
    [selectedId],
  );

  const clearTimers = useCallback(() => {
    timers.current.forEach((timer) => window.clearTimeout(timer));
    timers.current = [];
  }, []);

  const selectScenario = useCallback(
    (id: string) => {
      clearTimers();
      setSelectedId(id);
      setRunState('idle');
      setActiveStage(-1);
      setDownloaded(false);
    },
    [clearTimers],
  );

  const runScenario = useCallback(() => {
    clearTimers();
    setRunState('running');
    setActiveStage(-1);
    setDownloaded(false);

    STAGES.forEach((_, index) => {
      timers.current.push(
        window.setTimeout(() => {
          setActiveStage(index);
          if (index === STAGES.length - 1) setRunState('complete');
        }, 80 + index * STEP_DELAY_MS),
      );
    });
  }, [clearTimers]);

  useEffect(() => clearTimers, [clearTimers]);

  const downloadPacket = useCallback(() => {
    const body = JSON.stringify(
      {
        ...scenario.packet,
        exact_action: Object.fromEntries(
          scenario.fields.map((field) => [field.id, field.value]),
        ),
        policy_checks: scenario.checks,
        capability: scenario.capability,
        execution: scenario.execution,
        boundary:
          'Synthetic PHI-free reference fixture. Not a production eligibility, coverage, or payment decision.',
      },
      null,
      2,
    );
    const blob = new Blob([body], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `emilia-program-integrity-${scenario.id}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  }, [scenario]);

  const completed = runState === 'complete';
  const visibleStage =
    activeStage >= 0 ? STAGES[activeStage] : { label: 'Ready', description: 'Choose a scenario and run the gate.' };

  return (
    <main className={styles.page}>
      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <div className={styles.heroCopy}>
            <div className={styles.kicker}>
              <HeartPulse aria-hidden="true" size={15} />
              Amelia I + EMILIA Gate
            </div>
            <h1>Find the risky workflow. Then make the next payment prove its authorization.</h1>
            <p className={styles.heroLede}>
              Amelia I reconstructs the approval-to-effect chain from a governed legacy
              export. EMILIA Gate then binds the provider action, authorization,
              destination, amount, and named approval before the next protected effect.
            </p>
            <p className={styles.heroBoundary}>
              The diagnostic is read-only and does not declare fraud. The Gate is a
              prospective control designed to sit beside existing program-integrity and
              payment systems—not replace DHCS, CA-MMIS, or their controls.
            </p>
            <div className={styles.heroActions}>
              <a href="/pilot?v=health" className={styles.primaryAction}>
                Scope the Amelia I diagnostic
                <ArrowRight aria-hidden="true" size={16} />
              </a>
              <a href="#reference-lab" className={styles.secondaryAction}>
                Run the prospective Gate
              </a>
            </div>
          </div>
          <div className={styles.publicValue} aria-label="Public-interest control model">
            <div className={styles.valueTop}>
              <span>One commercial path</span>
              <ShieldCheck aria-hidden="true" size={22} />
            </div>
            <div className={styles.valueStatement}>
              <strong>Diagnose the old record.</strong>
              <strong>Bind the next decision.</strong>
              <strong>Reconcile the outcome.</strong>
            </div>
            <dl className={styles.valueFacts}>
              <div>
                <dt>Amelia I</dt>
                <dd>Find the boundary</dd>
              </div>
              <div>
                <dt>Gate</dt>
                <dd>Protect the effect</dd>
              </div>
              <div>
                <dt>Assurance</dt>
                <dd>Re-perform proof</dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      <section className={styles.boundaryBand} aria-label="Demo boundary">
        <div>
          <AlertTriangle aria-hidden="true" size={18} />
          <p>
            <strong>Synthetic and PHI-free.</strong> All names, identifiers, amounts,
            authorizations, destinations, and outcomes below are deterministic fixtures.
          </p>
        </div>
        <span>Reference lab · no production effect</span>
      </section>

      <section className={styles.lab} id="reference-lab">
        <header className={styles.labHeader}>
          <div>
            <div className={styles.eyebrow}>Interactive reference lab</div>
            <h2>What happens at the moment of consequence?</h2>
          </div>
          <div className={styles.labStatus} aria-live="polite" aria-atomic="true">
            <span className={runState === 'running' ? styles.statusPulse : styles.statusDot} />
            <div>
              <strong>{runState === 'running' ? visibleStage.label : completed ? scenario.finalState : 'Ready to run'}</strong>
              <span>{runState === 'running' ? visibleStage.description : 'Deterministic local fixture'}</span>
            </div>
          </div>
        </header>

        <div className={styles.scenarioBar} role="group" aria-label="Program integrity scenario">
          {SCENARIOS.map((item) => (
            <button
              type="button"
              key={item.id}
              className={item.id === selectedId ? styles.scenarioActive : styles.scenario}
              onClick={() => selectScenario(item.id)}
              aria-pressed={item.id === selectedId}
              disabled={runState === 'running'}
            >
              <span>{item.shortLabel}</span>
              <small>{item.initialVerdict}</small>
            </button>
          ))}
          <button
            type="button"
            className={styles.runButton}
            onClick={runScenario}
            disabled={runState === 'running'}
          >
            {completed ? (
              <RefreshCw aria-hidden="true" size={16} />
            ) : (
              <Play aria-hidden="true" size={16} fill="currentColor" />
            )}
            {completed ? 'Run again' : runState === 'running' ? 'Running…' : 'Run scenario'}
          </button>
        </div>

        <section className={styles.actionSummary} data-tone={scenario.tone}>
          <div className={styles.actionTitle}>
            <span>Proposed consequence</span>
            <h3>{scenario.label}</h3>
            <p>{scenario.summary}</p>
          </div>
          <div className={styles.caidBlock}>
            <span>Canonical Action Identifier (CAID)</span>
            <code>{scenario.caid}</code>
            <p>Any material field change produces a different action identifier.</p>
          </div>
          <div className={styles.actionResult}>
            <ResultBadge scenario={scenario} />
            <small>{completed ? scenario.finalState : 'Run to verify'}</small>
          </div>
        </section>

        <ol className={styles.stageRail} aria-label="Program integrity enforcement sequence">
          {STAGES.map((stage, index) => {
            const done = activeStage >= index;
            const current = runState === 'running' && activeStage === index;
            return (
              <li
                key={stage.id}
                className={`${styles.stage} ${done ? styles.stageDone : ''} ${current ? styles.stageCurrent : ''}`}
              >
                <div className={styles.stageIndex}>
                  {done ? <Check aria-hidden="true" size={14} strokeWidth={2.5} /> : String(index + 1).padStart(2, '0')}
                </div>
                <div>
                  <strong>{stage.label}</strong>
                  <span>{done ? scenario.stageNotes[index] : stage.description}</span>
                </div>
              </li>
            );
          })}
        </ol>

        <div className={styles.workbench}>
          <section className={styles.panel}>
            <header className={styles.panelHeader}>
              <div>
                <span>01 / Exact action</span>
                <h3>Material fields</h3>
              </div>
              <Fingerprint aria-hidden="true" size={21} />
            </header>
            <dl className={styles.fieldList}>
              {scenario.fields.map((field) => (
                <div className={field.state === 'mismatch' ? styles.fieldMismatch : undefined} key={field.id}>
                  <dt>{field.label}</dt>
                  <dd>
                    <code title={String(field.value)}>{field.displayValue ?? field.value}</code>
                    {field.authorizedValue ? (
                      <small title={String(field.authorizedValue)}>
                        {field.authorizedDisplayValue ?? field.authorizedValue}
                      </small>
                    ) : null}
                  </dd>
                </div>
              ))}
            </dl>
            {scenario.id === 'mismatch' ? (
              <div className={styles.receiptMismatch}>
                <X aria-hidden="true" size={16} />
                <div>
                  <strong>Receipt bound to a different CAID</strong>
                  <code>{scenario.receiptCaid}</code>
                </div>
              </div>
            ) : null}
          </section>

          <section className={styles.panel}>
            <header className={styles.panelHeader}>
              <div>
                <span>02 / Policy decision</span>
                <h3>Evidence checks</h3>
              </div>
              <ShieldCheck aria-hidden="true" size={21} />
            </header>
            <div className={styles.checkList}>
              {scenario.checks.map((check) => (
                <div className={styles.check} key={check.id}>
                  <StatusMark status={check.status}>{check.status === 'pass' ? 'Pass' : 'Refuse'}</StatusMark>
                  <div>
                    <strong>{check.label}</strong>
                    <span>{check.evidence}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className={styles.panel}>
            <header className={styles.panelHeader}>
              <div>
                <span>03 / Execution right</span>
                <h3>Bounded capability</h3>
              </div>
              <LockKeyhole aria-hidden="true" size={21} />
            </header>
            <div className={styles.capabilityState} data-state={scenario.capability.state}>
              <span>{scenario.capability.state}</span>
              <code>{scenario.capability.token}</code>
            </div>
            <dl className={styles.capabilityFacts}>
              <div>
                <dt>Scope</dt>
                <dd>{scenario.capability.scope}</dd>
              </div>
              <div>
                <dt>Budget</dt>
                <dd>{scenario.capability.budget}</dd>
              </div>
              <div>
                <dt>Usage</dt>
                <dd>{scenario.capability.uses}</dd>
              </div>
              <div>
                <dt>Expiry</dt>
                <dd>{scenario.capability.expiry}</dd>
              </div>
            </dl>
            <div className={styles.singleUseNote}>
              <CircleDollarSign aria-hidden="true" size={17} />
              <span>Amount, destination, action, use count, and time are all bounded.</span>
            </div>
          </section>
        </div>

        <section className={styles.outcomeSection}>
          <header className={styles.outcomeHeader}>
            <div>
              <div className={styles.eyebrow}>Executor outcome control</div>
              <h2>The timeout is a state—not permission to try again.</h2>
            </div>
            <ResultBadge scenario={scenario} />
          </header>
          <div className={styles.outcomeGrid}>
            <div>
              <span>Initial executor response</span>
              <strong>{scenario.execution.initial}</strong>
            </div>
            <div className={styles.replayCell}>
              <span>No-blind-replay guard</span>
              <strong>{scenario.execution.replay}</strong>
            </div>
            <div>
              <span>Authenticated reconciliation</span>
              <strong>{scenario.execution.reconciliation}</strong>
            </div>
            <div>
              <span>Safe terminal handling</span>
              <strong>{scenario.execution.final}</strong>
            </div>
          </div>
        </section>

        <section className={styles.packetSection}>
          <div className={styles.packetCopy}>
            <div className={styles.eyebrow}>Portable evidence packet</div>
            <h2>The agency does not have to take the operator's word for it.</h2>
            <p>
              The packet carries the exact action, policy decision, bounded capability,
              executor outcome, and evidence-chain head. An authorized reviewer can
              preserve it and verify it outside the application.
            </p>
            <button
              type="button"
              className={styles.downloadButton}
              onClick={downloadPacket}
              disabled={!completed}
            >
              <Download aria-hidden="true" size={16} />
              {downloaded ? 'Packet downloaded' : completed ? 'Download fixture packet' : 'Run scenario to download'}
            </button>
          </div>
          <div className={styles.packetPreview}>
            <div className={styles.packetPreviewHeader}>
              <span>evidence-packet.json</span>
              <FileCheck2 aria-hidden="true" size={17} />
            </div>
            <dl>
              {Object.entries(scenario.packet).map(([key, value]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd>
                    {typeof value === 'boolean'
                      ? String(value)
                      : key === 'action_caid'
                        ? value
                        : shortDigest(value as string, 20, 12)}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </section>
      </section>

      <section className={styles.honestBoundary}>
        <div>
          <div className={styles.eyebrow}>Honest boundary</div>
          <h2>A consequence-control demonstration, not a fraud detector.</h2>
        </div>
        <p>
          This browser fixture does not make eligibility, coverage, medical-necessity,
          provider-sanction, or payment decisions. It demonstrates how an agency can
          make existing decisions exact-action bound, single-use, fail-closed, and
          independently reviewable before a consequential action executes.
        </p>
      </section>

      <section className={styles.nextSteps} aria-labelledby="program-integrity-next-step">
        <div>
          <div className={styles.eyebrow}>Practical next step</div>
          <h2 id="program-integrity-next-step">Start with one read-only workflow for 60 days.</h2>
          <p>
            Begin with synthetic replay and a governed export. Amelia I surfaces the
            approval-to-effect gaps and produces an Action Control Manifest template.
            If the workflow justifies prospective enforcement, Gate becomes the separately
            scoped next engagement at the real system boundary.
          </p>
          <a href="/pilot?v=gov" className={styles.pilotAction}>
            Scope the Amelia I diagnostic
            <ArrowRight aria-hidden="true" size={16} />
          </a>
        </div>
        <nav className={styles.relatedLinks} aria-label="Related EMILIA control surfaces">
          <a href="/gate"><span>Gate</span><small>Pre-effect enforcement</small></a>
          <a href="/assurance"><span>Assurance</span><small>Independent re-performance</small></a>
          <a href="/action-escrow"><span>Action Escrow</span><small>Irreversible payment consequence</small></a>
          <a href="/grace"><span>GRACE</span><small>Physical-system outcome evidence</small></a>
        </nav>
      </section>
    </main>
  );
}
