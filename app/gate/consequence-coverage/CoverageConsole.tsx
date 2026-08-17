'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Database,
  FileKey2,
  Fingerprint,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import styles from './coverage.module.css';

interface Finding {
  record_id: string;
  caid: string;
  action_digest: string;
  classification?: string;
  classification_rule_id?: string;
  reclassification_reason?: string;
}

interface CoverageScenario {
  ok: true;
  reference_only: true;
  period: { start: string; end: string };
  summary: Record<string, number>;
  bypass: Finding;
  findings: {
    matched: Array<Finding & { system_record_id: string; receipt_record_id: string }>;
    effect_without_receipt: Finding[];
    receipted_without_observation: Finding[];
    indeterminate: Finding[];
    system_indeterminate: Finding[];
    excluded: Finding[];
    exception: Finding[];
  };
  sources: {
    system_of_record: { operator_id: string; record_count: number; population_root: string };
    receipt_population: { operator_id: string; record_count: number; population_root: string };
  };
  report_hash: string;
  attestation_body_digest: string;
  claim_boundary: string;
}

const LABELS: Array<[string, string]> = [
  ['matched', 'Matched exact action'],
  ['effect_without_receipt', 'Effect without receipt'],
  ['receipted_without_observation', 'Receipted without observation'],
  ['indeterminate', 'Uncertain outcome'],
  ['system_indeterminate', 'Unresolved classification'],
  ['excluded', 'Declared exclusion'],
  ['exception', 'Source exception'],
];

function short(value: string, start = 15, end = 8) {
  return value.length > start + end + 3
    ? `${value.slice(0, start)}…${value.slice(-end)}`
    : value;
}

function date(value: string) {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC',
  }).format(new Date(value));
}

export default function CoverageConsole() {
  const [data, setData] = useState<CoverageScenario | null>(null);
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading');

  const run = useCallback(async () => {
    setState('loading');
    try {
      const response = await fetch('/api/v1/gate/coverage-scenario', {
        cache: 'no-store', headers: { accept: 'application/json' },
      });
      const body = await response.json();
      if (!response.ok || body.ok !== true) throw new Error('coverage_reference_scenario_failed');
      setData(body);
      setState('ready');
    } catch {
      setState('error');
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => { void run(); }, 0);
    return () => window.clearTimeout(initial);
  }, [run]);

  return (
    <main className={styles.page}>
      <header className={styles.hero}>
        <div className={styles.kicker}>CONSEQUENCE COVERAGE / REFERENCE LAB</div>
        <h1>Prove what did not go through the Gate.</h1>
        <div className={styles.heroBottom}>
          <p>
            A receipt proves one action was mediated. Coverage reconciliation asks the harder
            population question: did the system of record contain an effect with no corresponding receipt?
          </p>
          <button type="button" onClick={run} disabled={state === 'loading'}>
            <RefreshCw size={16} className={state === 'loading' ? styles.spin : undefined} />
            Run signed reconciliation
          </button>
        </div>
      </header>

      {state === 'error' ? (
        <section className={styles.error} role="alert">
          <AlertTriangle size={18} /> Reference reconciliation unavailable.
        </section>
      ) : null}

      <section className={styles.sourceRail} aria-label="Reconciliation sources">
        <article>
          <Database size={21} />
          <div><span>Independent source 01</span><h2>Payer system of record</h2></div>
          <dl>
            <div><dt>Operator</dt><dd>{data?.sources.system_of_record.operator_id ?? 'loading'}</dd></div>
            <div><dt>Population</dt><dd>{data?.sources.system_of_record.record_count ?? '—'} records</dd></div>
            <div><dt>Signed root</dt><dd>{data ? short(data.sources.system_of_record.population_root) : 'loading'}</dd></div>
          </dl>
        </article>
        <div className={styles.joinMark} aria-hidden="true">
          <ArrowRight size={18} /><Fingerprint size={25} /><ArrowRight size={18} />
          <span>exact CAID + action digest</span>
        </div>
        <article>
          <FileKey2 size={21} />
          <div><span>Independent source 02</span><h2>Gate receipt population</h2></div>
          <dl>
            <div><dt>Operator</dt><dd>{data?.sources.receipt_population.operator_id ?? 'loading'}</dd></div>
            <div><dt>Population</dt><dd>{data?.sources.receipt_population.record_count ?? '—'} records</dd></div>
            <div><dt>Signed root</dt><dd>{data ? short(data.sources.receipt_population.population_root) : 'loading'}</dd></div>
          </dl>
        </article>
      </section>

      <section className={styles.verdict}>
        <div className={styles.verdictLabel}><ShieldAlert size={22} /><span>POPULATION EXCEPTION</span></div>
        <div className={styles.verdictCopy}>
          <h2>Effect observed. Receipt absent.</h2>
          <p>This record appears in the signed payer population and has no exact-action match in the independently signed Gate population.</p>
        </div>
        <dl>
          <div><dt>Source record</dt><dd>{data?.bypass.record_id ?? 'loading'}</dd></div>
          <div><dt>CAID</dt><dd>{data ? short(data.bypass.caid, 24, 10) : 'loading'}</dd></div>
          <div><dt>Action digest</dt><dd>{data ? short(data.bypass.action_digest) : 'loading'}</dd></div>
        </dl>
      </section>

      <section className={styles.results}>
        <div className={styles.resultsHeading}>
          <div>
            <span>CONSERVING COUNTS</span>
            <h2>Every supplied record receives a disposition.</h2>
          </div>
          <p>{data ? `${date(data.period.start)} — ${date(data.period.end)}` : 'Loading bounded period'}</p>
        </div>
        <div className={styles.countGrid}>
          {LABELS.map(([key, label]) => (
            <div key={key} className={key === 'effect_without_receipt' ? styles.countAlert : undefined}>
              <strong>{data?.summary[key] ?? '—'}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
        <div className={styles.reportLine}>
          <ScanSearch size={17} />
          <div><span>Signed report</span><code>{data ? short(data.report_hash, 28, 12) : 'generating'}</code></div>
          <div><span>Attestation</span><code>{data ? short(data.attestation_body_digest, 28, 12) : 'generating'}</code></div>
          <i><Check size={14} /> independent issuers</i>
        </div>
      </section>

      <section className={styles.boundary}>
        <AlertTriangle size={18} />
        <div>
          <strong>What this proves—and what it does not.</strong>
          <p>
            This reference run executes the real signing, verification, exact-action join, and
            attestation code over synthetic records. It proves reconciliation of the two supplied
            signed populations. It does not prove either source was complete, and it touches no
            production payer, patient record, or external effect system.
          </p>
        </div>
      </section>
    </main>
  );
}
