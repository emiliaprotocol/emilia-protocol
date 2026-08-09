'use client';
// SPDX-License-Identifier: Apache-2.0
//
// Watch It Refuse — client experience. Calls /api/refuse/evaluate (the real
// evaluation) and plays the returned decision back as a staged sequence. All
// verdicts, codes, and digests shown here come from the API response; this
// component only paces the reveal — it never invents a result.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import styles from './refuse.module.css';

type Reason = { code: string | null; plain: string };

type Decision = {
  allow: boolean;
  status: number | null;
  reason: Reason;
  challenge: Record<string, unknown> | null;
  receipt_required_header: string | null;
  evidence_hash: string | null;
};

type Evaluation = {
  demo: boolean;
  notice: string;
  input: { text: string };
  classification: {
    archetype: string;
    label: string;
    action_type: string;
    risk_class: string | null;
    summary: string | null;
  };
  identity: {
    caid: string | null;
    digest: string | null;
    suite: string;
    refusals: Reason[];
    action_object: Record<string, unknown>;
  };
  requirements: {
    receipt_required: boolean;
    assurance_class: string | null;
    max_age_sec: number;
    one_time_consumption: boolean;
    consumption_scope: string;
    execution_binding_fields: string[];
    why: string | null;
  };
  evidence_check: {
    verdict: string;
    verdict_plain: string;
    requirement: string | null;
    reasons: string[];
    replay_digest: string;
  };
  refusal: Decision;
  approval?: {
    ceremony_notice: string;
    receipt: Record<string, unknown>;
    stages: {
      verified: { ok: boolean; reason: Reason; signer: string | null; receipt_id: string | null };
      match: {
        ok: boolean;
        caid: { valid: boolean; reasons: Reason[] };
        execution_binding: Record<string, unknown> & { ok?: boolean };
      };
      satisfied: {
        ok: boolean;
        assurance: { ok: boolean; have: string; need: string; reason: Reason };
        admissibility: { verdict: string; verdict_plain: string };
      };
      authorized: Decision;
      consumed: { consumed: boolean; replay_attempt: Decision };
    };
  };
};

const EXAMPLES = [
  'Wire $40,000 to this account',
  'Delete the prod database',
  'Email the board my resignation',
  'Deploy this build to production',
  'Unlock the server-room door',
];

const REFUSAL_ACTS = 5;
const LIFECYCLE_ACTS = 6;
const ACT_INTERVAL_MS = 950;

function shortDigest(value: string | null | undefined): string {
  if (!value) return '—';
  const hex = value.replace(/^sha256:/, '');
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`;
}

function StatusTag({ state, children }: { state: 'ok' | 'fail' | 'wait' | 'none'; children: React.ReactNode }) {
  return <span className={`${styles.tag} ${styles[`tag_${state}`]}`}>{children}</span>;
}

export default function WatchItRefuseExperience() {
  const [text, setText] = useState('');
  const [phase, setPhase] = useState<'idle' | 'evaluating' | 'refusal' | 'ceremony' | 'approving' | 'lifecycle'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<Evaluation | null>(null);
  const [approved, setApproved] = useState<Evaluation | null>(null);
  const [step, setStep] = useState(0);
  const [lifecycleStep, setLifecycleStep] = useState(0);
  const [copied, setCopied] = useState(false);
  const stageRef = useRef<HTMLDivElement | null>(null);

  // Staged reveal pacing for the refusal play-by-play.
  useEffect(() => {
    if (phase !== 'refusal' || step >= REFUSAL_ACTS) return;
    const timer = setTimeout(() => setStep((s) => s + 1), ACT_INTERVAL_MS);
    return () => clearTimeout(timer);
  }, [phase, step]);

  // Staged reveal pacing for the lifecycle play-by-play.
  useEffect(() => {
    if (phase !== 'lifecycle' || lifecycleStep >= LIFECYCLE_ACTS) return;
    const timer = setTimeout(() => setLifecycleStep((s) => s + 1), ACT_INTERVAL_MS);
    return () => clearTimeout(timer);
  }, [phase, lifecycleStep]);

  const evaluate = useCallback(async (input: string) => {
    const clean = input.trim();
    if (clean.length < 3) {
      setError('Describe the action in a few words first.');
      return;
    }
    setError(null);
    setApproved(null);
    setCopied(false);
    setStep(0);
    setLifecycleStep(0);
    setPhase('evaluating');
    try {
      const res = await fetch('/api/refuse/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: clean }),
      });
      const body = await res.json();
      if (!res.ok) {
        setPhase('idle');
        setError(typeof body?.detail === 'string' ? body.detail : 'Evaluation failed. Try again.');
        return;
      }
      setData(body as Evaluation);
      setPhase('refusal');
      setStep(1);
      requestAnimationFrame(() => stageRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    } catch {
      setPhase('idle');
      setError('Evaluation failed. Try again.');
    }
  }, []);

  const runCeremony = useCallback(async () => {
    if (!data) return;
    setPhase('approving');
    try {
      const res = await fetch('/api/refuse/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: data.input.text, approve: true }),
      });
      const body = await res.json();
      if (!res.ok || !body?.approval) {
        setPhase('refusal');
        setError('Demo approval failed. Try again.');
        return;
      }
      setApproved(body as Evaluation);
      setLifecycleStep(1);
      setPhase('lifecycle');
    } catch {
      setPhase('refusal');
      setError('Demo approval failed. Try again.');
    }
  }, [data]);

  const reset = useCallback(() => {
    setPhase('idle');
    setData(null);
    setApproved(null);
    setStep(0);
    setLifecycleStep(0);
    setError(null);
    setText('');
    setCopied(false);
    if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const finalVerdict: 'refused' | 'authorized' | null = useMemo(() => {
    if (approved?.approval && lifecycleStep >= LIFECYCLE_ACTS) {
      return approved.approval.stages.authorized.allow && approved.approval.stages.consumed.consumed
        ? 'authorized'
        : 'refused';
    }
    if (data && phase === 'refusal' && step >= REFUSAL_ACTS) return 'refused';
    return null;
  }, [approved, data, phase, step, lifecycleStep]);

  const shareUrl = useMemo(() => {
    if (!data || typeof window === 'undefined') return '';
    const params = new URLSearchParams({ q: data.input.text });
    return `${window.location.origin}/refuse?${params.toString()}`;
  }, [data]);

  const cardUrl = useMemo(() => {
    if (!data) return '';
    const params = new URLSearchParams({ t: data.input.text });
    return `/api/refuse/og?${params.toString()}`;
  }, [data]);

  const caption = useMemo(() => {
    if (!data) return '';
    return finalVerdict === 'authorized'
      ? `I ran a synthetic EMILIA demo for “${data.input.text}”. The no-evidence attempt was refused; a demo receipt was admitted once and refused on immediate replay inside the same evaluation. No action executed.`
      : `I ran a synthetic EMILIA demo for “${data.input.text}”. The no-evidence attempt was refused. No action executed.`;
  }, [data, finalVerdict]);

  const copyShare = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(`${caption}\n${shareUrl}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  }, [caption, shareUrl]);

  const requirementRows = data ? [
    {
      label: 'Human authorization receipt',
      detail: `A signed EP-RECEIPT-v1 bound to this exact action (${data.classification.action_type})`,
    },
    {
      label: 'Assurance tier',
      detail: `${data.requirements.assurance_class ?? 'unknown'}, the ceremony class the policy demands`,
    },
    {
      label: 'Exact-action binding',
      detail: `Material fields pinned: ${data.requirements.execution_binding_fields.join(', ') || '—'}`,
    },
    {
      label: 'Freshness',
      detail: `Issued within the last ${data.requirements.max_age_sec} seconds`,
    },
    {
      label: 'One-time consumption',
      detail: 'For this demo, unused inside the current in-process evaluation; production requires durable atomic storage',
    },
  ] : [];

  const stages = approved?.approval?.stages ?? null;

  return (
    <main className={styles.page}>
      {/* ── Hero ─────────────────────────────────────────────── */}
      <section className={styles.hero}>
        <div className={styles.heroCopy}>
          <p className={styles.eyebrow}>Watch It Refuse. Live Demo</p>
          <h1 className={styles.headline}>
            Tell it to do<br />something<br /><span className={styles.headlineAccent}>irreversible.</span>
          </h1>
          <p className={styles.sub}>
            Type any consequential agent action in your own words. The real EMILIA
            authorization evaluation runs live and refuses it, with typed,
            verifiable reasons. Then you can run a synthetic approval lifecycle.
          </p>
          <p className={styles.noEffect}>
            No action is performed. This demonstrates the authorization decision layer only.
          </p>
        </div>
        <div className={styles.heroArt} aria-hidden="true">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/hero/agent-action-stamp.png" alt="" />
        </div>
      </section>

      {/* ── Input ────────────────────────────────────────────── */}
      <section className={styles.console}>
        <form
          className={styles.inputRow}
          onSubmit={(event) => { event.preventDefault(); void evaluate(text); }}
        >
          <label className={styles.inputLabel} htmlFor="wir-action">The agent is told to</label>
          <div className={styles.inputShell}>
            <input
              id="wir-action"
              className={styles.input}
              value={text}
              maxLength={280}
              placeholder="wire $40,000 to this account"
              onChange={(event) => setText(event.target.value)}
              disabled={phase === 'evaluating'}
            />
            <button className={styles.runButton} type="submit" disabled={phase === 'evaluating'}>
              {phase === 'evaluating' ? 'Evaluating…' : 'Run the evaluation'}
            </button>
          </div>
        </form>
        <div className={styles.examples}>
          {EXAMPLES.map((example) => (
            <button
              key={example}
              type="button"
              className={styles.example}
              onClick={() => { setText(example); void evaluate(example); }}
              disabled={phase === 'evaluating'}
            >
              {example}
            </button>
          ))}
        </div>
        {error ? <p className={styles.error} role="alert">{error}</p> : null}
      </section>

      {/* ── The refusal play-by-play ─────────────────────────── */}
      {data ? (
        <section className={styles.stage} ref={stageRef} aria-live="polite">
          {/* Act 1 — proposed */}
          <div className={`${styles.act} ${step >= 1 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>01</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Action proposed</p>
              <p className={styles.proposedText}>“{data.input.text}”</p>
              <p className={styles.actMeta}>
                Classified: <strong>{data.classification.label}</strong>
                {data.classification.risk_class ? <> · registry risk class <code>{data.classification.risk_class}</code></> : null}
              </p>
            </div>
          </div>

          {/* Act 2 — canonical identity */}
          <div className={`${styles.act} ${step >= 2 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>02</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Canonical action identity computed</p>
              {data.identity.caid ? (
                <>
                  <p className={styles.caid}><code>{data.identity.caid}</code></p>
                  <p className={styles.actMeta}>
                    Registry type <code>{data.classification.action_type}</code> · suite{' '}
                    <code>{data.identity.suite}</code> · digest <code>{shortDigest(data.identity.digest)}</code>.
                    This identifier commits to the exact typed content of the action. Approving this means approving exactly this.
                  </p>
                </>
              ) : (
                <>
                  <StatusTag state="fail">No identifier issued</StatusTag>
                  {data.identity.refusals.map((refusal) => (
                    <p key={refusal.code ?? refusal.plain} className={styles.actMeta}>
                      <code>{refusal.code}</code>: {refusal.plain}
                    </p>
                  ))}
                </>
              )}
            </div>
          </div>

          {/* Act 3 — requirements */}
          <div className={`${styles.act} ${step >= 3 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>03</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Evidence this action requires</p>
              <ul className={styles.reqList}>
                {requirementRows.map((row) => (
                  <li key={row.label}>
                    <span className={styles.reqLabel}>{row.label}</span>
                    <span className={styles.reqDetail}>{row.detail}</span>
                  </li>
                ))}
              </ul>
              {data.requirements.why ? <p className={styles.actMeta}>{data.requirements.why}</p> : null}
            </div>
          </div>

          {/* Act 4 — evidence check */}
          <div className={`${styles.act} ${step >= 4 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>04</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Evidence check</p>
              <ul className={styles.reqList}>
                {requirementRows.map((row) => (
                  <li key={row.label}>
                    <span className={styles.reqLabel}>{row.label}</span>
                    <StatusTag state="none">None presented</StatusTag>
                  </li>
                ))}
              </ul>
              <p className={styles.actMeta}>
                Sufficiency verdict: <code>{data.evidence_check.verdict}</code>. {data.evidence_check.verdict_plain}{' '}
                <span className={styles.dim}>(replayable: {shortDigest(data.evidence_check.replay_digest)})</span>
              </p>
            </div>
          </div>

          {/* Act 5 — verdict */}
          <div className={`${styles.act} ${step >= 5 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>05</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Decision</p>
              <div className={`${styles.verdictCard} ${styles.verdictRefused}`}>
                <p className={styles.verdictWord}>Refused</p>
                <p className={styles.verdictCode}>
                  HTTP {data.refusal.status ?? 428} · <code>{data.refusal.reason.code}</code>
                </p>
                <p className={styles.verdictPlain}>{data.refusal.reason.plain}</p>
              </div>
            </div>
          </div>

          {/* Post-verdict rail */}
          {phase !== 'lifecycle' && step >= REFUSAL_ACTS ? (
            <div className={styles.followUp}>
              <div className={styles.ceremonyCard}>
                <p className={styles.actKicker}>Want it to go through?</p>
                <p className={styles.ceremonyLead}>
                  Approve it yourself. A demo ceremony mints a receipt under the{' '}
                  <code>demo.watch-it-refuse</code> issuer, and the same evaluation runs again:
                  verified, matched, satisfied, authorized, consumed.
                </p>
                <p className={styles.ceremonyNotice}>
                  Demo ceremony: an explicit click-through earning the software assurance tier only.
                  Production policies pin device-biometric (class_a) or quorum ceremonies.
                  The receipt is demo-marked and authorizes nothing real.
                </p>
                <button
                  type="button"
                  className={styles.approveButton}
                  onClick={() => void runCeremony()}
                  disabled={phase === 'approving'}
                >
                  {phase === 'approving' ? 'Minting demo receipt…' : 'Approve it yourself: demo ceremony'}
                </button>
              </div>
            </div>
          ) : null}
        </section>
      ) : null}

      {/* ── The lifecycle play-by-play ───────────────────────── */}
      {stages ? (
        <section className={styles.stage} aria-live="polite">
          <p className={styles.lifecycleTitle}>Second run, with your demo receipt</p>

          <div className={`${styles.act} ${lifecycleStep >= 1 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>V</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Verified</p>
              <StatusTag state={stages.verified.ok ? 'ok' : 'fail'}>
                {stages.verified.ok ? 'Signature verifies' : stages.verified.reason.code ?? 'failed'}
              </StatusTag>
              <p className={styles.actMeta}>
                {stages.verified.ok
                  ? <>Ed25519 signature over the canonical payload verifies under the pinned demo issuer key <code>{stages.verified.signer}</code>. Receipt <code>{stages.verified.receipt_id}</code>.</>
                  : stages.verified.reason.plain}
              </p>
            </div>
          </div>

          <div className={`${styles.act} ${lifecycleStep >= 2 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>M</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Match</p>
              <StatusTag state={stages.match.ok ? 'ok' : 'fail'}>
                {stages.match.ok ? 'Exact action match' : 'mismatch'}
              </StatusTag>
              <p className={styles.actMeta}>
                The receipt recomputes to the same canonical identifier{' '}
                <code>{shortDigest(data?.identity.caid ?? null)}</code> and every pinned material
                field in the signed claim equals the observed action. Approving “roughly this” is not possible.
              </p>
            </div>
          </div>

          <div className={`${styles.act} ${lifecycleStep >= 3 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>S</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Satisfied</p>
              <StatusTag state={stages.satisfied.ok ? 'ok' : 'fail'}>
                {stages.satisfied.ok ? `Tier ${stages.satisfied.assurance.have} meets ${stages.satisfied.assurance.need}` : 'not satisfied'}
              </StatusTag>
              <p className={styles.actMeta}>
                {stages.satisfied.assurance.reason.plain} Sufficiency verdict:{' '}
                <code>{stages.satisfied.admissibility.verdict}</code>: {stages.satisfied.admissibility.verdict_plain}
              </p>
            </div>
          </div>

          <div className={`${styles.act} ${lifecycleStep >= 4 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>A</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Demo admission</p>
              <StatusTag state={stages.authorized.allow ? 'ok' : 'fail'}>
                {stages.authorized.allow ? 'Admitted in this evaluation' : stages.authorized.reason.code ?? 'refused'}
              </StatusTag>
              <p className={styles.actMeta}>
                {stages.authorized.allow
                  ? <>The in-process demo gate allows this exact action and appends the decision to its demo evidence chain <span className={styles.dim}>({shortDigest(stages.authorized.evidence_hash)})</span>. Nothing executes, and this is not a durable production admission.</>
                  : stages.authorized.reason.plain}
              </p>
            </div>
          </div>

          <div className={`${styles.act} ${lifecycleStep >= 5 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>C</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Demo state consumed</p>
              <StatusTag state={stages.consumed.consumed ? 'ok' : 'fail'}>
                {stages.consumed.consumed ? 'Immediate replay fenced' : 'not consumed'}
              </StatusTag>
              <p className={styles.actMeta}>
                The same receipt is consumed inside this ephemeral evaluation and its immediate replay is refused. No action executes; durable cross-request consumption is outside this demo.
              </p>
            </div>
          </div>

          <div className={`${styles.act} ${lifecycleStep >= 6 ? styles.actVisible : ''}`}>
            <div className={styles.actIndex}>R</div>
            <div className={styles.actBody}>
              <p className={styles.actKicker}>Replay attempt: same receipt, presented again</p>
              <div className={`${styles.verdictCard} ${styles.verdictRefused}`}>
                <p className={styles.verdictWordSmall}>Refused</p>
                <p className={styles.verdictCode}>
                  HTTP {stages.consumed.replay_attempt.status ?? 428} ·{' '}
                  <code>{stages.consumed.replay_attempt.reason.code}</code>
                </p>
                <p className={styles.verdictPlain}>{stages.consumed.replay_attempt.reason.plain}</p>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      {/* ── Share card ───────────────────────────────────────── */}
      {data && finalVerdict ? (
        <section className={styles.shareSection}>
          <p className={styles.actKicker}>Share the initial refusal</p>
          <p className={styles.shareCaption}>{caption}</p>
          <div className={styles.shareCardShell}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img className={styles.shareCard} src={cardUrl} alt={`Share card: ${caption}`} />
          </div>
          <div className={styles.shareActions}>
            <button type="button" className={styles.approveButton} onClick={() => void copyShare()}>
              {copied ? 'Copied' : 'Copy caption + link'}
            </button>
            <a className={styles.shareDownload} href={cardUrl} download="watch-it-refuse.png">
              Download the card
            </a>
            <button type="button" className={styles.resetButton} onClick={reset}>
              Run another action
            </button>
          </div>
        </section>
      ) : null}

      {/* ── Raw evidence ─────────────────────────────────────── */}
      {data ? (
        <section className={styles.rawSection}>
          <details className={styles.raw}>
            <summary>Raw evidence: the full evaluation record</summary>
            <p className={styles.rawNote}>
              Everything above renders this record. Demo artifacts carry{' '}
              <code>&quot;demo&quot;: true</code> and the <code>demo.watch-it-refuse</code> issuer id.
            </p>
            <pre>{JSON.stringify(approved ?? data, null, 2)}</pre>
          </details>
          <p className={styles.footNotice}>
            No action is performed. This demonstrates the authorization decision layer only.
          </p>
        </section>
      ) : null}
    </main>
  );
}
