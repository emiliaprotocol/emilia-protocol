// SPDX-License-Identifier: Apache-2.0
'use client';

import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import type { MarketplaceQualificationResponse } from '@/lib/works/marketplace-qualification';
import { isQualificationResponseProjection, qualificationDisplayDeadline, qualificationWindowRemaining, type QualificationDisplayWindow } from './display-window';
import styles from './qualification.module.css';

const MAX_BYTES = 256 * 1024;
const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

const DIMENSIONS = [
  ['verification', 'Evidence signatures'], ['acceptance', 'Trusted sources'],
  ['candidate_match', 'Exact candidate'], ['assignment_scope', 'Assignment'],
  ['currentness', 'Observed status'], ['campaign_graph', 'Evidence graph'],
] as const;

const reasonText: Record<string, string> = {
  qualification_not_configured: 'Hosted verification is not configured. No qualification result has been issued.',
  qualification_scope_unavailable: 'This test scope is not available from the hosted verifier. Ask the operator for your registered scope ID.',
  qualification_configuration_invalid: 'The hosted verifier cannot use its current configuration. No result can be issued.',
  qualification_rate_limit_unavailable: 'The request limit service is unavailable. Verification is paused.',
  rate_limited: 'Too many requests. Wait a minute and try again.',
  invalid_qualification_request: 'The request does not match the evidence format. Supply the six evidence fields only, not a verdict or status observation.',
};

export default function QualificationForm() {
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [scopeId, setScopeId] = useState('');
  const [evidence, setEvidence] = useState('');
  const [consent, setConsent] = useState(false);
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState('');
  const [response, setResponse] = useState<MarketplaceQualificationResponse | null>(null);
  const [remaining, setRemaining] = useState(0);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const displayWindow = useRef<QualificationDisplayWindow | null>(null);

  function invalidate() {
    generation.current += 1;
    controller.current?.abort();
    controller.current = null;
    displayWindow.current = null;
    setResponse(null);
    setRemaining(0);
    setPending(false);
    setNotice('');
  }

  useEffect(() => {
    function expire(message: string) {
      if (displayWindow.current === null) return;
      displayWindow.current = null;
      setRemaining(0);
      setResponse(null);
      setNotice(message);
    }
    const timer = window.setInterval(() => {
      if (displayWindow.current === null) return;
      const seconds = qualificationWindowRemaining(displayWindow.current, performance.now(), Date.now());
      setRemaining(seconds);
      if (!seconds) expire('This result has expired. Check the evidence again before relying on it.');
    }, 250);
    function visibilityChanged() {
      // Background timers and suspended devices cannot maintain a reliable
      // current display. Discard it instead of extending its lifetime.
      if (document.visibilityState === 'hidden') {
        generation.current += 1;
        controller.current?.abort();
        controller.current = null;
        setPending(false);
        expire('This check was closed while the page was hidden. Check again for a fresh result.');
      }
    }
    document.addEventListener('visibilitychange', visibilityChanged);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', visibilityChanged);
      generation.current += 1;
      controller.current?.abort();
    };
  }, []);

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready) return;
    invalidate();
    if (!consent) { setNotice('Confirm you are allowed to send this evidence before continuing.'); return; }
    if (!/^[a-z0-9][a-z0-9._-]{0,95}$/.test(scopeId)) {
      setNotice('Enter the registered scope ID supplied by the verifier operator.'); return;
    }
    // Do not parse and stringify the evidence here: that would silently erase
    // duplicate JSON keys before the server's strict parser could reject them.
    const body = `{"scope_id":${JSON.stringify(scopeId)},"evidence":${evidence}}`;
    if (new TextEncoder().encode(body).length > MAX_BYTES) {
      setNotice('The complete request must be 256 KiB or smaller. Nothing was sent.'); return;
    }
    try { JSON.parse(body); } catch { setNotice('Paste a valid evidence JSON object. Nothing was sent.'); return; }
    const current = generation.current;
    const abort = new AbortController();
    controller.current = abort;
    const startedAt = performance.now();
    const wallStartedAt = Date.now();
    setPending(true);
    try {
      const result = await fetch('/api/works/qualification', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body, signal: abort.signal, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      const data: unknown = await result.json();
      if (current !== generation.current || abort.signal.aborted) return;
      if (!isQualificationResponseProjection(data)) {
        throw new Error('unexpected_response');
      }
      if (data.status === 'QUALIFIED') {
        const display = data.display;
        if (!result.ok || data.result?.decision !== 'QUALIFIED' || !display
          || display.scope_id !== scopeId || display.checked_at !== data.checked_at) throw new Error('invalid_projection');
        const end = qualificationDisplayDeadline(display.checked_at, display.expires_at, startedAt, performance.now());
        if (end === null) {
          setNotice('The verification window closed before the response arrived. Check again.'); return;
        }
        const window = { deadline: end, monotonicStartedAt: startedAt, wallStartedAt };
        const seconds = qualificationWindowRemaining(window, performance.now(), Date.now());
        if (!seconds) { setNotice('The verification window closed before the response arrived. Check again.'); return; }
        displayWindow.current = window;
        setRemaining(seconds);
      }
      setResponse(data);
    } catch {
      if (current === generation.current && !abort.signal.aborted) {
        setNotice('Verification could not finish. No qualification result is available. Please try again.');
      }
    } finally {
      if (current === generation.current) { setPending(false); controller.current = null; }
    }
  }

  return <section className={styles.verify} aria-labelledby="qualification-check-title">
    <h2 id="qualification-check-title">Have signed evidence? Check it here.</h2>
    <p>You need a registered test scope and its signed evidence bundle. The hosted verifier supplies the trusted keys and status observation. You cannot supply your own trust settings.</p>
    <form method="post" onSubmit={verify} className={styles.form}>
      <noscript><p>JavaScript is required to check evidence securely. No evidence is sent before the form is ready.</p></noscript>
      <fieldset disabled={!ready} className={styles.form} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <label htmlFor="qualification-scope">Registered scope ID</label>
      <input id="qualification-scope" autoComplete="off" spellCheck={false} value={scopeId} maxLength={96}
        onChange={(event) => { invalidate(); setScopeId(event.target.value); }} placeholder="Your operator-provided scope ID" required />
      <label htmlFor="qualification-evidence">Evidence bundle JSON</label>
      <p id="evidence-help" className={styles.help}>Include candidate_manifest, campaigns, test_results, agent_evaluation_evidence, qualification_statement and runtime_measurement. Do not include status observations, private keys, credentials or customer data.</p>
      <textarea id="qualification-evidence" aria-describedby="evidence-help" value={evidence}
        onChange={(event) => { invalidate(); setEvidence(event.target.value); setConsent(false); }}
        rows={10} spellCheck={false} autoComplete="off" placeholder="Paste the six-field evidence object" required />
      <label className={styles.consent}><input type="checkbox" checked={consent}
        onChange={(event) => { invalidate(); setConsent(event.target.checked); }} />
        <span>I am allowed to send this evidence to EMILIA for this check. I understand it leaves my browser when I click Verify.</span>
      </label>
      <p className={styles.help}>This check does not publish a listing, save a public badge or authorize an agent to act.</p>
      <div className={styles.actions}>
        <button type="submit" disabled={!ready || pending || !consent}>{pending ? 'Verifying…' : 'Verify evidence'}</button>
        <button type="button" className={styles.secondary} onClick={() => { invalidate(); setScopeId(''); setEvidence(''); setConsent(false); }}>Clear evidence</button>
      </div>
      </fieldset>
    </form>
    <div aria-live="polite" aria-atomic="true">
      {notice ? <p className={styles.notice} role="status">{notice}</p> : null}
      {response ? <QualificationResult response={response} remaining={remaining} /> : null}
    </div>
  </section>;
}

export function QualificationResult({ response, remaining }: { response: MarketplaceQualificationResponse; remaining: number }) {
  const qualified = response.status === 'QUALIFIED' && response.result?.decision === 'QUALIFIED'
    && response.display !== null && remaining > 0;
  const title = qualified ? 'Qualified for this test scope'
    : response.status === 'NOT_QUALIFIED' ? 'Not qualified for this test scope'
      : response.status === 'INDETERMINATE' ? 'The evidence does not establish qualification'
        : 'No qualification result available';
  return <section className={styles.result} aria-labelledby="qualification-result-title">
    <p className={styles.eyebrow}>Verification result · not permission to act</p>
    <h3 id="qualification-result-title">{title}</h3>
    {qualified && response.display ? <>
      <p><strong>{response.display.scope_label}</strong></p>
      <p className={styles.validity}>Verified at {response.display.checked_at}. This display closes in {remaining} seconds. Status is current only as observed at {response.display.status_observed_at}; it can change after that observation.</p>
      <dl className={styles.pins}>
        <div><dt>Candidate</dt><dd>{response.display.candidate_manifest_digest}</dd></div>
        <div><dt>Assignment</dt><dd>{response.display.assignment_digest}</dd></div>
        <div><dt>Test policy</dt><dd>{response.display.qualification_policy_digest}</dd></div>
        <div><dt>Protected request</dt><dd>{response.display.protected_request_digest}</dd></div>
        <div><dt>Signed statement</dt><dd>{response.display.qualification_statement_digest}</dd></div>
        <div><dt>Observed status head</dt><dd>{response.display.qualification_status_head_digest}</dd></div>
      </dl>
    </> : <p>{Object.hasOwn(reasonText, response.reason) ? reasonText[response.reason] : 'The verifier did not establish a current qualification for this exact candidate, assignment and policy. Review the result below with your verifier operator.'}</p>}
    {response.result ? <dl className={styles.dimensions}>{DIMENSIONS.map(([key, label]) =>
      <div key={key}><dt>{label}</dt><dd>{response.result![key].replaceAll('_', ' ')}</dd></div>)}</dl> : null}
    {!qualified ? <p className={styles.help}>Result code: <code>{response.reason}</code></p> : null}
    <p className={styles.boundary}>This is not a safety certificate, compliance approval or performance promise. Gate deployment and authorization are separate. Payment cannot change the result.</p>
  </section>;
}
