// SPDX-License-Identifier: Apache-2.0
'use client';

import { useRef, useState, type ChangeEvent } from 'react';
import {
  AGENT_SCAN_LIMITS, createAgentScanReport, classificationLabel,
  SYNTHETIC_AGENT_SCAN_SAMPLE, type AgentScanReport,
} from '@/lib/works/agent-scan';
import styles from './scan.module.css';

export function ScanActionResult({ action, classification }: AgentScanReport['results'][number]) {
  return <div className={styles.actionDetail}>
    <p className={classification.decision === 'gate' ? styles.consequential : styles.review}>{classificationLabel(classification)}</p>
    <h3>{action.name}</h3>
    {action.http_method && <p className={styles.route}>{action.http_method} {action.route_path}</p>}
    {action.description && <p className={styles.description}>{action.description}</p>}
    <p><strong>Why this result:</strong> {classification.reason}</p>
    <p className={styles.confidence}>Rule-match confidence: {classification.confidence}. This is confidence in the declaration match, not in actual behavior or safety.</p>
    {classification.receipt_required && <p className={styles.recommendation}>Review this action before execution and decide where authorization should be enforced. No Gate has been configured by this scan.</p>}
  </div>;
}

export default function AgentScanner() {
  const [input, setInput] = useState('');
  const [report, setReport] = useState<AgentScanReport | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [synthetic, setSynthetic] = useState(false);
  const generation = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);

  function replaceInput(text: string, example = false) {
    generation.current++;
    setInput(text); setReport(null); setError(''); setBusy(false); setSynthetic(example);
  }

  async function loadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    replaceInput('');
    const request = generation.current;
    if (file.size > AGENT_SCAN_LIMITS.bytes) {
      setError('The file is too large. Choose a JSON file no larger than 1 MiB.');
      event.target.value = '';
      return;
    }
    try {
      const text = await file.text();
      if (generation.current === request) replaceInput(text);
    } catch { if (generation.current === request) setError('The file could not be read. Try pasting its JSON instead.'); }
    if (fileInput.current) fileInput.current.value = '';
  }

  async function scan() {
    const request = ++generation.current;
    setBusy(true); setError(''); setReport(null);
    try {
      const result = await createAgentScanReport(input);
      if (generation.current === request) setReport(result);
    } catch (caught) {
      if (generation.current === request) setError(caught instanceof Error ? caught.message : 'The JSON could not be scanned.');
    } finally { if (generation.current === request) setBusy(false); }
  }

  function download() {
    if (!report) return;
    const artifact = { ...report, example: synthetic ? 'SYNTHETIC_EXAMPLE' : 'NOT_ASSERTED' };
    const url = URL.createObjectURL(new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url; link.download = 'emilia-declared-action-scan.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <main id="main-content" className={styles.page}>
      <header className={styles.hero}>
        <a className={styles.back} href="/works">← EMILIA Marketplace</a>
        <p className={styles.eyebrow}>Free tool · no account</p>
        <h1>What does your agent<br className={styles.desktopBreak} /> say it can do?</h1>
        <p className={styles.lead}>Inspect its declared tools before giving it a job. Find actions that may move money, change access or affect real systems, and see what still needs review.</p>
        <p className={styles.privacy}>Your input stays in this browser tab. This tool does not upload it, run your agent or publish findings.</p>
      </header>

      <section className={styles.workspace} aria-labelledby="input-heading">
        <div className={styles.editor}>
          <h2 id="input-heading">Start with the tool declarations.</h2>
          <p>MCP tools/list, an actions array or OpenAPI JSON. Up to 1 MiB and 500 actions. No API keys needed.</p>
          <div className={styles.toolbar}>
            <label className={styles.fileButton}>Choose JSON file
              <input ref={fileInput} type="file" accept=".json,application/json" onChange={loadFile} aria-label="Choose JSON file" />
            </label>
            <button type="button" className={styles.textButton} onClick={() => replaceInput(SYNTHETIC_AGENT_SCAN_SAMPLE, true)}>Try a synthetic example</button>
          </div>
          <label className={styles.inputLabel} htmlFor="agent-json">Or paste JSON</label>
          <textarea id="agent-json" value={input} onChange={event => replaceInput(event.target.value)} maxLength={AGENT_SCAN_LIMITS.bytes + 1} placeholder={'{ "actions": [{ "name": "refund_payment" }] }'} spellCheck={false} autoComplete="off" autoCorrect="off" autoCapitalize="off" data-1p-ignore data-lpignore="true" />
          {synthetic && <p className={styles.notice}>Synthetic example. These tools do not belong to a real agent. The refund tool deliberately has a conflicting read-only hint.</p>}
          <div className={styles.toolbar}>
            <button type="button" className={styles.primaryButton} onClick={scan} disabled={busy || !input.trim()}>{busy ? 'Inspecting declarations…' : 'Scan declarations, free'}</button>
            <button type="button" className={styles.textButton} onClick={() => replaceInput('')}>Clear</button>
          </div>
          {error && <p className={styles.error} role="alert">{error}</p>}
          <details className={styles.formats}>
            <summary>Supported formats and limits</summary>
            <p>MCP: <code>{'{ "tools": [...] }'}</code> or a JSON-RPC response containing <code>result.tools</code>. Plain actions: an array of names or objects with a name, description and optional annotations, or <code>{'{ "actions": [...] }'}</code>. OpenAPI: a 3.x or Swagger 2.0 JSON document with paths.</p>
            <p>One declaration format per scan. Duplicate names or JSON keys, reserved object keys and bidirectional control characters are rejected. Maximum nesting is 32 levels. References and additional MCP pages are not fetched. This is not a schema validator.</p>
          </details>
        </div>
        <aside className={styles.scope}>
          <p className={styles.eyebrow}>Know what this tells you</p>
          <h2>Declarations are a starting point. Not proof.</h2>
          <p>A tool named “read account” may still change it. This scan uses the existing EMILIA action classifier to flag declared signals, including conflicts between descriptions and read-only hints.</p>
          <p>It cannot tell you what code actually runs, which credentials an agent holds or whether every consequential call passes through a Gate.</p>
          <p className={styles.scopeNote}>No safety score. No certification. No agent execution.</p>
        </aside>
      </section>

      <section className={styles.results} aria-live="polite" aria-busy={busy}>
        {report && <>
          <div className={styles.resultHeading}>
            <div><p className={styles.eyebrow}>{synthetic ? 'Synthetic example report' : 'Declaration report'}</p><h2>{report.summary.declared_actions} declared actions. Actual behavior unknown.</h2></div>
            <button type="button" className={styles.secondaryButton} onClick={download}>Download JSON report</button>
          </div>
          <p className={styles.downloadNote}>The download contains declaration text and a SHA-256 fingerprint of the exact input. A matching fingerprint identifies the same input bytes, not a verified agent.</p>
          <dl className={styles.counts}>
            <div><dt>Potential consequential</dt><dd>{report.summary.potential_consequential}</dd></div>
            <div><dt>Unknown · review needed</dt><dd>{report.summary.needs_review}</dd></div>
            <div><dt>Read-like · not verified</dt><dd>{report.summary.read_like_unverified}</dd></div>
          </dl>
          {report.results.length === 0 && <p className={styles.notice}>No inline actions were found. This does not mean the agent has no capabilities. Review the scope gaps below.</p>}
          <ol className={styles.actionList}>
            {report.results.map(({ action, classification }, index) => <li key={action.name}>
              <div className={styles.actionNumber}>{String(index + 1).padStart(2, '0')}</div>
              <ScanActionResult action={action} classification={classification} />
            </li>)}
          </ol>
          <div className={styles.blindSpots}>
            <h3>What remains unknown</h3>
            <ul>{report.blind_spots.map(spot => <li key={spot}>{spot}</li>)}</ul>
            <p className={styles.digest}><strong>Input SHA-256</strong><br />{report.source.input_sha256}</p>
          </div>
        </>}
      </section>

      <section className={styles.next} aria-labelledby="next-heading">
        <h2 id="next-heading">Give the agent a clear next step.</h2>
        <div className={styles.nextLinks}>
          <div><h3>Share what you have built.</h3><p>A listing is separate from this private scan. Choose what you want to publish.</p><a href="/works/join">List your agent →</a><a href="/works/claim">Claim an Authority Record →</a></div>
          <div><h3>Review a specific deployment.</h3><p>Qualification checks a defined scope. Gate deployment is a separate step for enforcing authority on covered calls.</p><a href="/works/qualification">Explore scoped qualification →</a><a href="/works/gate">Explore Gate deployment →</a></div>
        </div>
      </section>
    </main>
  );
}
