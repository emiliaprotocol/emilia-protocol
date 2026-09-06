// SPDX-License-Identifier: Apache-2.0
'use client';

import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import {
  AGENT_SCAN_LIMITS, createAgentScanReport, classificationLabel,
  SYNTHETIC_AGENT_SCAN_SAMPLE, type AgentScanReport,
} from '@/lib/works/agent-scan';
import styles from './scan.module.css';

export type ScanFilter = 'all' | 'consequential' | 'review' | 'read_like';

const decisionPriority = { gate: 0, review_fail_closed: 1, pass_through: 2 } as const;
const filterDecision = { consequential: 'gate', review: 'review_fail_closed', read_like: 'pass_through' } as const;

export function visibleScanResults(results: AgentScanReport['results'], filter: ScanFilter) {
  return results
    .filter(({ classification }) => filter === 'all' || classification.decision === filterDecision[filter])
    .sort((a, b) => decisionPriority[a.classification.decision] - decisionPriority[b.classification.decision]);
}

export function ScanReportResults({ report, filter, onFilterChange }: {
  report: AgentScanReport;
  filter: ScanFilter;
  onFilterChange: (filter: ScanFilter) => void;
}) {
  const summary = report.summary;
  const visible = visibleScanResults(report.results, filter);
  const filters: { value: ScanFilter; label: string; count: number }[] = [
    { value: 'all', label: 'All', count: summary.declared_actions },
    { value: 'consequential', label: 'Consequential', count: summary.potential_consequential },
    { value: 'review', label: 'Needs review', count: summary.needs_review },
    { value: 'read_like', label: 'Read-like', count: summary.read_like_unverified },
  ];

  return <>
    <p className={styles.executiveSummary}>
      {summary.potential_consequential > 0
        ? `Start with the ${summary.potential_consequential} declared ${summary.potential_consequential === 1 ? 'action that may affect a real system' : 'actions that may affect real systems'}. Decide the limits and who can authorize each one before connecting real credentials.`
        : summary.needs_review > 0
          ? `The purpose of ${summary.needs_review} declared ${summary.needs_review === 1 ? 'action is' : 'actions is'} unclear. Review what the code can do before delegating a job.`
          : summary.declared_actions > 0
            ? 'Only read-like declarations were found. Check the implementation and credentials before relying on that description; actual behavior remains unknown.'
            : 'No inline actions were found. This does not mean the agent has no capabilities. Review the scope gaps below.'}
    </p>
    <dl className={styles.counts}>
      <div><dt>Potential consequential</dt><dd>{summary.potential_consequential}</dd></div>
      <div><dt>Unknown · review needed</dt><dd>{summary.needs_review}</dd></div>
      <div><dt>Read-like · not verified</dt><dd>{summary.read_like_unverified}</dd></div>
    </dl>
    <div className={styles.filters} role="group" aria-label="Filter declared actions">
      {filters.map(({ value, label, count }) => <button key={value} type="button" aria-label={`${label}: ${count} declared actions`} aria-pressed={filter === value} aria-controls="scan-action-results" onClick={() => onFilterChange(value)}>
        {label}<span className={styles.filterCount}>{count}</span>
      </button>)}
    </div>
    <p className={styles.resultStatus} role="status">Showing {visible.length} of {summary.declared_actions} declared actions. {filter === 'all' ? 'Potential consequential actions first.' : filter === 'read_like' ? 'Read-like does not mean verified or safe.' : 'The download still includes every result.'}</p>
    <ol id="scan-action-results" className={styles.actionList}>
      {visible.map(({ action, classification }) => <li key={action.name}>
        <ScanActionResult action={action} classification={classification} />
      </li>)}
    </ol>
    {visible.length === 0 && summary.declared_actions > 0 && <p className={styles.emptyFilter}>No declarations in this group. Choose another filter to continue your review.</p>}
  </>;
}

export function ScanActionResult({ action, classification }: AgentScanReport['results'][number]) {
  return <div className={styles.actionDetail}>
    <p className={classification.decision === 'gate' ? styles.consequential : styles.review}>{classificationLabel(classification)}</p>
    <h3>{action.name}</h3>
    {action.http_method && <p className={styles.route}>{action.http_method} {action.route_path}</p>}
    {action.description && <p className={styles.description}>{action.description}</p>}
    <p><strong>Why this result:</strong> {classification.reason}</p>
    <p className={styles.recommendation}><strong>Next step:</strong> {classification.decision === 'gate'
      ? 'Set the allowed scope and an approval rule before this action runs. Check where a Gate could enforce them; this scan has not configured one.'
      : classification.decision === 'review_fail_closed'
        ? 'Ask the builder what this action changes, then inspect its implementation and required permissions. Do not treat an unclear declaration as read-only.'
        : 'Check that the implementation and credentials are read-only too. A read-like name or hint is not proof.'}</p>
    <details className={styles.ruleDetail}><summary>About this rule match</summary><p className={styles.confidence}>Rule-match confidence: {classification.confidence}. This describes the declaration match, not actual behavior or safety.</p></details>
  </div>;
}

export default function AgentScanner() {
  const [input, setInput] = useState('');
  const [report, setReport] = useState<AgentScanReport | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [synthetic, setSynthetic] = useState(false);
  const [filter, setFilter] = useState<ScanFilter>('all');
  const [dragActive, setDragActive] = useState(false);
  const [readingFile, setReadingFile] = useState(false);
  const [sourceName, setSourceName] = useState('');
  const generation = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);

  function replaceInput(text: string, example = false) {
    generation.current++;
    setInput(text); setReport(null); setError(''); setBusy(false); setSynthetic(example);
    setFilter('all'); setReadingFile(false); setSourceName('');
  }

  async function loadLocalFile(file: File) {
    replaceInput('');
    const request = generation.current;
    if (file.size > AGENT_SCAN_LIMITS.bytes) {
      setError('The file is too large. Choose a JSON file no larger than 1 MiB.');
      return;
    }
    setReadingFile(true);
    try {
      const text = await file.text();
      if (generation.current === request) { replaceInput(text); setSourceName(file.name); }
    } catch {
      if (generation.current === request) { setError('The file could not be read. Try pasting its JSON instead.'); setReadingFile(false); }
    }
  }

  function loadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (file) void loadLocalFile(file);
  }

  function dropFile(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragActive(false);
    if (event.dataTransfer.files.length !== 1) {
      replaceInput('');
      setError('Drop one local JSON file at a time, or paste its contents below.');
      return;
    }
    void loadLocalFile(event.dataTransfer.files[0]);
  }

  async function scan() {
    const request = ++generation.current;
    setBusy(true); setError(''); setReport(null); setFilter('all');
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
      <div className={styles.topline}>
        <a className={styles.back} href="/works">EMILIA Marketplace</a>
        <p className={styles.eyebrow}>Free tool · no account</p>
      </div>
      <header className={styles.hero}>
        <h1>Before you delegate,<br /> <em>know what to review.</em></h1>
        <p className={styles.lead}>Scan an agent’s declared tools. See which actions may move money, change access or affect real systems, then decide what needs a closer look.</p>
      </header>
      <p className={styles.privacy}><span className={styles.privacyLabel}>Browser-only scan</span><span>Your input stays in this browser tab. This tool does not upload it, run your agent or publish findings.</span></p>

      <section className={styles.workspace} aria-labelledby="input-heading">
        <div className={styles.editor}>
          <div className={styles.editorHeading}><h2 id="input-heading">Bring the tool declarations.</h2></div>
          <p>MCP tools/list, an actions array or OpenAPI JSON. Up to 1 MiB and 500 actions. No API keys needed.</p>
          <div className={styles.dropZone} data-drag-active={dragActive} onDragOver={event => { event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={dropFile}>
            <div><p className={styles.dropTitle}>Drop a JSON file here</p><p className={styles.dropNote}>Read locally. Nothing is uploaded.</p></div>
            <label className={styles.fileButton}>Choose JSON file<input ref={fileInput} type="file" accept=".json,application/json" onChange={loadFile} aria-label="Choose JSON file" /></label>
          </div>
          <div className={styles.sampleRow}><span>No file handy?</span><button type="button" className={styles.textButton} onClick={() => replaceInput(SYNTHETIC_AGENT_SCAN_SAMPLE, true)}>Try a synthetic example</button></div>
          {(readingFile || sourceName) && <p className={styles.fileStatus} role="status">{readingFile ? 'Reading your local file…' : `Loaded ${sourceName}. Ready to scan.`}</p>}
          <label className={styles.inputLabel} htmlFor="agent-json">Or paste JSON</label>
          <textarea id="agent-json" value={input} onChange={event => replaceInput(event.target.value)} maxLength={AGENT_SCAN_LIMITS.bytes + 1} placeholder={'{ "actions": [{ "name": "refund_payment" }] }'} spellCheck={false} autoComplete="off" autoCorrect="off" autoCapitalize="off" data-1p-ignore data-lpignore="true" />
          {synthetic && <p className={styles.notice}>Synthetic example. These tools do not belong to a real agent. The refund tool deliberately has a conflicting read-only hint.</p>}
          <div className={styles.toolbar}>
            <button type="button" className={styles.primaryButton} onClick={scan} disabled={busy || readingFile || !input.trim()}>{busy ? 'Inspecting declarations…' : 'Scan declarations, free'}</button>
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
          <p className={styles.eyebrow}>A useful first look</p>
          <h2>A review list.<br />Not a safety badge.</h2>
          <p>The report puts potential consequential actions first, explains each match and suggests what to check next.</p>
          <p>A tool named “read account” may still change it. This is a declaration scan, not a code audit or sandbox test. It cannot see runtime behavior, credentials or calls that bypass a Gate.</p>
          <p className={styles.scopeNote}>No safety score. No certification. No agent execution.</p>
        </aside>
      </section>

      <section className={styles.results} aria-live="polite" aria-busy={busy}>
        {report && <>
          <div className={styles.resultHeading}>
            <div><p className={styles.eyebrow}>{synthetic ? 'Synthetic example report' : 'Declaration report'}</p><h2>{report.summary.declared_actions} declared actions. Actual behavior unknown.</h2></div>
            <button type="button" className={styles.secondaryButton} onClick={download}>Download JSON report</button>
          </div>
          <ScanReportResults report={report} filter={filter} onFilterChange={setFilter} />
          <p className={styles.downloadNote}>The download includes all {report.summary.declared_actions} declarations, regardless of your filter, and a SHA-256 fingerprint of the exact input. A matching fingerprint identifies the same input bytes, not a verified agent. Review declaration text before sharing it.</p>
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
          <div><h3>Share what you have built.</h3><p>A listing is separate from this private scan. Choose what you want to publish.</p><a href="/works/join">List your agent</a><a href="/works/claim">Claim an Authority Record</a></div>
          <div><h3>Review a specific deployment.</h3><p>Qualification checks a defined scope. Gate deployment is a separate step for enforcing authority on covered calls.</p><a href="/works/qualification">Explore scoped qualification</a><a href="/works/gate">Explore Gate deployment</a></div>
        </div>
      </section>
    </main>
  );
}
