// SPDX-License-Identifier: Apache-2.0

'use client';

import { useCallback, useMemo, useState } from 'react';
import {
  FINANCE_LAB_BOUNDARY,
  FINANCE_LAB_COMPANY,
  FINANCE_LAB_SCENARIOS,
  type FinanceLabScenario,
} from './finance-lab-fixture';
import { emitPortfolioEvent } from './portfolio-analytics';
import css from './private-equity.module.css';

type SandboxCredentials = Readonly<{
  api_key: string;
  organization_id: string;
}>;

type PrecheckResult = Readonly<{
  decision?: string;
  observed_decision?: string | null;
  signoff_tier?: string | null;
  required_assurance?: string | null;
  action_hash?: string;
  evidence_status?: string;
  detail?: string;
  title?: string;
}>;

function outcomeLabel(result: PrecheckResult): string {
  const observed = result.observed_decision || result.decision || 'unknown';
  if (observed === 'allow_with_signoff') {
    if (result.signoff_tier === 'dual') return 'Observed rule requires two accountable signoffs';
    return 'Observed rule requires an accountable signoff';
  }
  if (observed === 'deny') return 'Observed rule refuses this action';
  if (observed === 'allow') return 'Observed rule would allow this action';
  return `Observed: ${observed}`;
}

function curlFor(scenario: FinanceLabScenario, credentials: SandboxCredentials): string {
  const base = typeof window === 'undefined' ? 'https://www.emiliaprotocol.ai' : window.location.origin;
  return [
    `curl -s ${base}${scenario.path} \\`,
    `  -H 'authorization: Bearer ${credentials.api_key}' \\`,
    "  -H 'content-type: application/json' \\",
    `  -d '${JSON.stringify(scenario.body(credentials.organization_id))}'`,
  ].join('\n');
}

export default function PortfolioActionRiskLab(): React.ReactElement {
  const [credentials, setCredentials] = useState<SandboxCredentials | null>(null);
  const [busy, setBusy] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [result, setResult] = useState<PrecheckResult | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<FinanceLabScenario['id']>('single_signoff');
  const [copied, setCopied] = useState(false);

  const selectedScenario = FINANCE_LAB_SCENARIOS.find((scenario) => scenario.id === selectedScenarioId)
    ?? FINANCE_LAB_SCENARIOS[0];
  const curl = useMemo(
    () => (credentials ? curlFor(selectedScenario, credentials) : ''),
    [credentials, selectedScenario],
  );

  const provision = useCallback(async (): Promise<void> => {
    setBusy('provision');
    setError('');
    setResult(null);
    emitPortfolioEvent({ event: 'sandbox_provision_started', location: 'risk_lab' });
    try {
      const response = await fetch('/api/pilot/sandbox/provision', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vertical: 'fin', org: FINANCE_LAB_COMPANY }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok || typeof body.api_key !== 'string' || typeof body.organization_id !== 'string') {
        setError(body.detail || body.title || 'The observe-only sandbox could not be provisioned.');
        return;
      }
      setCredentials({ api_key: body.api_key, organization_id: body.organization_id });
      emitPortfolioEvent({ event: 'sandbox_provision_completed', location: 'risk_lab' });
    } catch {
      setError('Network error while provisioning the observe-only sandbox.');
    } finally {
      setBusy('');
    }
  }, []);

  const runScenario = useCallback(async (): Promise<void> => {
    if (!credentials) return;
    setBusy('precheck');
    setError('');
    try {
      const response = await fetch(selectedScenario.path, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${credentials.api_key}`,
        },
        body: JSON.stringify(selectedScenario.body(credentials.organization_id)),
      });
      const body: PrecheckResult = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(body.detail || body.title || 'The payment-release precheck failed.');
        return;
      }
      setResult(body);
      emitPortfolioEvent({
        event: 'sandbox_precheck_completed',
        location: 'risk_lab',
        scenario: selectedScenario.id,
      });
    } catch {
      setError('Network error while evaluating the fictional payment release.');
    } finally {
      setBusy('');
    }
  }, [credentials, selectedScenario]);

  const copyCurl = useCallback(async (): Promise<void> => {
    if (!curl) return;
    try {
      await navigator.clipboard.writeText(curl);
      setCopied(true);
      emitPortfolioEvent({
        event: 'sandbox_curl_copied',
        location: 'risk_lab',
        scenario: selectedScenario.id,
      });
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError('Copy was unavailable. Select the cURL command manually.');
    }
  }, [curl, selectedScenario.id]);

  const selectScenario = useCallback((scenario: FinanceLabScenario): void => {
    setSelectedScenarioId(scenario.id);
    setResult(null);
    setCopied(false);
    setError('');
    emitPortfolioEvent({
      event: 'sandbox_scenario_selected',
      location: 'risk_lab',
      scenario: scenario.id,
    });
  }, []);

  return (
    <div className={css.labPanel}>
      <div className={css.labNotice} role="note">
        <span>OBSERVE ONLY</span>
        <p>
          This synthetic lab evaluates metadata. It does not authorize, block, mutate, or execute a
          production finance action and does not establish complete mediation.
        </p>
      </div>

      <div className={css.companyRecord}>
        <div>
          <span>Consenting sandbox subject</span>
          <strong>Northstar Components</strong>
        </div>
        <span className={css.fictionalBadge}>FICTIONAL</span>
      </div>

      {!credentials ? (
        <div className={css.provisionStep}>
          <span className={css.labStep}>01 / Provision</span>
          <h3>Create a scoped key for one fictional payment boundary.</h3>
          <p>
            The key is born for observe mode. It cannot turn this exercise into enforcement or reach
            a production ERP, bank, or payment rail.
          </p>
          <button type="button" onClick={provision} disabled={busy === 'provision'}>
            {busy === 'provision' ? 'Provisioning…' : 'Provision observe-only lab'}
          </button>
        </div>
      ) : (
        <>
          <div className={css.credentialRail}>
            <div>
              <span>Sandbox ready</span>
              <code>{credentials.organization_id}</code>
            </div>
            <span className={css.readyBadge}>OBSERVE</span>
          </div>

          <div className={css.actionStep}>
            <span className={css.labStep}>02 / Choose a condition</span>
            <h3>Keep the boundary fixed. Change the evidence condition.</h3>
            <p className={css.actionStepLead}>{FINANCE_LAB_BOUNDARY}</p>
            <div className={css.scenarioGrid} aria-label="Payment-release conditions">
              {FINANCE_LAB_SCENARIOS.map((scenario, index) => (
                <button
                  key={scenario.id}
                  type="button"
                  aria-pressed={selectedScenarioId === scenario.id}
                  onClick={() => selectScenario(scenario)}
                >
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <strong>{scenario.title}</strong>
                  <small>{scenario.expectedObservation}</small>
                </button>
              ))}
            </div>

            <div className={css.actionPreview}>
              <div className={css.previewHeader}>
                <div>
                  <span>Fictional exact action</span>
                  <strong>{selectedScenario.amountLabel} payment release</strong>
                </div>
                <span>OBSERVE</span>
              </div>
              <dl className={css.previewGrid}>
                <div><dt>Instruction</dt><dd>{String(selectedScenario.body('sandbox').payment_instruction_id)}</dd></div>
                <div><dt>Counterparty</dt><dd>Northstar Demo Vendor</dd></div>
                <div><dt>Boundary</dt><dd>Finance provider entry</dd></div>
                <div><dt>Expected</dt><dd>{selectedScenario.expectedObservation}</dd></div>
              </dl>
              <button type="button" onClick={runScenario} disabled={busy === 'precheck'}>
                {busy === 'precheck' ? 'Evaluating…' : result ? 'Run observed rule again' : 'Run observed rule'}
              </button>
            </div>

            {result && (
              <div className={css.resultPanel} aria-live="polite">
                <div className={css.resultHeader}>
                  <span>Observed result</span>
                  <strong>{outcomeLabel(result)}</strong>
                </div>
                <dl className={css.resultMeta}>
                  <div><dt>Action digest</dt><dd><code>{result.action_hash?.slice(0, 22) ?? 'unavailable'}…</code></dd></div>
                  <div><dt>Evidence row</dt><dd>{result.evidence_status ?? 'unknown'}</dd></div>
                  <div><dt>Assurance floor</dt><dd>{result.required_assurance ? `Class ${result.required_assurance}` : 'Not returned'}</dd></div>
                </dl>
                <ol className={css.resultStages}>
                  <li><strong>Metadata evaluated</strong><span>The current finance rule produced the result above.</span></li>
                  <li><strong>Provider not entered</strong><span>This public lab has no payment-provider connection.</span></li>
                  <li><strong>Production control is separate</strong><span>A buyer-approved, completely mediated Gate would enforce accepted authority and evidence before provider entry.</span></li>
                </ol>
              </div>
            )}
          </div>

          <div className={css.curlStep}>
            <div className={css.curlHeader}>
              <div>
                <span className={css.labStep}>03 / Integrate after provisioning</span>
                <h3>Copy the exact observe-mode request.</h3>
              </div>
              <button type="button" onClick={copyCurl}>{copied ? 'Copied' : 'Copy cURL'}</button>
            </div>
            <pre tabIndex={0}><code>{curl}</code></pre>
            <p>
              Replace fictional metadata only inside a buyer-approved sandbox. A production integration
              requires explicit boundary, credential, trust, retention, and complete-mediation review.
              This adapter derives the organization from the authenticated key and rejects tenant
              mismatches; it does not turn an unknown identifier into accepted authority.
            </p>
          </div>
        </>
      )}

      {error && <div className={css.labError} role="alert">{error}</div>}
    </div>
  );
}
