// SPDX-License-Identifier: Apache-2.0

'use client';

import { useCallback, useMemo, useState } from 'react';
import {
  FINANCE_LAB_ACTIONS,
  FINANCE_LAB_COMPANY,
  type FinanceLabAction,
} from './finance-lab-fixture';
import css from './private-equity.module.css';

type SandboxCredentials = Readonly<{
  api_key: string;
  organization_id: string;
}>;

type PrecheckResult = Readonly<{
  decision?: string;
  observed_decision?: string | null;
  signoff_tier?: string | null;
  action_hash?: string;
  evidence_status?: string;
  detail?: string;
  title?: string;
}>;

function outcomeLabel(result: PrecheckResult): string {
  const observed = result.observed_decision || result.decision || 'unknown';
  if (observed === 'allow_with_signoff') {
    return `Would require signoff${result.signoff_tier ? ` (${result.signoff_tier})` : ''}`;
  }
  if (observed === 'deny') return 'Would refuse';
  if (observed === 'allow') return 'Would allow under this sandbox rule';
  return `Observed: ${observed}`;
}

function curlFor(action: FinanceLabAction, credentials: SandboxCredentials): string {
  const base = typeof window === 'undefined' ? 'https://www.emiliaprotocol.ai' : window.location.origin;
  return [
    `curl -s ${base}${action.path} \\`,
    `  -H 'authorization: Bearer ${credentials.api_key}' \\`,
    "  -H 'content-type: application/json' \\",
    `  -d '${JSON.stringify(action.body(credentials.organization_id))}'`,
  ].join('\n');
}

export default function PortfolioActionRiskLab(): React.ReactElement {
  const [credentials, setCredentials] = useState<SandboxCredentials | null>(null);
  const [busy, setBusy] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [results, setResults] = useState<Record<string, PrecheckResult>>({});
  const [selectedActionId, setSelectedActionId] = useState<FinanceLabAction['id']>('vendor-change');
  const [copied, setCopied] = useState(false);

  const selectedAction = FINANCE_LAB_ACTIONS.find((action) => action.id === selectedActionId)
    ?? FINANCE_LAB_ACTIONS[0];
  const curl = useMemo(
    () => (credentials ? curlFor(selectedAction, credentials) : ''),
    [credentials, selectedAction],
  );

  const provision = useCallback(async (): Promise<void> => {
    setBusy('provision');
    setError('');
    setResults({});
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
    } catch {
      setError('Network error while provisioning the observe-only sandbox.');
    } finally {
      setBusy('');
    }
  }, []);

  const runAction = useCallback(async (action: FinanceLabAction): Promise<void> => {
    if (!credentials) return;
    setBusy(action.id);
    setError('');
    try {
      const response = await fetch(action.path, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${credentials.api_key}`,
        },
        body: JSON.stringify(action.body(credentials.organization_id)),
      });
      const body: PrecheckResult = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(body.detail || body.title || `The ${action.title.toLowerCase()} precheck failed.`);
        return;
      }
      setResults((current) => ({ ...current, [action.id]: body }));
    } catch {
      setError(`Network error while evaluating the ${action.title.toLowerCase()}.`);
    } finally {
      setBusy('');
    }
  }, [credentials]);

  const copyCurl = useCallback(async (): Promise<void> => {
    if (!curl) return;
    try {
      await navigator.clipboard.writeText(curl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError('Copy was unavailable. Select the cURL command manually.');
    }
  }, [curl]);

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
          <h3>Create a scoped, throwaway finance sandbox key.</h3>
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
            <span className={css.labStep}>02 / Evaluate</span>
            <h3>Send two fictional actions through the finance prechecks.</h3>
            <div className={css.actionList}>
              {FINANCE_LAB_ACTIONS.map((action) => {
                const result = results[action.id];
                return (
                  <article key={action.id}>
                    <div>
                      <h4>{action.title}</h4>
                      <p>{action.subtitle}</p>
                      {result && (
                        <div className={css.resultLine} aria-live="polite">
                          <span>{outcomeLabel(result)}</span>
                          {result.action_hash && <code>{result.action_hash.slice(0, 22)}…</code>}
                        </div>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => runAction(action)}
                      disabled={busy === action.id}
                    >
                      {busy === action.id ? 'Evaluating…' : result ? 'Run again' : 'Run precheck'}
                    </button>
                  </article>
                );
              })}
            </div>
          </div>

          <div className={css.curlStep}>
            <div className={css.curlHeader}>
              <div>
                <span className={css.labStep}>03 / Integrate after provisioning</span>
                <h3>Copy the exact observe-mode request.</h3>
              </div>
              <button type="button" onClick={copyCurl}>{copied ? 'Copied' : 'Copy cURL'}</button>
            </div>
            <div className={css.curlTabs} role="tablist" aria-label="Finance precheck cURL">
              {FINANCE_LAB_ACTIONS.map((action) => (
                <button
                  key={action.id}
                  type="button"
                  role="tab"
                  aria-selected={selectedActionId === action.id}
                  onClick={() => { setSelectedActionId(action.id); setCopied(false); }}
                >
                  {action.id === 'vendor-change' ? 'Vendor change' : 'Payment release'}
                </button>
              ))}
            </div>
            <pre tabIndex={0}><code>{curl}</code></pre>
            <p>
              Replace fictional metadata only inside a buyer-approved sandbox. A production integration
              requires explicit boundary, credential, trust, retention, and complete-mediation review.
            </p>
          </div>
        </>
      )}

      {error && <div className={css.labError} role="alert">{error}</div>}
    </div>
  );
}
