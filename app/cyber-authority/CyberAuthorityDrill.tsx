'use client';

// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react';
import css from './cyber-authority.module.css';

type Verdict = 'ADMITTED' | 'REFUSED' | 'INDETERMINATE';

type Scenario = {
  id: string;
  label: string;
  short: string;
  verdict: Verdict;
  operation: string;
  target: string;
  evidence: string;
  consumption: string;
  providerEntry: string;
  explanation: string;
};

const SCENARIOS: Scenario[] = [
  {
    id: 'exact',
    label: 'Exact action',
    short: 'Inside mandate',
    verdict: 'ADMITTED',
    operation: 'identity.disable',
    target: 'svc-billing-prod',
    evidence: 'Current incident + customer mandate',
    consumption: 'Available → reserved once',
    providerEntry: 'One attempt may enter',
    explanation:
      'The frozen operation, target, incident binding, and evidence match the customer mandate. Admission permits one provider attempt; it does not prove the provider succeeded.',
  },
  {
    id: 'substitution',
    label: 'Wider target',
    short: 'Action substitution',
    verdict: 'REFUSED',
    operation: 'identity.disable',
    target: 'tenant:*',
    evidence: 'Evidence names svc-billing-prod only',
    consumption: 'Not consumed',
    providerEntry: 'Blocked before entry',
    explanation:
      'The AI defender widened one identity into a tenant-wide action. The material target no longer matches accepted authority, so the provider credential is never used.',
  },
  {
    id: 'replay',
    label: 'Second attempt',
    short: 'Replay after consumption',
    verdict: 'REFUSED',
    operation: 'identity.disable',
    target: 'svc-billing-prod',
    evidence: 'Exact prior evidence replayed',
    consumption: 'Already consumed',
    providerEntry: 'Blocked before entry',
    explanation:
      'The exact evidence was already consumed by the first admitted crossing. Replaying the same bytes cannot create a second provider attempt.',
  },
  {
    id: 'timeout',
    label: 'Provider timeout',
    short: 'Effect cannot be established',
    verdict: 'INDETERMINATE',
    operation: 'identity.disable',
    target: 'svc-billing-prod',
    evidence: 'Admitted before provider entry',
    consumption: 'Consumed; retry remains closed',
    providerEntry: 'May have occurred',
    explanation:
      'The action was admitted and the provider may have received it, but no authenticated result establishes the effect. Gate records uncertainty and refuses a blind retry until reconciliation.',
  },
] as const;

function verdictClass(verdict: Verdict): string {
  if (verdict === 'ADMITTED') return css.verdictAdmitted;
  if (verdict === 'REFUSED') return css.verdictRefused;
  return css.verdictIndeterminate;
}

export default function CyberAuthorityDrill(): React.ReactElement {
  const [selectedId, setSelectedId] = useState(SCENARIOS[0].id);
  const selected = SCENARIOS.find((scenario) => scenario.id === selectedId) ?? SCENARIOS[0];

  return (
    <div className={css.drill}>
      <div className={css.scenarioRail} role="group" aria-label="Choose an authority-boundary scenario">
        {SCENARIOS.map((scenario, index) => (
          <button
            key={scenario.id}
            type="button"
            className={css.scenarioButton}
            data-selected={selected.id === scenario.id ? 'true' : undefined}
            aria-pressed={selected.id === scenario.id}
            onClick={() => setSelectedId(scenario.id)}
          >
            <span>{String(index + 1).padStart(2, '0')}</span>
            <strong>{scenario.label}</strong>
            <small>{scenario.short}</small>
          </button>
        ))}
      </div>

      <div className={css.drillConsole} aria-live="polite">
        <div className={css.consoleTop}>
          <span>AUTHORITY BOUNDARY / LOCAL SIMULATION</span>
          <span>NO EXTERNAL ACTION</span>
        </div>
        <div className={css.consoleBody}>
          <div className={css.requestPanel}>
            <p className={css.consoleLabel}>Frozen request</p>
            <dl>
              <div><dt>operation</dt><dd><code>{selected.operation}</code></dd></div>
              <div><dt>target</dt><dd><code>{selected.target}</code></dd></div>
              <div><dt>evidence</dt><dd>{selected.evidence}</dd></div>
              <div><dt>authority</dt><dd>{selected.consumption}</dd></div>
            </dl>
          </div>

          <div className={css.decisionPanel}>
            <div className={`${css.verdict} ${verdictClass(selected.verdict)}`}>
              <span>GATE VERDICT</span>
              <strong>{selected.verdict}</strong>
            </div>
            <div className={css.providerState}>
              <span>Provider entry</span>
              <strong>{selected.providerEntry}</strong>
            </div>
            <p>{selected.explanation}</p>
          </div>
        </div>
        <div className={css.consoleBottom}>
          <span>Identity is not action authority.</span>
          <span>Admission is not provider success.</span>
        </div>
      </div>
    </div>
  );
}
