'use client';

// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BanknoteArrowUp,
  Braces,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clipboard,
  Code2,
  Copy,
  DatabaseZap,
  Eye,
  FileCheck2,
  Fingerprint,
  GitBranch,
  KeyRound,
  LockKeyhole,
  Network,
  Play,
  Radar,
  Rocket,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserCheck,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import {
  AUTHORITY_ACTIONS,
  DEMO_STEPS,
  canRunSyntheticPath,
  filterAuthorityActions,
  nextDemoStep,
  visibleAuthorityActionCount,
} from './model';
import type {
  AuthorityAction,
  AuthorityDisposition,
  AuthorityFilter,
  AuthorityIcon,
} from './model';
import styles from './authority-brain.module.css';

const COMMAND = 'npx @emilia-protocol/scan brain ./tools.json';

const FILTERS: Array<{ id: AuthorityFilter; label: string }> = [
  { id: 'all', label: 'All surfaces' },
  { id: 'review', label: 'Review required' },
  { id: 'pass-through', label: 'Pass-through' },
  { id: 'blind-spot', label: 'Blind spots' },
];

const ACTION_ICONS: Record<AuthorityIcon, LucideIcon> = {
  wire: BanknoteArrowUp,
  deploy: Rocket,
  delete: Trash2,
  summarize: Clipboard,
  unknown: CircleHelp,
};

const DISPOSITION_LABELS: Record<AuthorityDisposition, string> = {
  review_required: 'Review required',
  pass_through_proposal: 'Pass-through proposal',
  visibility_gap: 'Visibility gap',
};

const LOOP = [
  {
    n: '01',
    title: 'Discover',
    icon: ScanSearch,
    copy: 'Enumerate the declared MCP and OpenAPI action surfaces the local scanner can actually see.',
  },
  {
    n: '02',
    title: 'Map',
    icon: Network,
    copy: 'Propose consequence classifications, exact material fields, confidence, and blind spots; authority source remains an owner decision.',
  },
  {
    n: '03',
    title: 'Protect',
    icon: LockKeyhole,
    copy: 'For a reviewed MCP surface, generate the scaffold and place Gate at one credential-owning executor boundary.',
  },
  {
    n: '04',
    title: 'Prove',
    icon: FileCheck2,
    copy: 'Refuse insufficient authority, consume accepted authority once, and preserve portable evidence under customer-pinned rules.',
  },
];

function actionCount(disposition: AuthorityDisposition): number {
  return AUTHORITY_ACTIONS.filter((action) => action.disposition === disposition).length;
}

function dispositionClass(disposition: AuthorityDisposition): string {
  if (disposition === 'review_required') return styles.reviewBadge;
  if (disposition === 'pass_through_proposal') return styles.passBadge;
  return styles.gapBadge;
}

function Confidence({ value }: { value: AuthorityAction['confidence'] }): React.ReactElement {
  const bars = value === 'high' ? 3 : value === 'medium' ? 2 : value === 'low' ? 1 : 0;
  return (
    <span className={styles.confidence} aria-label={`Confidence: ${value.replace('_', ' ')}`}>
      <span className={styles.confidenceBars} aria-hidden="true">
        {[0, 1, 2].map((index) => (
          <span key={index} data-on={index < bars ? 'true' : undefined} />
        ))}
      </span>
      {value === 'not_available' ? 'Not available' : value}
    </span>
  );
}

function ActionRow({
  action,
  selected,
  onSelect,
}: {
  action: AuthorityAction;
  selected: boolean;
  onSelect: () => void;
}): React.ReactElement {
  const Icon = ACTION_ICONS[action.icon];
  return (
    <button
      type="button"
      className={styles.actionRow}
      data-selected={selected ? 'true' : undefined}
      aria-pressed={selected}
      onClick={onSelect}
    >
      <span className={styles.actionIcon}><Icon aria-hidden="true" size={17} /></span>
      <span className={styles.actionCopy}>
        <strong>{action.name}</strong>
        <code>{action.selector}</code>
      </span>
      <span className={`${styles.dispositionBadge} ${dispositionClass(action.disposition)}`}>
        {DISPOSITION_LABELS[action.disposition]}
      </span>
      <ChevronRight className={styles.actionChevron} aria-hidden="true" size={16} />
    </button>
  );
}

export default function AuthorityBrainExperience(): React.ReactElement {
  const [filter, setFilter] = useState<AuthorityFilter>('all');
  const [selectedId, setSelectedId] = useState(AUTHORITY_ACTIONS[0].id);
  const [demoStep, setDemoStep] = useState(0);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'selected' | 'failed'>('idle');
  const commandRef = useRef<HTMLElement>(null);

  const filteredActions = useMemo(
    () => filterAuthorityActions(AUTHORITY_ACTIONS, filter),
    [filter],
  );
  const activeAction = AUTHORITY_ACTIONS.find((action) => action.id === selectedId)
    ?? AUTHORITY_ACTIONS[0];
  const pathAvailable = canRunSyntheticPath(activeAction);
  const complete = demoStep === DEMO_STEPS.length - 1;

  const evidencePacket = JSON.stringify({
    artifact: 'EP-SYNTHETIC-AUTHORITY-DEMO-v1',
    selected_action: activeAction.selector,
    result: complete ? 'synthetic_path_complete' : 'pending',
    handler_invoked_without_authority: false,
    authority_consumed_once: complete,
    visitor_environment_scanned: false,
    production_enforcement: false,
  }, null, 2);

  function chooseFilter(nextFilter: AuthorityFilter): void {
    const nextActions = filterAuthorityActions(AUTHORITY_ACTIONS, nextFilter);
    setFilter(nextFilter);
    if (!nextActions.some((action) => action.id === selectedId)) {
      setSelectedId(nextActions[0]?.id ?? AUTHORITY_ACTIONS[0].id);
    }
    setDemoStep(0);
  }

  function chooseAction(action: AuthorityAction): void {
    setSelectedId(action.id);
    setDemoStep(0);
  }

  async function copyCommand(): Promise<void> {
    try {
      if (!navigator.clipboard) throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(COMMAND);
      setCopyState('copied');
    } catch {
      try {
        if (!commandRef.current) throw new Error('command unavailable');
        const selection = window.getSelection();
        if (!selection) throw new Error('selection unavailable');
        const range = document.createRange();
        range.selectNodeContents(commandRef.current);
        selection.removeAllRanges();
        selection.addRange(range);
        commandRef.current.focus();
        setCopyState('selected');
      } catch {
        setCopyState('failed');
      }
    }
  }

  return (
    <div className={styles.page}>
      <SiteNav activePage="map" />
      <main>
        <section className={styles.hero}>
          <div className={styles.gridField} aria-hidden="true" />
          <div className={styles.heroShell}>
            <div className={styles.heroCopy}>
              <div className={styles.heroKicker}>
                <span className={styles.liveDot} />
                EMILIA Authority Map · Local-first
              </div>
              <h1>See where your AI can act. Decide what needs authority.</h1>
              <p>
                Discover the declared actions your scanner can see. Review the proposed Authority Map.
                Put customer-controlled Gate in front of one consequential action. Preserve evidence
                without sending your code, credentials, or policy to us.
              </p>
              <div className={styles.heroActions}>
                <a className={styles.primaryCta} href="#run-local">
                  Run the local scan <ArrowRight aria-hidden="true" size={16} />
                </a>
                <Link className={styles.secondaryCta} href="/pilot">
                  Scope a protected workflow
                </Link>
              </div>
              <div className={styles.boundaryLine}>
                <ShieldCheck aria-hidden="true" size={16} />
                <span>The scanner proposes. The owner reviews. Gate enforces.</span>
              </div>
            </div>

            <div className={styles.heroMap} aria-label="Authority path illustration">
              <div className={styles.mapHeader}>
                <span>Authority topology</span>
                <span>Illustrative</span>
              </div>
              <svg viewBox="0 0 600 420" role="img" aria-label="Declared action surfaces flowing through owner review and Gate to portable evidence">
                <path className={styles.mapPathMuted} d="M90 86 C190 86 188 190 294 190" />
                <path className={styles.mapPathMuted} d="M90 210 C180 210 205 190 294 190" />
                <path className={styles.mapPathRisk} d="M90 332 C198 332 188 220 294 220" />
                <path className={styles.mapPathActive} d="M310 205 C386 205 408 123 488 123" />
                <path className={styles.mapPathActive} d="M310 205 C392 205 407 292 488 292" />
                <g className={styles.mapNode}>
                  <circle cx="82" cy="86" r="26" />
                  <circle cx="82" cy="86" r="5" className={styles.nodeFillBlue} />
                  <text x="82" y="128" textAnchor="middle">MCP tools</text>
                </g>
                <g className={styles.mapNode}>
                  <circle cx="82" cy="210" r="26" />
                  <circle cx="82" cy="210" r="5" className={styles.nodeFillBlue} />
                  <text x="82" y="252" textAnchor="middle">OpenAPI</text>
                </g>
                <g className={styles.mapNodeRisk}>
                  <circle cx="82" cy="332" r="26" />
                  <path d="M73 332h18M82 323v18" />
                  <text x="82" y="374" textAnchor="middle">Unknown</text>
                </g>
                <g className={styles.mapCore}>
                  <circle cx="302" cy="205" r="62" />
                  <circle cx="302" cy="205" r="45" />
                  <text x="302" y="200" textAnchor="middle">OWNER</text>
                  <text x="302" y="220" textAnchor="middle">REVIEW</text>
                </g>
                <g className={styles.mapNodeGate}>
                  <rect x="458" y="91" width="60" height="64" rx="4" />
                  <path d="M477 123h22M488 112v22" />
                  <text x="488" y="177" textAnchor="middle">Gate</text>
                </g>
                <g className={styles.mapNode}>
                  <circle cx="488" cy="292" r="28" />
                  <path d="M477 292l8 8 15-17" />
                  <text x="488" y="337" textAnchor="middle">Evidence</text>
                </g>
              </svg>
              <div className={styles.mapLegend}>
                <span><i data-tone="blue" /> Visible surface</span>
                <span><i data-tone="amber" /> Owner decision</span>
                <span><i data-tone="red" /> Blind spot</span>
              </div>
            </div>
          </div>
        </section>

        <section className={styles.loopSection} aria-labelledby="loop-heading">
          <div className={styles.sectionShell}>
            <div className={styles.sectionIntro}>
              <div className={styles.eyebrow}>One operating loop</div>
              <h2 id="loop-heading">Discover → Map → Protect → Prove</h2>
              <p>
                One local path from visibility to a customer-owned refusal boundary. Discovery never
                silently upgrades itself into an enforcement claim.
              </p>
            </div>
            <ol className={styles.loopGrid}>
              {LOOP.map(({ n, title, icon: Icon, copy }) => (
                <li key={title}>
                  <div className={styles.loopNumber}>{n}</div>
                  <Icon aria-hidden="true" size={22} />
                  <h3>{title}</h3>
                  <p>{copy}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className={styles.demoSection} aria-labelledby="demo-heading">
          <div className={styles.demoShell}>
            <header className={styles.demoHeader}>
              <div>
                <div className={styles.syntheticLabel}>
                  <Radar aria-hidden="true" size={14} />
                  SYNTHETIC LOCAL DEMO
                </div>
                <h2 id="demo-heading">Authority Map / declared surfaces</h2>
                <p>
                  Static fictional inputs. This hosted page has not scanned your device, connected to
                  your systems, blocked production, or detected fraud.
                </p>
              </div>
              <div className={styles.demoSession}>
                <span className={styles.sessionDot} />
                Browser-only simulation · no external effect
              </div>
            </header>

            <div className={styles.metricGrid}>
                  <div><span>Visible actions</span><strong>{visibleAuthorityActionCount(AUTHORITY_ACTIONS)}</strong><small>synthetic records</small></div>
              <div><span>Review required</span><strong>{actionCount('review_required')}</strong><small>owner decision</small></div>
              <div><span>Pass-through</span><strong>{actionCount('pass_through_proposal')}</strong><small>proposal only</small></div>
              <div data-tone="red"><span>Visibility gaps</span><strong>{actionCount('visibility_gap')}</strong><small>no judgment</small></div>
            </div>

            <div className={styles.dashboard}>
              <aside className={styles.inventoryPanel} aria-label="Synthetic action inventory">
                <div className={styles.panelTitle}>
                  <div><span>01 / Inventory</span><h3>Action surfaces and gaps</h3></div>
                  <Eye aria-hidden="true" size={18} />
                </div>
                <div className={styles.filters} role="group" aria-label="Filter synthetic actions">
                  {FILTERS.map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      data-active={filter === item.id ? 'true' : undefined}
                      aria-pressed={filter === item.id}
                      onClick={() => chooseFilter(item.id)}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
                <div className={styles.actionList}>
                  {filteredActions.map((action) => (
                    <ActionRow
                      key={action.id}
                      action={action}
                      selected={activeAction.id === action.id}
                      onSelect={() => chooseAction(action)}
                    />
                  ))}
                </div>
                <div className={styles.inventoryBoundary}>
                  <AlertTriangle aria-hidden="true" size={15} />
                  <span>Only declared, supported actions count as visible. OpenAPI remains map-only; generated protection is MCP-only.</span>
                </div>
              </aside>

              <section className={styles.detailPanel} aria-live="polite">
                <div className={styles.panelTitle}>
                  <div><span>02 / Inspect proposal</span><h3>{activeAction.name}</h3></div>
                  <span className={`${styles.dispositionBadge} ${dispositionClass(activeAction.disposition)}`}>
                    {DISPOSITION_LABELS[activeAction.disposition]}
                  </span>
                </div>
                <p className={styles.actionDescription}>{activeAction.description}</p>
                <dl className={styles.detailFacts}>
                  <div><dt>Authority source</dt><dd>{activeAction.authoritySource}</dd></div>
                  <div><dt>Assurance</dt><dd>{activeAction.assurance}</dd></div>
                  <div><dt>Category</dt><dd>{activeAction.category}</dd></div>
                  <div><dt>Confidence</dt><dd><Confidence value={activeAction.confidence} /></dd></div>
                </dl>

                <div className={styles.fieldBlock}>
                  <div className={styles.miniHeading}><Fingerprint aria-hidden="true" size={15} /> Required exact fields</div>
                  {activeAction.exactFields.length > 0 ? (
                    <div className={styles.fieldChips}>
                      {activeAction.exactFields.map((field) => <code key={field}>{field}</code>)}
                    </div>
                  ) : activeAction.disposition === 'pass_through_proposal' ? (
                    <p className={styles.unavailable}>No receipt-binding fields are proposed. The owner must still confirm the handler is read-only.</p>
                  ) : (
                    <p className={styles.unavailable}>Not available until the operation schema is visible.</p>
                  )}
                </div>

                <div className={styles.blindSpotBlock}>
                  <div className={styles.miniHeading}><ShieldAlert aria-hidden="true" size={15} /> Named blind spots</div>
                  <ul>
                    {activeAction.blindSpots.map((blindSpot) => <li key={blindSpot}>{blindSpot}</li>)}
                  </ul>
                </div>
              </section>
            </div>

            <section className={styles.proofConsole} aria-labelledby="proof-console-title">
              <div className={styles.proofHeader}>
                <div>
                  <span>03 / Synthetic proof path</span>
                  <h3 id="proof-console-title">From proposal to portable evidence</h3>
                </div>
                {pathAvailable ? (
                  <div className={styles.proofActions}>
                    <button type="button" onClick={() => setDemoStep(0)} disabled={demoStep === 0}>Reset</button>
                    <button
                      type="button"
                      className={styles.advanceButton}
                      onClick={() => setDemoStep(nextDemoStep(demoStep))}
                      disabled={complete}
                    >
                      {complete ? <><Check aria-hidden="true" size={15} /> Synthetic path complete</> : <><Play aria-hidden="true" size={14} /> Advance synthetic path</>}
                    </button>
                  </div>
                ) : (
                  <span className={styles.pathUnavailable}>
                    {activeAction.disposition === 'visibility_gap'
                      ? 'No protection path can be proposed for an unobserved operation surface'
                      : 'No receipt path is proposed until the owner confirms this handler is read-only'}
                  </span>
                )}
              </div>

              <ol className={styles.stageRail} aria-live="polite">
                {DEMO_STEPS.map((step, index) => {
                  const done = pathAvailable && index < demoStep;
                  const current = pathAvailable && index === demoStep;
                  return (
                    <li
                      key={step.id}
                      data-done={done ? 'true' : undefined}
                      data-current={current ? 'true' : undefined}
                    >
                      <div className={styles.stageIndex}>{done ? <Check aria-hidden="true" size={14} /> : String(index + 1).padStart(2, '0')}</div>
                      <div><strong>{step.label}</strong><p>{step.detail}</p></div>
                    </li>
                  );
                })}
              </ol>

              <div className={styles.proofOutput}>
                <div className={styles.proofReadout}>
                  <div className={styles.readoutIcon} data-step={DEMO_STEPS[demoStep].id}>
                    {complete ? <BadgeCheck aria-hidden="true" size={23} /> : <GitBranch aria-hidden="true" size={22} />}
                  </div>
                  <div>
                    <span>Current synthetic state</span>
                    <strong>{pathAvailable ? DEMO_STEPS[demoStep].label : 'Protection path unavailable'}</strong>
                    <p>{pathAvailable ? DEMO_STEPS[demoStep].detail : 'Make the action surface visible or select a review-required action. No execution judgment has been made.'}</p>
                  </div>
                </div>
                <div className={styles.evidencePreview} data-ready={complete ? 'true' : undefined}>
                  <div><Braces aria-hidden="true" size={15} /><span>Synthetic packet preview</span></div>
                  <pre>{evidencePacket}</pre>
                </div>
              </div>
              <div className={styles.syntheticBoundary}>
                <AlertTriangle aria-hidden="true" size={15} />
                <span>
                  This proves only the browser simulation shown here. Production prevention requires a completely mediated Gate,
                  durable shared state, pinned trust roots, credential custody, and deployment-specific verification.
                </span>
              </div>
            </section>
          </div>
        </section>

        <section className={styles.honestySection} aria-labelledby="honesty-heading">
          <div className={styles.sectionShell}>
            <div className={styles.sectionIntro}>
              <div className={styles.eyebrow}>Deliberately bounded</div>
              <h2 id="honesty-heading">The unknowns stay visible.</h2>
              <p>
                Authority Map reduces the cost of finding and reviewing declared action surfaces.
                It does not turn incomplete visibility into a safety score.
              </p>
            </div>
            <div className={styles.boundaryGrid}>
              <div>
                <CheckCircle2 aria-hidden="true" size={21} />
                <h3>What the local product can establish</h3>
                <ul>
                  <li>Which supported declared actions were visible to this scan</li>
                  <li>Why a consequence classification was proposed</li>
                  <li>Which exact fields and authority sources require owner review</li>
                  <li>Whether a supported local synthetic refusal kept its mock handler from running</li>
                </ul>
              </div>
              <div>
                <CircleHelp aria-hidden="true" size={21} />
                <h3>What remains a deployment question</h3>
                <ul>
                  <li>Whether every consequential path reaches the same Gate</li>
                  <li>Whether provider credentials are unavailable through another path</li>
                  <li>Whether production state, keys, policy, and approvers are configured correctly</li>
                  <li>Whether external effects occurred beyond the evidence an observer can verify</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        <section className={styles.runSection} id="run-local" aria-labelledby="run-heading">
          <div className={styles.runShell}>
            <div className={styles.runCopy}>
              <div className={styles.eyebrow}>Start with the free local product</div>
              <h2 id="run-heading">Map one declared action surface.</h2>
              <p>
                The generated dashboard uses no account, upload, telemetry, or remote asset. When invoked
                through <code>npx</code>, npm may download the package before scanner startup. The scan itself
                launches no configured server.
              </p>
            </div>
            <div className={styles.commandCard}>
              <div className={styles.commandHeader}>
                <span><Code2 aria-hidden="true" size={15} /> Terminal</span>
                <span>Local command</span>
              </div>
              <div className={styles.commandLine}>
                <span aria-hidden="true">$</span>
                <code ref={commandRef} tabIndex={0}>{COMMAND}</code>
                <button type="button" onClick={copyCommand} aria-label="Copy Authority Map command">
                  {copyState === 'copied' ? <Check aria-hidden="true" size={16} /> : <Copy aria-hidden="true" size={16} />}
                  <span>{copyState === 'copied' ? 'Copied' : copyState === 'selected' ? 'Selected' : 'Copy'}</span>
                </button>
              </div>
              <div className={styles.copyStatus} aria-live="polite">
                {copyState === 'selected'
                  ? 'Clipboard unavailable. The command is selected.'
                  : copyState === 'failed' ? 'Clipboard and text selection are unavailable.' : '\u00a0'}
              </div>
              <div className={styles.commandActions}>
                <a href="https://www.npmjs.com/package/@emilia-protocol/scan" target="_blank" rel="noopener noreferrer">
                  Open package <ArrowRight aria-hidden="true" size={14} />
                </a>
                <Link href="/pilot">
                  Protect one workflow <ArrowRight aria-hidden="true" size={14} />
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
