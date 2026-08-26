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
  Eye,
  FileCheck2,
  Fingerprint,
  GitBranch,
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
import { ProductJourney, ProductStoryCallout } from '@/components/product-story/ProductStory';
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
  { id: 'all', label: 'Everything found' },
  { id: 'review', label: 'Needs a decision' },
  { id: 'pass-through', label: 'Read-only candidate' },
  { id: 'blind-spot', label: 'Paths not visible' },
];

const ACTION_ICONS: Record<AuthorityIcon, LucideIcon> = {
  wire: BanknoteArrowUp,
  deploy: Rocket,
  delete: Trash2,
  summarize: Clipboard,
  unknown: CircleHelp,
};

const DISPOSITION_LABELS: Record<AuthorityDisposition, string> = {
  review_required: 'Needs a decision',
  pass_through_proposal: 'Read-only candidate',
  visibility_gap: 'Path not visible',
};

const LOOP = [
  {
    n: '01',
    title: 'See',
    icon: ScanSearch,
    copy: 'Find the declared MCP and OpenAPI actions the local scanner can actually see.',
  },
  {
    n: '02',
    title: 'Decide',
    icon: Network,
    copy: 'Review the proposed consequence, exact fields, confidence, and blind spots. The owner decides what needs authority.',
  },
  {
    n: '03',
    title: 'Protect',
    icon: LockKeyhole,
    copy: 'For a reviewed MCP action, put Gate at the credential-owning executor boundary before the action runs.',
  },
  {
    n: '04',
    title: 'Prove',
    icon: FileCheck2,
    copy: 'Refuse insufficient authority, consume accepted authority once, and keep a portable record under customer-pinned rules.',
  },
];

function AuthorityBrainGraphic(): React.ReactElement {
  return (
    <div className={styles.brainGraphic}>
      <div className={styles.brainGraphicHeader}>
        <span>Two-sided visibility</span>
        <span>Illustrative</span>
      </div>
      <div className={styles.brainStage}>
        <div className={styles.brainInputs}>
          <span>What the agent can reach</span>
          <strong>Move money</strong>
          <strong>Deploy code</strong>
          <strong>Delete data</strong>
        </div>

        <svg viewBox="0 0 760 470" role="img" aria-labelledby="authority-brain-graphic-title authority-brain-graphic-description">
          <title id="authority-brain-graphic-title">EMILIA Authority Brain</title>
          <desc id="authority-brain-graphic-description">
            Two eyes connected by a synaptic brain illustrate declared agent actions on the left and expected protected-outcome evidence on the right. The owner decides what requires authority and Gate enforces separately.
          </desc>
          <defs>
            <radialGradient id="brain-eye-blue" cx="50%" cy="50%" r="65%">
              <stop offset="0%" stopColor="#dff3ff" />
              <stop offset="28%" stopColor="#58a6ff" />
              <stop offset="72%" stopColor="#163d64" />
              <stop offset="100%" stopColor="#07121d" />
            </radialGradient>
            <radialGradient id="brain-eye-gold" cx="50%" cy="50%" r="65%">
              <stop offset="0%" stopColor="#fff5d4" />
              <stop offset="28%" stopColor="#e7b65b" />
              <stop offset="72%" stopColor="#654719" />
              <stop offset="100%" stopColor="#161006" />
            </radialGradient>
            <filter id="brain-glow-blue" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="8" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="brain-glow-gold" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="7" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          <g className={styles.brainSidePaths}>
            <path data-tone="blue" d="M8 118 C92 118 112 170 192 170" />
            <path data-tone="blue" d="M8 235 C96 235 116 222 192 222" />
            <path data-tone="blue" d="M8 352 C92 352 112 274 192 274" />
            <path data-tone="gold" d="M568 170 C648 170 666 118 752 118" />
            <path data-tone="gold" d="M568 222 C648 222 666 235 752 235" />
            <path data-tone="gold" d="M568 274 C648 274 666 352 752 352" />
          </g>

          <g className={styles.brainOutline}>
            <path d="M380 72 C340 30 278 43 263 99 C207 91 174 140 191 187 C145 215 151 279 198 299 C181 352 224 397 274 385 C301 430 352 418 380 388" />
            <path d="M380 72 C420 30 482 43 497 99 C553 91 586 140 569 187 C615 215 609 279 562 299 C579 352 536 397 486 385 C459 430 408 418 380 388" />
            <path d="M380 72V388" />
          </g>

          <g className={styles.synapses}>
            <path d="M259 113L303 153L337 117L380 165L426 112L468 155L506 121" />
            <path d="M205 190L257 209L305 178L345 219L380 181L417 218L461 178L553 195" />
            <path d="M204 299L262 277L302 314L340 271L380 315L424 274L469 316L558 293" />
            <path d="M274 385L304 342L347 367L380 329L415 367L459 342L486 385" />
            <circle cx="259" cy="113" r="4" /><circle cx="303" cy="153" r="4" />
            <circle cx="337" cy="117" r="4" /><circle cx="426" cy="112" r="4" />
            <circle cx="468" cy="155" r="4" /><circle cx="506" cy="121" r="4" />
            <circle cx="205" cy="190" r="4" /><circle cx="257" cy="209" r="4" />
            <circle cx="305" cy="178" r="4" /><circle cx="345" cy="219" r="4" />
            <circle cx="417" cy="218" r="4" /><circle cx="461" cy="178" r="4" />
            <circle cx="553" cy="195" r="4" /><circle cx="204" cy="299" r="4" />
            <circle cx="262" cy="277" r="4" /><circle cx="302" cy="314" r="4" />
            <circle cx="340" cy="271" r="4" /><circle cx="424" cy="274" r="4" />
            <circle cx="469" cy="316" r="4" /><circle cx="558" cy="293" r="4" />
            <circle cx="274" cy="385" r="4" /><circle cx="304" cy="342" r="4" />
            <circle cx="347" cy="367" r="4" /><circle cx="415" cy="367" r="4" />
            <circle cx="459" cy="342" r="4" /><circle cx="486" cy="385" r="4" />
          </g>

          <g className={styles.brainEyeLeft}>
            <path d="M210 239 Q282 160 354 239 Q282 318 210 239Z" />
            <circle cx="282" cy="239" r="40" fill="url(#brain-eye-blue)" filter="url(#brain-glow-blue)" />
            <circle cx="282" cy="239" r="13" />
            <circle cx="270" cy="226" r="6" className={styles.eyeGlint} />
            <text x="282" y="331" textAnchor="middle">INTENT</text>
          </g>
          <g className={styles.brainEyeRight}>
            <path d="M406 239 Q478 160 550 239 Q478 318 406 239Z" />
            <circle cx="478" cy="239" r="40" fill="url(#brain-eye-gold)" filter="url(#brain-glow-gold)" />
            <circle cx="478" cy="239" r="13" />
            <circle cx="466" cy="226" r="6" className={styles.eyeGlint} />
            <text x="478" y="331" textAnchor="middle">OUTCOME</text>
          </g>
          <g className={styles.brainGate}>
            <rect x="362" y="221" width="36" height="36" rx="5" />
            <text x="380" y="243" textAnchor="middle">GATE</text>
          </g>

          <g className={styles.brainFlowDots}>
            <circle cx="112" cy="145" r="4" data-tone="blue" />
            <circle cx="151" cy="235" r="4" data-tone="blue" />
            <circle cx="626" cy="235" r="4" data-tone="gold" />
            <circle cx="676" cy="328" r="4" data-tone="gold" />
          </g>
        </svg>

        <div className={styles.brainOutputs}>
          <span>What happens next</span>
          <strong>Exact authority</strong>
          <strong>Provider entry</strong>
          <strong>Outcome evidence</strong>
        </div>
      </div>
      <div className={styles.brainRoles}>
        <div><strong>Authority Brain</strong><span>maps and proposes</span></div>
        <ArrowRight aria-hidden="true" size={17} />
        <div><strong>Customer owner</strong><span>decides</span></div>
        <ArrowRight aria-hidden="true" size={17} />
        <div data-role="gate"><strong>Gate</strong><span>enforces</span></div>
      </div>
    </div>
  );
}

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
      <SiteNav activePage="brain" />
      <main>
        <section className={styles.hero}>
          <div className={styles.gridField} aria-hidden="true" />
          <div className={styles.heroShell}>
            <div className={styles.heroCopy}>
              <div className={styles.heroKicker}>
                <span className={styles.liveDot} />
                CUSTOMER-OWNED AUTHORITY FOR AI AGENTS
              </div>
              <h1>Your AI can act. Map both sides first.</h1>
              <p>
                Authority Brain maps what the agent declares it can reach and where evidence should
                return. You decide which actions need authority. At a completely mediated executor,
                Gate checks the exact mandate before the action and binds authenticated outcome
                evidence afterward.
              </p>
              <div className={styles.signatureLine}>Two eyes. One before the action. One after.</div>
              <div className={styles.heroActions}>
                <a className={styles.primaryCta} href="#demo-heading">
                  Watch the Gate decide <ArrowRight aria-hidden="true" size={16} />
                </a>
                <a className={styles.secondaryCta} href="#run-local">Scan my agent locally</a>
              </div>
              <div className={styles.boundaryLine}>
                <ShieldCheck aria-hidden="true" size={16} />
                <span>Authority Brain proposes. The customer decides. Gate enforces.</span>
              </div>
            </div>
            <AuthorityBrainGraphic />
          </div>
        </section>

        <ProductStoryCallout product="authority-brain" />
        <ProductJourney active="authority-brain" />

        <section className={styles.loopSection} aria-labelledby="loop-heading">
          <div className={styles.sectionShell}>
            <div className={styles.sectionIntro}>
              <div className={styles.eyebrow}>A four-step path</div>
              <h2 id="loop-heading">See it. Decide it. Protect it. Prove it.</h2>
              <p>
                Authority Brain never turns visibility into permission. The owner sets the rule, and a
                real Gate at the executor boundary puts it into force.
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
                <h2 id="demo-heading">Actions your agent says it can take</h2>
                <p>
                  Choose an action to see what the owner would need to decide. These are fictional
                  examples. This page has not scanned your device, connected to your systems, blocked
                  production, or detected fraud.
                </p>
              </div>
              <div className={styles.demoSession}>
                <span className={styles.sessionDot} />
                Browser-only simulation · no external effect
              </div>
            </header>

            <div className={styles.metricGrid}>
              <div><span>Actions found</span><strong>{visibleAuthorityActionCount(AUTHORITY_ACTIONS)}</strong><small>fictional records</small></div>
              <div><span>Needs a decision</span><strong>{actionCount('review_required')}</strong><small>owner decides</small></div>
              <div><span>Read-only candidates</span><strong>{actionCount('pass_through_proposal')}</strong><small>proposal only</small></div>
              <div data-tone="red"><span>Paths not visible</span><strong>{actionCount('visibility_gap')}</strong><small>unknown stays unknown</small></div>
            </div>

            <div className={styles.dashboard}>
              <aside className={styles.inventoryPanel} aria-label="Synthetic action inventory">
                <div className={styles.panelTitle}>
                  <div><span>01 / What we can see</span><h3>Actions and unknown paths</h3></div>
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

              <p className={styles.srOnly} role="status">
                {pathAvailable
                  ? `Step ${demoStep + 1} of ${DEMO_STEPS.length}: ${DEMO_STEPS[demoStep].label}. ${DEMO_STEPS[demoStep].detail}`
                  : 'A protected proof path is not available for the selected action.'}
              </p>
              <ol className={styles.stageRail}>
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
                Authority Brain reduces the cost of finding and reviewing declared action surfaces.
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
                <button type="button" onClick={copyCommand} aria-label="Copy Authority Brain command">
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
