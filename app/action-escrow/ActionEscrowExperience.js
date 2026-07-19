'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Banknote,
  Building2,
  Check,
  CheckCircle2,
  ClipboardCheck,
  Download,
  FileCheck2,
  FileJson2,
  FileText,
  Fingerprint,
  GitCommitHorizontal,
  Hammer,
  KeyRound,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  UserRoundCheck,
  UsersRound,
  XCircle,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import styles from './action-escrow.module.css';

const ROW_ICONS = {
  project: Building2,
  document: FileCheck2,
  approvals: UsersRound,
  custodian: Banknote,
};

const OUTCOME_ICONS = {
  approve: CheckCircle2,
  decline: XCircle,
  reject: LockKeyhole,
  amend: GitCommitHorizontal,
};

function short(value, start = 12, end = 8) {
  if (typeof value !== 'string' || value.length <= start + end + 3) return value || 'not available';
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

function formatBytes(value) {
  return `${Math.max(1, Math.round(Number(value) / 1024))} KB`;
}

function Status({ pass, children, tone = 'green' }) {
  const Icon = pass ? CheckCircle2 : XCircle;
  return (
    <span className={`${styles.status} ${styles[`status${tone}`]}`}>
      <Icon aria-hidden="true" size={15} strokeWidth={2.2} />
      {children}
    </span>
  );
}

function IntegrationRow({ row, index, phase }) {
  const Icon = ROW_ICONS[row.id] || ShieldCheck;
  const complete = phase >= index;
  return (
    <article
      className={`${styles.integrationRow} ${complete ? styles.integrationRowComplete : ''}`}
      data-testid={`action-escrow-row-${row.id}`}
    >
      <div className={styles.rowNumber}>{row.number}</div>
      <div className={styles.rowIcon}><Icon aria-hidden="true" size={22} /></div>
      <div className={styles.rowMain}>
        <div className={styles.rowTitleLine}>
          <h3>{row.label}</h3>
          <Status pass={complete && row.pass}>{complete ? row.status : 'CHECKING'}</Status>
        </div>
        <p>{complete ? row.detail : 'Replaying the recorded verification result for this layer.'}</p>
        <div className={styles.rowSource}>
          <span>{row.source}</span>
          <strong>{row.boundary}</strong>
        </div>
      </div>
    </article>
  );
}

export default function ActionEscrowExperience({ data }) {
  const [activeOutcome, setActiveOutcome] = useState('approve');
  const [phase, setPhase] = useState(data.integration_rows.length - 1);
  const [running, setRunning] = useState(false);
  const timers = useRef([]);

  const clearTimers = useCallback(() => {
    timers.current.forEach((timer) => window.clearTimeout(timer));
    timers.current = [];
  }, []);

  const replayChecks = () => {
    clearTimers();
    setRunning(true);
    setPhase(-1);
    data.integration_rows.forEach((_, index) => {
      timers.current.push(window.setTimeout(() => {
        setPhase(index);
        if (index === data.integration_rows.length - 1) setRunning(false);
      }, 260 + index * 520));
    });
  };

  useEffect(() => clearTimers, [clearTimers]);

  const outcome = useMemo(
    () => data.outcomes.find((entry) => entry.outcome === activeOutcome) || data.outcomes[0],
    [activeOutcome, data.outcomes],
  );
  const allAttacksRefused = data.attacks.every((attack) => attack.refused);

  return (
    <main className={styles.page}>
      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <div className={styles.heroCopy}>
            <div className={styles.kicker}>
              <Hammer aria-hidden="true" size={15} />
              EMILIA ACTION ESCROW · CONTRACTOR VIEW
            </div>
            <h1>Action Escrow</h1>
            <p className={styles.promise}>Both sides sign. The system obeys.</p>
            <p className={styles.heroLede}>
              Your e-sign provider proves the document was signed. EMILIA makes the system obey it.
            </p>
            <p className={styles.heroBoundary}>
              This reference run uses real signatures, the shipped DAB verifier, and the Action
              Escrow kernel. Project-system, e-sign, and custody provider adapters are simulated.
              No real money moves.
            </p>
            <div className={styles.heroActions}>
              <a className={styles.primaryButton} href="/action-escrow/evidence-bundle">
                <FileJson2 aria-hidden="true" size={18} />
                Download evidence bundle
              </a>
              <a className={styles.secondaryButton} href="/action-escrow/final-agreement?download=1">
                <Download aria-hidden="true" size={18} />
                Download final PDF
              </a>
            </div>
          </div>

          <aside className={styles.releaseSummary} aria-label="Milestone release summary">
            <div className={styles.simulationFlag}>
              <AlertTriangle aria-hidden="true" size={16} />
              SIMULATED CUSTODY
            </div>
            <span className={styles.summaryLabel}>Milestone release</span>
            <strong className={styles.summaryAmount}>{data.project.release_amount}</strong>
            <span className={styles.summaryProject}>{data.project.milestone}</span>
            <dl className={styles.summaryFacts}>
              <div><dt>Gate</dt><dd>Allowed once</dd></div>
              <div><dt>Approvals</dt><dd>2 of 2</dd></div>
              <div><dt>Evidence</dt><dd>Portable</dd></div>
              <div><dt>Money held by EMILIA</dt><dd>None</dd></div>
            </dl>
          </aside>
        </div>
      </section>

      <section className={styles.clearanceBand}>
        <div className={styles.sectionInner}>
          <div className={styles.sectionHeader}>
            <div>
              <span className={styles.eyebrow}>Release clearance</span>
              <h2>Six evidence rows. Two explicit approval seats.</h2>
              <p>
                This mutual-release demo requires both the homeowner and contractor. It does not
                claim initiator exclusion: the contractor submits the milestone evidence and also
                fills the contractor approval seat. Deployments that require initiator exclusion
                set <code>prohibit_self_approval</code> and Gate refuses that overlap.
              </p>
            </div>
            <button type="button" className={styles.replayButton} onClick={replayChecks} disabled={running}>
              <RefreshCw aria-hidden="true" size={17} className={running ? styles.spin : undefined} />
              Replay verification trace
            </button>
          </div>
          <div className={styles.integrationRows} aria-live="polite">
            {data.integration_rows.map((row, index) => (
              <IntegrationRow key={row.id} row={row} index={index} phase={phase} />
            ))}
          </div>
        </div>
      </section>

      <section className={styles.artifactBand}>
        <div className={styles.sectionInner}>
          <div className={styles.sectionHeader}>
            <div>
              <span className={styles.eyebrow}>Final agreement</span>
              <h2>One PDF. One signed binding.</h2>
            </div>
            <div className={styles.hashBadge}>
              <Fingerprint aria-hidden="true" size={16} />
              {short(data.document.sha256, 14, 10)}
            </div>
          </div>

          <div className={styles.artifactGrid}>
            <div className={styles.pdfTool}>
              <div className={styles.pdfToolbar}>
                <div>
                  <FileText aria-hidden="true" size={18} />
                  <span>{data.document.filename}</span>
                </div>
                <span>{formatBytes(data.document.size_bytes)}</span>
              </div>
              <div className={styles.pdfPage} aria-label="Preview of the final milestone agreement">
                <div className={styles.pdfStamp}>FINAL · V2</div>
                <span>ACTION ESCROW AGREEMENT</span>
                <h3>{data.project.name}</h3>
                <p>{data.project.milestone}</p>
                <dl>
                  <div><dt>Release</dt><dd>{data.project.release_amount} {data.project.currency}</dd></div>
                  <div><dt>Payee</dt><dd>{data.project.contractor}</dd></div>
                  <div><dt>Destination</dt><dd>{data.project.destination_id}</dd></div>
                  <div><dt>Amendment</dt><dd>Version {data.project.amendment_version}</dd></div>
                </dl>
                <div className={styles.pdfRule}>
                  Separate exact-action approval from both parties is required before release.
                </div>
                <div className={styles.documentSigners}>
                  <span><Check aria-hidden="true" size={14} /> Homeowner signed</span>
                  <span><Check aria-hidden="true" size={14} /> Contractor signed</span>
                </div>
                <strong className={styles.notAuthority}>SIGNED DOCUMENT ≠ PAYMENT AUTHORIZATION</strong>
              </div>
            </div>

            <div className={styles.termsTool}>
              <div className={styles.toolHeading}>
                <div>
                  <FileJson2 aria-hidden="true" size={19} />
                  <span>Structured material terms</span>
                </div>
                <Status pass={data.document.verification.verified}>MATCHED</Status>
              </div>
              <dl className={styles.termsList}>
                <div><dt>Agreement</dt><dd>{data.document.material_terms.agreement_id}</dd></div>
                <div><dt>Milestone</dt><dd>{data.document.material_terms.milestone.id}</dd></div>
                <div><dt>Release amount</dt><dd>{data.project.release_amount}</dd></div>
                <div><dt>Retainage</dt><dd>$4,600.00</dd></div>
                <div><dt>Destination</dt><dd>{data.project.destination_id}</dd></div>
                <div><dt>Bound terms</dt><dd>{data.document.binding_material_terms.length} typed values</dd></div>
              </dl>
              <div className={styles.digestStack}>
                <div><span>PDF SHA-256</span><code>{short(data.document.sha256, 16, 12)}</code></div>
                <div><span>DAB terms SHA-256</span><code>{short(data.document.material_terms_sha256, 16, 12)}</code></div>
                <div><span>DAB binding SHA-256</span><code>{short(data.document.mapping_sha256, 16, 12)}</code></div>
              </div>
              <div className={styles.providerNotice}>
                <Building2 aria-hidden="true" size={18} />
                <div>
                  <strong>{data.project_record.provider} source adapter</strong>
                  <span>
                    {data.project_record.change_order_number} · {data.project_record.line_item_count}
                    {' '}line items · {data.project_record.notice}
                  </span>
                </div>
              </div>
              <div className={styles.providerNotice}>
                <BadgeCheck aria-hidden="true" size={18} />
                <div>
                  <strong>{data.document.signing_provider.name} adapter</strong>
                  <span>{data.document.signing_provider.notice}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.actionBand}>
        <div className={styles.sectionInner}>
          <div className={styles.sectionHeader}>
            <div>
              <span className={styles.eyebrow}>Binding moment</span>
              <h2>Both parties approve this exact release.</h2>
            </div>
            <Status pass tone="blue">ACTION DIGEST {short(data.release.action_sha256, 10, 8)}</Status>
          </div>

          <div className={styles.actionLedger}>
            <div className={styles.actionAmount}>
              <span>Release exactly</span>
              <strong>{data.project.release_amount}</strong>
              <small>{data.project.currency} · one-time milestone release</small>
            </div>
            <dl className={styles.actionFields}>
              <div><dt>Destination</dt><dd>{data.project.destination_id}</dd></div>
              <div><dt>Final document</dt><dd>{short(data.release.action.document_sha256)}</dd></div>
              <div><dt>Material terms</dt><dd>{short(data.release.action.material_terms_sha256)}</dd></div>
              <div><dt>Project source</dt><dd>{short(data.release.action.project_record_snapshot_digest)}</dd></div>
              <div><dt>Milestone evidence</dt><dd>{short(data.release.action.completion_evidence_sha256)}</dd></div>
              <div><dt>Amendment version</dt><dd>{data.release.action.amendment_version}</dd></div>
              <div><dt>Custodian transaction</dt><dd>{data.release.action.custodian_transaction_id}</dd></div>
            </dl>
          </div>

          <div className={styles.approvalLine}>
            {[
              ['Homeowner', data.release.approvals.homeowner],
              ['Contractor', data.release.approvals.contractor],
            ].map(([label, approval]) => (
              <div className={styles.approvalSeat} key={label}>
                <UserRoundCheck aria-hidden="true" size={24} />
                <div>
                  <span>{label}</span>
                  <strong>{approval.outcome.toUpperCase()}</strong>
                  <code>{approval.receipt_id}</code>
                </div>
                <Status pass={approval.verification.valid}>VERIFIED</Status>
              </div>
            ))}
          </div>

          <div className={styles.completionStrip}>
            <ClipboardCheck aria-hidden="true" size={21} />
            <div>
              <strong>Completion evidence submitted</strong>
              <span>{data.completion.artifacts.length} files + signed contractor statement</span>
            </div>
            <code>{short(data.completion.sha256, 14, 10)}</code>
            <p>Integrity evidence only. EMILIA does not judge workmanship or physical completion.</p>
          </div>
        </div>
      </section>

      <section className={styles.outcomeBand}>
        <div className={styles.sectionInner}>
          <div className={styles.sectionHeader}>
            <div>
              <span className={styles.eyebrow}>Signed outcome lab</span>
              <h2>Four decisions keep their meaning.</h2>
            </div>
            <p className={styles.sectionNote}>Each choice is a separate deterministic fork over the same exact action.</p>
          </div>

          <div className={styles.outcomeControl} role="group" aria-label="Inspect signed decision outcomes">
            {data.outcomes.map((entry) => {
              const Icon = OUTCOME_ICONS[entry.outcome] || KeyRound;
              return (
                <button
                  type="button"
                  key={entry.outcome}
                  className={activeOutcome === entry.outcome ? styles.outcomeActive : ''}
                  aria-pressed={activeOutcome === entry.outcome}
                  onClick={() => setActiveOutcome(entry.outcome)}
                >
                  <Icon aria-hidden="true" size={17} />
                  {entry.title}
                </button>
              );
            })}
          </div>

          <div className={styles.outcomeDetail} data-outcome={outcome.outcome}>
            <div className={styles.outcomeIcon}>
              {(() => {
                const Icon = OUTCOME_ICONS[outcome.outcome] || KeyRound;
                return <Icon aria-hidden="true" size={30} />;
              })()}
            </div>
            <div>
              <span>HOMEOWNER DECISION · {outcome.outcome.toUpperCase()}</span>
              <h3>{outcome.detail}</h3>
              <p>
                Signed receipt <code>{outcome.receipt_id}</code> verifies.{' '}
                {outcome.release_authorized
                  ? 'Together with the contractor approval, this fork is eligible for Gate evaluation.'
                  : 'This fork cannot authorize the original release.'}
              </p>
            </div>
            <div className={styles.outcomeVerdict}>
              <Status pass={outcome.release_authorized} tone={outcome.release_authorized ? 'green' : 'red'}>
                {outcome.release_authorized ? 'GATE ELIGIBLE' : 'NO RELEASE'}
              </Status>
              <span>{outcome.effect.replaceAll('_', ' ')}</span>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.custodyBand}>
        <div className={styles.sectionInner}>
          <div className={styles.custodyHeader}>
            <div>
              <span className={styles.eyebrow}>External funds rail</span>
              <h2>{data.custodian.provider.display_name}</h2>
              <p>{data.custodian.provider.notice}</p>
            </div>
            <div className={styles.custodyFlag}>
              <AlertTriangle aria-hidden="true" size={18} />
              SIMULATED LICENSED-CUSTODIAN MODEL
            </div>
          </div>

          <div className={styles.custodyTimeline}>
            <div>
              <span className={styles.timelineDot}><Check aria-hidden="true" size={15} /></span>
              <small>STATE 01</small>
              <strong>Funded</strong>
              <p>{data.project.release_amount} reported available for {data.project.milestone}.</p>
              <Status pass={data.custodian.funding_verification.valid}>SIGNED STATE</Status>
            </div>
            <ArrowRight aria-hidden="true" className={styles.timelineArrow} />
            <div>
              <span className={styles.timelineDot}><Check aria-hidden="true" size={15} /></span>
              <small>GATE</small>
              <strong>Released once</strong>
              <p>Exact action cleared; the simulated custodian adapter was invoked one time.</p>
              <Status pass={data.release.gate.release_calls === 1}>1 CALL</Status>
            </div>
            <ArrowRight aria-hidden="true" className={styles.timelineArrow} />
            <div>
              <span className={styles.timelineDot}><LockKeyhole aria-hidden="true" size={15} /></span>
              <small>STATE 02</small>
              <strong>Replay closed</strong>
              <p>The same receipt was presented again and never reached the custodian.</p>
              <Status pass={data.release.gate.replay_refused}>REPLAY REFUSED</Status>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.attackBand} data-testid="action-escrow-attacks">
        <div className={styles.sectionInner}>
          <div className={styles.sectionHeader}>
            <div>
              <span className={styles.eyebrow}>Attack bench</span>
              <h2>Change one material fact. The release closes.</h2>
            </div>
            <Status pass={allAttacksRefused} tone="red">{data.attacks.length} OF {data.attacks.length} REFUSED</Status>
          </div>

          <div className={styles.attackGrid}>
            {data.attacks.map((attack, index) => (
              <article className={styles.attackItem} key={attack.id} data-testid={`action-escrow-attack-${attack.id}`}>
                <div className={styles.attackTopline}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <Status pass={attack.refused} tone="red">REFUSED</Status>
                </div>
                <h3>{attack.title}</h3>
                <p>{attack.mutation}</p>
                <code>{attack.reason}</code>
                <small>{attack.detail}</small>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.bundleBand}>
        <div className={styles.sectionInner}>
          <div className={styles.bundleLayout}>
            <div className={styles.bundleIcon}><ShieldCheck aria-hidden="true" size={30} /></div>
            <div className={styles.bundleCopy}>
              <span className={styles.eyebrow}>Portable evidence for both parties</span>
              <h2>Take the verified manifest and its exact final PDF with you.</h2>
              <p>
                The shipped evidence-package manifest keeps document execution, agreement
                acceptances, exact release approvals, funding, completion evidence, custodian
                release, and signed durable state distinct. The final PDF and project source record
                travel beside it; both are joined by digests inside the exact release action.
              </p>
              <div className={styles.bundleChecks}>
                <span><Check aria-hidden="true" size={15} /> Homeowner copy</span>
                <span><Check aria-hidden="true" size={15} /> Contractor copy</span>
                <span><Check aria-hidden="true" size={15} /> Package re-performed</span>
              </div>
            </div>
            <div className={styles.bundleActions}>
              <a className={styles.primaryButton} href="/action-escrow/evidence-bundle">
                <FileJson2 aria-hidden="true" size={18} />
                Download evidence JSON
              </a>
              <a className={styles.secondaryButtonLight} href="/action-escrow/final-agreement?download=1">
                <Download aria-hidden="true" size={18} />
                Download final PDF
              </a>
              <a className={styles.secondaryButtonLight} href="/action-escrow/project-record">
                <Building2 aria-hidden="true" size={18} />
                Download project record
              </a>
              <code>{short(data.bundle.digest, 16, 12)}</code>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.boundaryBand}>
        <div className={styles.sectionInner}>
          <AlertTriangle aria-hidden="true" size={22} />
          <div>
            <strong>Honest boundary</strong>
            <p>
              Simulated providers, parties, project records, license reference, evidence files, and
              balances. Real cryptography and Gate behavior. No claim of legal enforceability,
              identity, comprehension, workmanship, physical completion, provider licensing, or
              non-bypassability outside the protected release path.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
