'use client';

// SPDX-License-Identifier: Apache-2.0
import Image from 'next/image';
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Check,
  CheckCircle2,
  ClipboardCheck,
  Download,
  FileCheck2,
  Fingerprint,
  Hammer,
  KeyRound,
  Landmark,
  LoaderCircle,
  LockKeyhole,
  PencilLine,
  QrCode,
  ShieldCheck,
  Smartphone,
  UserRound,
  UserRoundCheck,
  XCircle,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  createReleaseLockPairing,
  getReleaseLock,
  getReleaseLockEvidence,
} from '../api';
import {
  advanceDemoMilestone,
  amendDemoReleaseLock,
  initialDemoState,
  readDemoState,
  subscribeToDemoState,
} from '../demo-store';
import {
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
} from '../demo-fixture';
import { shortDigest } from '../digests';
import { approveReleaseLockWithPasskey } from '../passkey';
import ReleaseLockShell from '../ReleaseLockShell';
import ReleaseLockTerms, { formatReleaseLockExpiration } from '../ReleaseLockTerms';
import styles from '../release-lock.module.css';

const CEREMONY_CHECKS: Record<string, Array<[string, string]>> = {
  [CEREMONY_CO_ACCEPTANCE]: [
    ['Document', 'Reference and SHA-256 match this immutable version'],
    ['Scope', 'Rendered scope matches the accepted change order'],
    ['Price', 'Price and currency match the canonical acceptance action'],
    ['Schedule', 'Schedule effect is present in the acceptance action'],
  ],
  [CEREMONY_DRAW_RELEASE]: [
    ['Draw ID', 'Draw identifier matches the canonical release action'],
    ['Amount + payees', 'Total and named allocation match exactly'],
    ['Completion', 'Completion evidence reference and digest match'],
    ['Lien waiver', 'Lien-waiver evidence reference and digest match'],
  ],
};

function statusLabel(status: string): string {
  if (status === 'CO_ACCEPTED' || status === 'DRAW_RELEASE') return status;
  if (status === 'locked_until_milestone') return 'LOCKED';
  return 'PENDING';
}

interface CeremonyLedgerProps {
  lock: any;
  state: any;
}

function CeremonyLedger({ lock, state }: CeremonyLedgerProps): React.ReactElement {
  const co = state.ceremonies[CEREMONY_CO_ACCEPTANCE];
  const draw = state.ceremonies[CEREMONY_DRAW_RELEASE];
  return (
    <section className={styles.ceremonyLedger} aria-label="Release Lock ceremony ledger">
      <article data-complete={co.status === 'CO_ACCEPTED' ? 'true' : undefined}>
        <span className={styles.roundNumber}>01</span>
        <div>
          <span className={styles.eyebrow}>Before work · document acceptance</span>
          <h2>Change-order acceptance</h2>
          <p>Document · scope · price · schedule effect</p>
          <code>{shortDigest(lock.ceremonies[CEREMONY_CO_ACCEPTANCE].digest, 14, 9)}</code>
        </div>
        <span className={styles.ledgerStatus}>{statusLabel(co.status)}</span>
        <strong>Not payment authority</strong>
      </article>
      <ArrowRight aria-hidden="true" className={styles.ledgerArrow} />
      <article
        data-complete={draw.status === 'DRAW_RELEASE' ? 'true' : undefined}
        data-locked={draw.status === 'locked_until_milestone' ? 'true' : undefined}
      >
        <span className={styles.roundNumber}>02</span>
        <div>
          <span className={styles.eyebrow}>After milestone · draw approval</span>
          <h2>Draw release</h2>
          <p>Draw ID · amount · payees · completion + lien evidence</p>
          <code>{shortDigest(lock.ceremonies[CEREMONY_DRAW_RELEASE].digest, 14, 9)}</code>
        </div>
        <span className={styles.ledgerStatus}>{statusLabel(draw.status)}</span>
        <strong>Controls eligibility</strong>
      </article>
    </section>
  );
}

interface SeatCellProps {
  approval: any;
  locked?: boolean;
}

function SeatCell({ approval, locked }: SeatCellProps): React.ReactElement {
  if (locked) {
    return (
      <span className={styles.matrixStatus} data-locked="true">
        <LockKeyhole aria-hidden="true" size={13} />
        Locked
      </span>
    );
  }
  return (
    <span className={styles.matrixStatus} data-approved={approval ? 'true' : undefined}>
      {approval
        ? <CheckCircle2 aria-hidden="true" size={14} />
        : <LockKeyhole aria-hidden="true" size={13} />}
      {approval ? 'Approved' : 'Pending'}
    </span>
  );
}

interface PartyMatrixProps {
  lock: any;
  state: any;
}

function PartyMatrix({ lock, state }: PartyMatrixProps): React.ReactElement {
  const drawLocked = state.ceremonies[CEREMONY_DRAW_RELEASE].status === 'locked_until_milestone';
  return (
    <section className={styles.partyMatrix} aria-labelledby="party-matrix-title">
      <div className={styles.sidebarHeading}>
        <span className={styles.eyebrow}>Separate credentials</span>
        <h2 id="party-matrix-title">Party status by round</h2>
      </div>
      <div className={styles.matrixHeader}>
        <span>Party</span>
        <span>CO</span>
        <span>Draw</span>
      </div>
      {['contractor', 'customer'].map((role) => (
        <div className={styles.matrixRow} key={role}>
          <div>
            <span className={styles.seatIcon}>
              <UserRound aria-hidden="true" size={17} />
            </span>
            <div>
              <strong>{lock.contacts[role].role}</strong>
              <code>{lock.contacts[role].verified_handle}</code>
            </div>
          </div>
          <SeatCell
            approval={state.ceremonies[CEREMONY_CO_ACCEPTANCE].approvals[role]}
          />
          <SeatCell
            approval={state.ceremonies[CEREMONY_DRAW_RELEASE].approvals[role]}
            locked={drawLocked}
          />
        </div>
      ))}
      <div className={styles.partyRule}>
        <ShieldCheck aria-hidden="true" size={18} />
        <p>
          Each role keeps one separately enrolled credential across both ceremonies.
          Production also requires distinct subjects under one pinned external authority;
          that authority remains responsible for civil-identity proofing.
        </p>
      </div>
    </section>
  );
}

interface ActionCheckProps {
  lock: any;
  ceremony: string;
  locked?: boolean;
  demo?: boolean;
}

function ActionCheck({
  lock,
  ceremony,
  locked,
  demo,
}: ActionCheckProps): React.ReactElement {
  const definition = lock.ceremonies[ceremony];
  return (
    <section
      className={styles.actionCheck}
      aria-labelledby={`${ceremony}-action-check-title`}
      data-locked={locked ? 'true' : undefined}
    >
      <div className={styles.actionCheckHeader}>
        <div>
          <span className={styles.eyebrow}>{definition.code} comparison</span>
          <h2 id={`${ceremony}-action-check-title`}>Action Check</h2>
        </div>
        <span className={styles.checkVerdict}>
          {locked
            ? <LockKeyhole aria-hidden="true" size={15} />
            : <ShieldCheck aria-hidden="true" size={16} />}
          {locked ? 'Milestone locked' : demo ? '4 of 4 matched' : 'Exact fields pinned'}
        </span>
      </div>
      <div className={styles.checkRows}>
        {CEREMONY_CHECKS[ceremony].map(([label, detail]) => (
          <div key={label}>
            {locked
              ? <LockKeyhole aria-hidden="true" size={15} />
              : <Check aria-hidden="true" size={16} />}
            <strong>{label}</strong>
            <span>{detail}</span>
          </div>
        ))}
      </div>
      <div className={styles.actionDigest}>
        <Fingerprint aria-hidden="true" size={16} />
        <span>{definition.code} action digest</span>
        <code title={definition.digest}>{shortDigest(definition.digest, 18, 12)}</code>
      </div>
    </section>
  );
}

interface ApprovalCompleteProps {
  role: string;
  ceremony: string;
  approval: any;
  otherApproved: boolean;
  onSwitch: () => void;
  demo?: boolean;
}

function ApprovalComplete({
  role,
  ceremony,
  approval,
  otherApproved,
  onSwitch,
  demo,
}: ApprovalCompleteProps): React.ReactElement {
  const code = ceremony === CEREMONY_CO_ACCEPTANCE ? 'CO_ACCEPTED' : 'DRAW_RELEASE';
  return (
    <div className={styles.approvalComplete} role="status">
      <CheckCircle2 aria-hidden="true" size={26} />
      <div>
        <span>{role} · {code} approval recorded</span>
        <strong>This credential approved this ceremony digest only.</strong>
        <code>{approval?.credential_id}</code>
      </div>
      {demo && !otherApproved && (
        <button type="button" className={styles.secondaryButton} onClick={onSwitch}>
          Continue demo as {role === 'Customer' ? 'contractor' : 'customer'}
          <ArrowRight aria-hidden="true" size={16} />
        </button>
      )}
    </div>
  );
}

interface CeremonyApprovalProps {
  lock: any;
  state: any;
  ceremony: string;
  role?: string;
  demo?: boolean;
  locked?: boolean;
  mirrorOpen: boolean;
  qrDataUrl: string;
  busy: boolean;
  pairingBusy: boolean;
  onStartMirror: () => void;
  onOpenMirror: () => void;
  onApproveContractor: () => void;
  onSwitchRole: (role: string) => void;
}

function CeremonyApproval({
  lock,
  state,
  ceremony,
  role,
  demo,
  locked,
  mirrorOpen,
  qrDataUrl,
  busy,
  pairingBusy,
  onStartMirror,
  onOpenMirror,
  onApproveContractor,
  onSwitchRole,
}: CeremonyApprovalProps): React.ReactElement {
  const definition = lock.ceremonies[ceremony];
  const ceremonyState = state.ceremonies[ceremony];
  const approval = role ? ceremonyState.approvals[role] : null;
  const otherRole = role === 'customer' ? 'contractor' : 'customer';
  const otherApproved = role ? Boolean(ceremonyState.approvals[otherRole]) : false;
  const isCo = ceremony === CEREMONY_CO_ACCEPTANCE;

  return (
    <section
      className={styles.approvalPanel}
      aria-labelledby={`${ceremony}-approval-title`}
      data-locked={locked ? 'true' : undefined}
    >
      <div className={styles.approvalHeading}>
        <div>
          <span className={styles.eyebrow}>
            Round {definition.round} · {role} resolution
          </span>
          <h2 id={`${ceremony}-approval-title`}>
            {isCo ? 'Accept this exact change order' : 'Approve this exact draw release'}
          </h2>
        </div>
        {locked
          ? <LockKeyhole aria-hidden="true" size={22} />
          : <KeyRound aria-hidden="true" size={23} />}
      </div>

      {locked ? (
        <div className={styles.lockedApproval}>
          <LockKeyhole aria-hidden="true" size={23} />
          <div>
            <strong>Round 2 is not available yet.</strong>
            <p>CO_ACCEPTED and milestone evidence must exist before DRAW_RELEASE begins.</p>
          </div>
        </div>
      ) : approval ? (
        <ApprovalComplete
          role={role === 'customer' ? 'Customer' : 'Contractor'}
          ceremony={ceremony}
          approval={approval}
          otherApproved={otherApproved}
          onSwitch={() => onSwitchRole(otherRole)}
          demo={demo}
        />
      ) : role === 'customer' || !demo ? (
        <>
          {!mirrorOpen ? (
            <div className={styles.approvalPrompt}>
              <div>
                <Smartphone aria-hidden="true" size={24} />
                <div>
                  <strong>Continue with Action Mirror</strong>
                  <p>
                    Independently retrieve the canonical {isCo ? 'change order' : 'draw and evidence set'},
                    answer randomized exact-term questions, then use the {role} passkey.
                  </p>
                </div>
              </div>
              <button
                type="button"
                className={styles.primaryButton}
                onClick={onStartMirror}
                disabled={pairingBusy}
              >
                {pairingBusy
                  ? <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
                  : <QrCode aria-hidden="true" size={18} />}
                {pairingBusy ? 'Creating one-time pairing' : 'Start Action Mirror'}
              </button>
            </div>
          ) : (
            <div className={styles.mirrorPairing}>
              <div className={styles.qrFrame}>
                {qrDataUrl ? (
                  <Image
                    src={qrDataUrl}
                    alt={`QR code to retrieve the ${definition.label} in Action Mirror`}
                    width={184}
                    height={184}
                    unoptimized
                  />
                ) : (
                  <LoaderCircle
                    aria-label="Generating pairing QR code"
                    size={26}
                    className={styles.spin}
                  />
                )}
              </div>
              <div className={styles.pairingCopy}>
                <span className={styles.eyebrow}>Short pairing phrase</span>
                <strong>{definition.pairing_phrase}</strong>
                <p>
                  The phone route retrieves the {definition.code} action independently and renders
                  its exact canonical fields before requesting approval.
                </p>
                <button type="button" className={styles.primaryButton} onClick={onOpenMirror}>
                  <Smartphone aria-hidden="true" size={18} />
                  Open Action Mirror{demo ? ' demo' : ''}
                  <ArrowRight aria-hidden="true" size={16} />
                </button>
              </div>
            </div>
          )}
          <p className={styles.approvalBoundary}>
            {isCo
              ? 'CO_ACCEPTED records document acceptance only and is not payment authority. '
              : 'Only both DRAW_RELEASE approvals can make the custodian instruction eligible. '}
            Exact-term answers do not prove comprehension, identity, absence of coercion,
            device-bound hardware, or legal enforceability.
          </p>
        </>
      ) : (
        <>
          <div className={styles.approvalPrompt}>
            <div>
              <BadgeCheck aria-hidden="true" size={24} />
              <div>
                <strong>Contractor seat · {definition.code}</strong>
                <p>
                  Approve this ceremony digest with the separately enrolled contractor credential.
                  {isCo ? ' This does not authorize payment.' : ' This does not move funds.'}
                </p>
              </div>
            </div>
            <button
              type="button"
              className={styles.primaryButton}
              onClick={onApproveContractor}
              disabled={busy}
            >
              {busy
                ? <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
                : <KeyRound aria-hidden="true" size={18} />}
              {busy
                ? 'Waiting for demo credential'
                : `${isCo ? 'Accept' : 'Approve'} with ${demo ? 'demo ' : ''}passkey`}
            </button>
          </div>
          <p className={styles.approvalBoundary}>
            {isCo
              ? 'This CO_ACCEPTED resolution has no payment authority.'
              : 'Eligibility still requires the customer DRAW_RELEASE resolution over the same digest.'}
          </p>
        </>
      )}
    </section>
  );
}

interface ReleaseLockExperienceProps {
  lockId: string;
  initialLock: any;
  initialRole?: string;
  demo?: boolean;
}

export default function ReleaseLockExperience({
  lockId,
  initialLock,
  initialRole,
  demo,
}: ReleaseLockExperienceProps): React.ReactElement {
  const [lock, setLock] = useState<any>(initialLock);
  const [state, setState] = useState<any>(() => initialDemoState());
  const [role, setRole] = useState<string | undefined>(initialRole);
  const [mirrorOpen, setMirrorOpen] = useState<string | null>(null);
  const [pairingPath, setPairingPath] = useState<string>('');
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [busy, setBusy] = useState<string>('');
  const [downloading, setDownloading] = useState<boolean>(false);
  const [amendConfirm, setAmendConfirm] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const coComplete = state.ceremonies[CEREMONY_CO_ACCEPTANCE].status === 'CO_ACCEPTED';
  const milestoneReady = state.milestone.evidence_available;
  const drawComplete = state.ceremonies[CEREMONY_DRAW_RELEASE].status === 'DRAW_RELEASE';
  const releaseEligible = Boolean(state.release_instruction.eligible);

  useEffect(() => {
    let active = true;
    getReleaseLock(lockId)
      .then((result) => {
        if (!active) return;
        setLock(result.lock);
        if (result.state) setState(result.state);
        if (result.role === 'contractor' || result.role === 'customer') {
          setRole(result.role);
        }
      })
      .catch((caught) => {
        if (active) setError(caught.message || 'Release Lock could not be loaded.');
      });

    const unsubscribe = demo
      ? subscribeToDemoState((next) => {
        if (!active) return;
        setState(next);
        setLock(next.lock);
      })
      : () => {};

    return () => {
      active = false;
      unsubscribe();
    };
  }, [demo, lockId]);

  const mirrorPath = useMemo(() => {
    if (!mirrorOpen) return '';
    const query = new URLSearchParams({ ceremony: mirrorOpen });
    return `/release-lock/${encodeURIComponent(lockId)}/mirror?${query}`;
  }, [lockId, mirrorOpen]);
  const qrTargetPath = demo ? mirrorPath : pairingPath;

  useEffect(() => {
    if (!qrTargetPath || typeof window === 'undefined') return;
    let active = true;
    const target = `${window.location.origin}${qrTargetPath}`;
    import('qrcode')
      .then((module) => {
        const QRCode = module.default || module;
        return QRCode.toDataURL(target, {
          width: 184,
          margin: 1,
          color: {
            dark: '#0C0A09',
            light: '#FFFFFF',
          },
        });
      })
      .then((value) => {
        if (active) setQrDataUrl(value);
      })
      .catch(() => {
        if (active) setQrDataUrl('');
      });
    return () => {
      active = false;
    };
  }, [qrTargetPath]);

  if (!lock) {
    return (
      <ReleaseLockShell demo={demo} statusLabel="Loading exact version">
        <main className={styles.centeredState}>
          <LoaderCircle aria-hidden="true" size={28} className={styles.spin} />
          <span className={styles.eyebrow}>Release Lock</span>
          <h1>Retrieving the canonical ceremonies</h1>
        </main>
      </ReleaseLockShell>
    );
  }

  function switchRole(nextRole) {
    if (!demo) return;
    document.cookie = `release_lock_demo_role=${nextRole}; Path=/release-lock; SameSite=Lax`;
    setRole(nextRole);
    setMirrorOpen(null);
    setPairingPath('');
    setQrDataUrl('');
    setError('');
  }

  async function approveContractor(ceremony) {
    setBusy(ceremony);
    setError('');
    try {
      const result = await approveReleaseLockWithPasskey({
        lockId,
        ceremony,
        role: 'contractor',
        verifiedHandle: lock.contacts.contractor.verified_handle,
        bindings: {
          action_digest: lock.ceremonies[ceremony].digest,
        },
      });
      if (!demo && result.state) setState(result.state);
      if (demo) setState(readDemoState());
    } catch (caught) {
      setError(caught.message || 'The contractor approval was not recorded.');
    } finally {
      setBusy('');
    }
  }

  async function startMirror(ceremony) {
    setMirrorOpen(ceremony);
    setPairingPath('');
    setQrDataUrl('');
    setError('');
    if (demo) return;
    setBusy(`pairing:${ceremony}`);
    try {
      const pairing = await createReleaseLockPairing(lockId, ceremony);
      setPairingPath(pairing.pairing_path);
    } catch (caught) {
      setMirrorOpen(null);
      setError(caught.message || 'A one-time Action Mirror pairing could not be created.');
    } finally {
      setBusy('');
    }
  }

  function openMirror() {
    const compact = window.matchMedia('(max-width: 680px)').matches;
    if (compact) {
      window.location.assign(mirrorPath);
      return;
    }
    window.open(mirrorPath, '_blank', 'noopener,noreferrer');
  }

  function advanceMilestone() {
    setError('');
    try {
      const next = advanceDemoMilestone();
      setState(next);
    } catch (caught) {
      setError(caught.message || 'The milestone could not be advanced.');
    }
  }

  function confirmAmendment() {
    const next = amendDemoReleaseLock();
    setState(next);
    setLock(next.lock);
    setMirrorOpen(null);
    setPairingPath('');
    setAmendConfirm(false);
    setRole('contractor');
    window.scrollTo(0, 0);
  }

  async function downloadEvidence() {
    setDownloading(true);
    setError('');
    try {
      const blob = await getReleaseLockEvidence(lockId);
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = `release-lock-${lock.id}-evidence.json`;
      anchor.click();
      URL.revokeObjectURL(href);
    } catch (caught) {
      setError(caught.message || 'Portable evidence could not be downloaded.');
    } finally {
      setDownloading(false);
    }
  }

  return (
    <ReleaseLockShell
      demo={demo}
      role={role === 'contractor' ? 'Contractor' : 'Customer'}
      statusLabel={releaseEligible ? 'DRAW_RELEASE eligible' : 'Two-round lock'}
    >
      <main>
        <section className={styles.lockSummaryBand}>
          <div className={styles.lockSummaryInner}>
            <div className={styles.lockIdentity}>
              <span className={styles.eyebrow}>{lock.project}</span>
              <h1>{lock.title}</h1>
              <div className={styles.lockMeta}>
                <span>
                  <FileCheck2 aria-hidden="true" size={15} />
                  Immutable version {lock.version.number}
                </span>
                <span>
                  CO acceptance expires {formatReleaseLockExpiration(lock.expiration)}
                </span>
              </div>
            </div>
            <div className={styles.lockAmount}>
              <span>Planned draw</span>
              <strong>{lock.draw.amount.display}</strong>
              <small>
                {lock.draw.id} · {releaseEligible ? 'DRAW_RELEASE eligible' : 'blocked until DRAW_RELEASE'}
              </small>
            </div>
          </div>
        </section>

        {state.amendment && (
          <section className={styles.amendmentNotice} role="status">
            <PencilLine aria-hidden="true" size={20} />
            <div>
              <strong>Both ceremonies invalidated by amendment.</strong>
              <p>
                Version {(state.amendment as { prior_version: number; new_version: number }).prior_version} approvals no longer apply. Version
                {' '}{(state.amendment as { prior_version: number; new_version: number }).new_version} requires new CO_ACCEPTED and DRAW_RELEASE rounds.
              </p>
            </div>
          </section>
        )}

        {demo && (
          <section className={styles.demoSeatControl} aria-label="Demo seat">
            <div>
              <span>Demo seat</span>
              <p>Switch views to complete each independent party resolution.</p>
            </div>
            <div className={styles.segmentedControl} role="group" aria-label="Choose demo role">
              <button
                type="button"
                aria-pressed={role === 'contractor'}
                onClick={() => switchRole('contractor')}
              >
                <Hammer aria-hidden="true" size={15} />
                Contractor
              </button>
              <button
                type="button"
                aria-pressed={role === 'customer'}
                onClick={() => switchRole('customer')}
              >
                <UserRound aria-hidden="true" size={15} />
                Customer
              </button>
            </div>
          </section>
        )}

        <CeremonyLedger lock={lock} state={state} />

        <div className={styles.reviewLayout}>
          <div className={styles.reviewMain}>
            <ReleaseLockTerms lock={lock} ceremony={CEREMONY_CO_ACCEPTANCE} />
            <ActionCheck
              lock={lock}
              ceremony={CEREMONY_CO_ACCEPTANCE}
              demo={demo}
            />
            <CeremonyApproval
              lock={lock}
              state={state}
              ceremony={CEREMONY_CO_ACCEPTANCE}
              role={role}
              demo={demo}
              locked={false}
              mirrorOpen={mirrorOpen === CEREMONY_CO_ACCEPTANCE}
              qrDataUrl={qrDataUrl}
              busy={busy === CEREMONY_CO_ACCEPTANCE}
              pairingBusy={busy === `pairing:${CEREMONY_CO_ACCEPTANCE}`}
              onStartMirror={() => startMirror(CEREMONY_CO_ACCEPTANCE)}
              onOpenMirror={openMirror}
              onApproveContractor={() => approveContractor(CEREMONY_CO_ACCEPTANCE)}
              onSwitchRole={switchRole}
            />

            <section
              className={`${styles.milestoneGate} ${milestoneReady ? styles.milestoneGateReady : ''}`}
              aria-live="polite"
            >
              {milestoneReady
                ? <ClipboardCheck aria-hidden="true" size={26} />
                : <Landmark aria-hidden="true" size={25} />}
              <div>
                <span className={styles.eyebrow}>Between ceremonies</span>
                <h2>
                  {milestoneReady
                    ? 'Milestone evidence available'
                    : coComplete
                      ? 'CO_ACCEPTED · work may proceed'
                      : 'Milestone stage locked'}
                </h2>
                <p>
                  {milestoneReady
                    ? `${lock.draw.completion_evidence.reference} and `
                      + `${lock.draw.lien_waiver_evidence.reference} are now bound to ${lock.draw.id}.`
                    : coComplete
                      ? 'Round 1 is complete but carries no payment authority. Advance the demo only after the milestone.'
                      : 'Both parties must accept the change order before the milestone stage begins.'}
                </p>
              </div>
              {demo && coComplete && !milestoneReady && (
                <button type="button" className={styles.secondaryButton} onClick={advanceMilestone}>
                  <ClipboardCheck aria-hidden="true" size={17} />
                  Advance demo to completed milestone
                </button>
              )}
            </section>

            <ReleaseLockTerms lock={lock} ceremony={CEREMONY_DRAW_RELEASE} />
            <ActionCheck
              lock={lock}
              ceremony={CEREMONY_DRAW_RELEASE}
              locked={!milestoneReady}
              demo={demo}
            />
            <CeremonyApproval
              lock={lock}
              state={state}
              ceremony={CEREMONY_DRAW_RELEASE}
              role={role}
              demo={demo}
              locked={!milestoneReady}
              mirrorOpen={mirrorOpen === CEREMONY_DRAW_RELEASE}
              qrDataUrl={qrDataUrl}
              busy={busy === CEREMONY_DRAW_RELEASE}
              pairingBusy={busy === `pairing:${CEREMONY_DRAW_RELEASE}`}
              onStartMirror={() => startMirror(CEREMONY_DRAW_RELEASE)}
              onOpenMirror={openMirror}
              onApproveContractor={() => approveContractor(CEREMONY_DRAW_RELEASE)}
              onSwitchRole={switchRole}
            />

            {error && (
              <div className={styles.formError} role="alert">
                <AlertTriangle aria-hidden="true" size={17} />
                {error}
              </div>
            )}
          </div>

          <aside className={styles.reviewSidebar}>
            <PartyMatrix lock={lock} state={state} />

            <section className={styles.instructionPanel} aria-labelledby="instruction-title">
              <span className={styles.eyebrow}>Custodian instruction</span>
              <h2 id="instruction-title">{lock.draw.id}</h2>
              <p>{lock.draw.instruction}</p>
              <dl>
                <div>
                  <dt>Status</dt>
                  <dd>{releaseEligible ? 'Eligible · not executed' : 'Blocked'}</dd>
                </div>
                <div>
                  <dt>Eligibility source</dt>
                  <dd>DRAW_RELEASE only</dd>
                </div>
                <div>
                  <dt>Funds held by EMILIA</dt>
                  <dd>None</dd>
                </div>
              </dl>
            </section>

            <section className={styles.versionPolicy}>
              <PencilLine aria-hidden="true" size={20} />
              <div>
                <span className={styles.eyebrow}>Amendment rule</span>
                <h2>New version, two new ceremonies</h2>
                <p>
                  Any material amendment changes both action digests and invalidates CO_ACCEPTED
                  and DRAW_RELEASE approvals from the prior version.
                </p>
                {demo && !amendConfirm && (
                  <button
                    type="button"
                    className={styles.quietButton}
                    onClick={() => setAmendConfirm(true)}
                  >
                    <PencilLine aria-hidden="true" size={16} />
                    Simulate amended version
                  </button>
                )}
              </div>
              {demo && amendConfirm && (
                <div className={styles.amendConfirm}>
                  <AlertTriangle aria-hidden="true" size={17} />
                  <p>Version 2 will clear approvals from both rounds and block eligibility.</p>
                  <button type="button" onClick={confirmAmendment}>
                    Invalidate both ceremonies
                  </button>
                  <button type="button" onClick={() => setAmendConfirm(false)}>
                    Cancel
                  </button>
                </div>
              )}
            </section>
          </aside>
        </div>

        <section
          className={`${styles.eligibilityBand} ${releaseEligible ? styles.eligibilityBandReady : ''}`}
          aria-live="polite"
        >
          <div>
            {releaseEligible
              ? <CheckCircle2 aria-hidden="true" size={27} />
              : <LockKeyhole aria-hidden="true" size={25} />}
            <div>
              <span className={styles.eyebrow}>Custodian instruction</span>
              <h2>
                {releaseEligible ? 'DRAW_RELEASE · instruction eligible' : 'Draw release blocked'}
              </h2>
              <p>
                {releaseEligible
                  ? 'Both DRAW_RELEASE credentials approved the exact draw and evidence set. No funds moved.'
                  : drawComplete
                    ? 'DRAW_RELEASE recorded; evaluating instruction state.'
                    : 'CO_ACCEPTED alone cannot authorize this instruction.'}
              </p>
            </div>
          </div>
          <button
            type="button"
            className={styles.evidenceButton}
            disabled={!releaseEligible || downloading}
            onClick={downloadEvidence}
          >
            {downloading
              ? <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
              : <Download aria-hidden="true" size={18} />}
            {downloading ? 'Preparing evidence' : 'Download portable evidence'}
          </button>
        </section>

        <section className={styles.safeguardBand} aria-labelledby="safeguards-title">
          <div className={styles.safeguardHeader}>
            <div>
              <span className={styles.eyebrow}>Deterministic refusal record</span>
              <h2 id="safeguards-title">Changed or reused actions stay closed</h2>
            </div>
            <span className={styles.refusalCount}>
              <XCircle aria-hidden="true" size={16} />
              4 of 4 refused
            </span>
          </div>
          <div className={styles.refusalRows}>
            {lock.refusals.map((refusal) => (
              <article key={refusal.id}>
                <XCircle aria-hidden="true" size={18} />
                <div>
                  <h3>{refusal.title}</h3>
                  <p>{refusal.detail}</p>
                </div>
                <code>{refusal.reason}</code>
              </article>
            ))}
          </div>
          <div className={styles.portableLine}>
            <ClipboardCheck aria-hidden="true" size={20} />
            <div>
              <strong>{releaseEligible ? 'Portable evidence ready' : 'Portable evidence pending'}</strong>
              <span>
                Separate CO_ACCEPTED and DRAW_RELEASE terms, digests, Action Mirror bindings,
                credential resolutions, milestone evidence, and refusals.
              </span>
            </div>
            <code>{shortDigest(lock.evidence.package_digest, 14, 10)}</code>
          </div>
        </section>

        <section className={styles.honestBoundary}>
          <AlertTriangle aria-hidden="true" size={19} />
          <p>
            Release Lock records exact-version acceptance and draw-approval evidence. CO_ACCEPTED
            is not payment authority. Release Lock does not hold funds, judge workmanship,
            establish legal enforceability, or establish what a person understood or whether they
            acted without pressure.
          </p>
        </section>
      </main>
    </ReleaseLockShell>
  );
}
