// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import {
  CircleDollarSign,
  FileCheck2,
  Fingerprint,
  ShieldCheck,
} from 'lucide-react';
import {
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
} from './demo-fixture';
import { shortDigest } from './digests';
import styles from './release-lock.module.css';

export function formatReleaseLockExpiration(value: unknown): string {
  const date = new Date(value as string | number);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZone: 'America/Los_Angeles',
    timeZoneName: 'short',
  }).format(date);
}

interface LockData {
  project: string;
  document: { reference: string; digest: string };
  scope_summary: string;
  amount: { display: string; currency: string };
  schedule_effect: string;
  expiration: string;
  draw: {
    id: string;
    amount: { display: string; currency: string };
    payees: Array<{ name: string; amount: string }>;
    completion_evidence: { reference: string; digest: string };
    lien_waiver_evidence: { reference: string; digest: string };
    instruction: string;
  };
  version: { number: number };
  ceremonies: Record<string, { code: string; round: number; label: string; digest: string }>;
}

interface CoTermsProps {
  lock: LockData;
  compact?: boolean;
}

function CoTerms({ lock, compact }: CoTermsProps): React.ReactElement {
  return (
    <>
      <dl className={styles.termRows}>
        <div>
          <dt>Project</dt>
          <dd>{lock.project}</dd>
        </div>
        <div>
          <dt>Change-order document</dt>
          <dd>{lock.document.reference}</dd>
        </div>
        <div className={styles.termRowWide}>
          <dt>Scope summary</dt>
          <dd>{lock.scope_summary}</dd>
        </div>
        <div>
          <dt>Price effect</dt>
          <dd className={styles.termAmount}>
            {lock.amount.display} <span>{lock.amount.currency}</span>
          </dd>
        </div>
        <div>
          <dt>Schedule effect</dt>
          <dd>{lock.schedule_effect}</dd>
        </div>
        {!compact && (
          <>
            <div>
              <dt>Acceptance expiration</dt>
              <dd>{formatReleaseLockExpiration(lock.expiration)}</dd>
            </div>
            <div>
              <dt>Document SHA-256</dt>
              <dd><code>{shortDigest(lock.document.digest, 15, 10)}</code></dd>
            </div>
          </>
        )}
      </dl>
      <div className={styles.authorityBoundary}>
        <CircleDollarSign aria-hidden="true" size={17} />
        <p>
          <strong>CO_ACCEPTED is not payment authority.</strong>
          It records acceptance of this exact document, scope, price, and schedule effect.
        </p>
      </div>
    </>
  );
}

interface DrawTermsProps {
  lock: LockData;
  compact?: boolean;
}

function DrawTerms({ lock, compact }: DrawTermsProps): React.ReactElement {
  return (
    <>
      <dl className={styles.termRows}>
        <div>
          <dt>Draw ID</dt>
          <dd>{lock.draw.id}</dd>
        </div>
        <div>
          <dt>Exact draw amount</dt>
          <dd className={styles.termAmount}>
            {lock.draw.amount.display} <span>{lock.draw.amount.currency}</span>
          </dd>
        </div>
        {lock.draw.payees.map((payee) => (
          <div key={payee.name}>
            <dt>Payee</dt>
            <dd>{payee.name} · {payee.amount}</dd>
          </div>
        ))}
        <div className={styles.termRowWide}>
          <dt>Completion evidence</dt>
          <dd>
            {lock.draw.completion_evidence.reference}
            {!compact && <code>{shortDigest(lock.draw.completion_evidence.digest, 15, 10)}</code>}
          </dd>
        </div>
        <div className={styles.termRowWide}>
          <dt>Lien-waiver evidence</dt>
          <dd>
            {lock.draw.lien_waiver_evidence.reference}
            {!compact && <code>{shortDigest(lock.draw.lien_waiver_evidence.digest, 15, 10)}</code>}
          </dd>
        </div>
        {!compact && (
          <div className={styles.termRowWide}>
            <dt>Custodian instruction</dt>
            <dd>{lock.draw.instruction}</dd>
          </div>
        )}
      </dl>
      <div className={`${styles.authorityBoundary} ${styles.authorityBoundaryDraw}`}>
        <ShieldCheck aria-hidden="true" size={17} />
        <p>
          <strong>Only DRAW_RELEASE can make this custodian instruction eligible.</strong>
          Both authority-bound role credentials must approve this exact draw and evidence set
          after the milestone.
        </p>
      </div>
    </>
  );
}

interface ReleaseLockTermsProps {
  lock: LockData;
  compact?: boolean;
  ceremony?: string;
}

export default function ReleaseLockTerms({
  lock,
  compact = false,
  ceremony = CEREMONY_CO_ACCEPTANCE,
}: ReleaseLockTermsProps): React.ReactElement {
  const definition = lock.ceremonies[ceremony];
  const isDraw = ceremony === CEREMONY_DRAW_RELEASE;
  const headingId = `release-lock-${ceremony}-${compact ? 'preview' : 'terms'}-title`;

  return (
    <section
      className={`${styles.termsPanel} ${compact ? styles.termsPanelCompact : ''}`}
      aria-labelledby={headingId}
      data-ceremony={ceremony}
    >
      <div className={styles.panelHeading}>
        <div>
          <span className={styles.eyebrow}>Round {definition.round} · exact material terms</span>
          <h2 id={headingId}>{definition.label}</h2>
        </div>
        <span className={styles.immutableBadge}>
          <FileCheck2 aria-hidden="true" size={15} />
          Version {lock.version.number}
        </span>
      </div>

      {isDraw
        ? <DrawTerms lock={lock} compact={compact} />
        : <CoTerms lock={lock} compact={compact} />}

      <div className={styles.digestRow}>
        <Fingerprint aria-hidden="true" size={17} />
        <div>
          <span>{definition.code} action digest</span>
          <code title={definition.digest}>{shortDigest(definition.digest, 18, 12)}</code>
        </div>
      </div>
    </section>
  );
}
