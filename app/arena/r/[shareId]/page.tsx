// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

import { loadPublicArenaRefusal } from '@/lib/arena/service';
import styles from '../../arena.module.css';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export const metadata: Metadata = {
  title: 'Synthetic Refusal Record — EMILIA Arena',
  description: 'Integrity verification for an explicitly published synthetic EMILIA Arena refusal.',
  robots: {
    index: false,
    follow: false,
    nocache: true,
    googleBot: { index: false, follow: false, noimageindex: true },
  },
};

type PageProps = { params: Promise<{ shareId: string }> };
type ViewState =
  | { kind: 'record'; record: NonNullable<Awaited<ReturnType<typeof loadPublicArenaRefusal>>> }
  | { kind: 'missing' }
  | { kind: 'unavailable' };

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function text(value: unknown, fallback = '—'): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

function number(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString() : '—';
}

function date(value: unknown): string {
  if (typeof value !== 'string') return '—';
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(parsed) + ' UTC'
    : '—';
}

function reason(value: unknown): string {
  const reasons: Record<string, string> = {
    allowance_per_action_limit_exceeded: 'Per-action allowance exceeded',
    allowance_aggregate_limit_exceeded: 'Remaining allowance exceeded',
    allowance_target_not_allowed: 'Target outside the approved set',
    allowance_currency_mismatch: 'Allowance unit mismatch',
    allowance_expired: 'Allowance expired',
  };
  return typeof value === 'string' ? reasons[value] || 'Outside the declared allowance' : 'Outside the declared allowance';
}

function safeVerificationMessage(value: unknown): string {
  const messages: Record<string, string> = {
    arena_projection_invalid: 'The public record could not be parsed as the expected Arena profile.',
    arena_projection_binding_mismatch: 'The public fields do not match the signed refusal binding.',
    arena_refusal_invalid: 'The refusal signature or signed fields did not verify.',
    refusal_expired: 'The refusal validity window has elapsed. Historical signature integrity still verifies.',
  };
  return typeof value === 'string' ? messages[value] || 'The record did not satisfy the public verification profile.' : 'The record did not satisfy the public verification profile.';
}

async function loadState(shareId: string): Promise<ViewState> {
  try {
    const record = await loadPublicArenaRefusal(shareId);
    return record ? { kind: 'record', record } : { kind: 'missing' };
  } catch {
    return { kind: 'unavailable' };
  }
}

function ErrorState({ unavailable }: { unavailable: boolean }) {
  return (
    <main className={styles.sharePage}>
      <div className={styles.shareShell}>
        <div className={styles.shareTopline}>
          <a className={styles.shareBrand} href="/arena">EMILIA / ARENA</a>
          <span className={styles.shareProfile}>EP-ARENA-PUBLIC-REFUSAL-v1</span>
        </div>
        <section className={styles.errorState}>
          <span className={styles.stateIcon} aria-hidden="true">!</span>
          <h1>{unavailable ? 'Verification is temporarily unavailable.' : 'This refusal record is unavailable.'}</h1>
          <p>
            {unavailable
              ? 'The verifier could not retrieve the record, so no integrity result is asserted. Try again later.'
              : 'The link is invalid, unpublished, or the record has been revoked. No integrity result is asserted.'}
          </p>
          <a href="/arena">Return to the synthetic Arena →</a>
        </section>
      </div>
    </main>
  );
}

export default async function ArenaRefusalPage({ params }: PageProps) {
  const { shareId } = await params;
  const state = await loadState(shareId);
  if (state.kind !== 'record') return <ErrorState unavailable={state.kind === 'unavailable'} />;

  const { record } = state;
  const projection = object(record.projection);
  const attempt = object(projection?.attempt);
  const action = object(attempt?.action);
  const verification = record.verification;
  const verified = verification.integrity_verified === true;
  const current = verified && verification.currently_valid === true;
  const sealClass = !verified ? `${styles.verificationSeal} ${styles.failed}`
    : current ? styles.verificationSeal
      : `${styles.verificationSeal} ${styles.stale}`;
  const pilotHref = `/pilot?artifact_id=${encodeURIComponent(shareId)}`;

  if (!verified) {
    return (
      <main className={styles.sharePage}>
        <div className={styles.shareShell}>
          <div className={styles.shareTopline}>
            <a className={styles.shareBrand} href="/arena">EMILIA / ARENA</a>
            <span className={styles.shareProfile}>EP-ARENA-PUBLIC-REFUSAL-v1</span>
          </div>
          <section className={styles.errorState}>
            <span className={styles.stateIcon} aria-hidden="true">!</span>
            <h1>Integrity verification failed.</h1>
            <p>{safeVerificationMessage(verification.reason)}</p>
            <p>This page does not display unverified record fields. No identity, certification, authority, or acceptance claim is made.</p>
            <a href="/arena">Run a new synthetic challenge →</a>
          </section>
        </div>
      </main>
    );
  }

  return (
    <main className={styles.sharePage}>
      <div className={styles.shareShell}>
        <div className={styles.shareTopline}>
          <a className={styles.shareBrand} href="/arena">EMILIA / ARENA</a>
          <span className={styles.shareProfile}>EP-ARENA-PUBLIC-REFUSAL-v1</span>
        </div>

        <header className={styles.shareHero}>
          <div>
            <p className={styles.statusEyebrow}>PUBLIC SYNTHETIC REFUSAL RECORD</p>
            <h1>An exact synthetic action crossed a declared boundary.</h1>
            <p>
              This public integrity checker re-derives the action binding and checks the signed refusal against the included session key. That key is not an independently pinned identity or authority credential.
            </p>
          </div>
          <div className={sealClass} role="status">
            <span className={styles.statusEyebrow}>{current ? 'RECORD INTEGRITY MATCHES' : 'HISTORICAL INTEGRITY MATCHES'}</span>
            <strong>{current ? 'Signed fields match' : 'Signature matches · window elapsed'}</strong>
            <p>{current ? 'The included session key validates the signed fields and action binding; it does not establish who controlled that key.' : safeVerificationMessage(verification.current_reason)}</p>
          </div>
        </header>

        <section className={styles.shareGrid}>
          <div className={styles.shareMain}>
            <div className={styles.recordHeadline}>
              <div>
                <p className={styles.sectionKicker}>WHAT THE GATE REFUSED</p>
                <h2>{text(action?.purpose, 'Synthetic action').replaceAll('-', ' ')}</h2>
              </div>
              <span className={styles.refusalBadge}>REFUSED</span>
            </div>

            <dl className={styles.factList}>
              <div><dt>Target</dt><dd className={styles.mono}>{text(action?.target)}</dd></div>
              <div><dt>Requested</dt><dd>{number(action?.amount)} {text(action?.currency, 'CREDITS')}</dd></div>
              <div><dt>Reason</dt><dd>{reason(attempt?.reason)}</dd></div>
              <div><dt>Recorded</dt><dd>{date(attempt?.created_at)}</dd></div>
            </dl>

            <div className={styles.proofSection}>
              <h3>Exact-action binding</h3>
              <div className={styles.digest}>Public record ID<br />{shareId}</div>
              <div className={styles.digest}>CAID<br />{text(attempt?.caid)}</div>
              <div className={styles.digest}>ACTION DIGEST<br />{text(attempt?.action_digest)}</div>
              <div className={styles.digest}>REFUSAL DIGEST<br />{text(projection?.refusal_digest)}</div>
            </div>
          </div>

          <aside className={styles.shareAside}>
            <section>
              <h3>What this record verifies</h3>
              <ul>
                <li>The published action and reason match the signed refusal.</li>
                <li>The refusal binds the exact synthetic action shown here.</li>
                <li>The displayed fields remain consistent with the included session key.</li>
              </ul>
            </section>
            <section className={styles.notProof}>
              <h3>What this does not prove</h3>
              <ul>
                <li>Identity, competence, certification, or reputation.</li>
                <li>Money movement, custody, settlement, or a production event.</li>
                <li>Legal authority, policy acceptance, or substantive correctness.</li>
              </ul>
            </section>
            <div className={styles.trustNote}>
              <strong>Integrity-only trust boundary.</strong><br />
              The verification key is included in this public record. It checks consistency with that key; it does not establish who controlled that key and is not an independently pinned identity, authority, or certification credential.
            </div>
          </aside>
        </section>

        <footer className={styles.shareFooter}>
          <span>Published {date(record.published_at)} · Synthetic no-egress challenge</span>
          <a href="/arena">Continue the factual record →</a>
          <a href={pilotHref}>Scope the protected-workflow pilot →</a>
        </footer>
      </div>
    </main>
  );
}
