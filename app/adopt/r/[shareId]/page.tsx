// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

import { loadPublicAgentAdoptionBond } from '@/lib/agent-adoption/service';
import styles from './share.module.css';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Operating Bond · EMILIA Agent Adoption',
  description: 'A revocable public projection from the synthetic EMILIA Agent Adoption challenge.',
  robots: { index: false, follow: false },
};

function shortDigest(value: unknown): string {
  if (typeof value !== 'string') return 'Unavailable';
  return value.length > 34 ? `${value.slice(0, 20)}…${value.slice(-10)}` : value;
}

export default async function AgentAdoptionSharePage({
  params,
}: {
  params: Promise<{ shareId: string }> | { shareId: string };
}) {
  const { shareId } = await params;
  let record: Awaited<ReturnType<typeof loadPublicAgentAdoptionBond>> = null;
  let storeUnavailable = false;
  try {
    record = await loadPublicAgentAdoptionBond({ shareId });
  } catch {
    storeUnavailable = true;
  }

  if (storeUnavailable) {
    return (
      <main className={styles.page}>
        <section className={styles.unavailable} role="status">
          <a href="/adopt" className={styles.brand}>EMILIA / ADOPTION</a>
          <p className={styles.kicker}>STATUS UNAVAILABLE</p>
          <h1>This record cannot be checked right now.</h1>
          <p>The projection store is temporarily unavailable. This page makes no claim about whether the record exists, is active, or was revoked.</p>
          <a href="/adopt" className={styles.button}>Return to the challenge →</a>
        </section>
      </main>
    );
  }

  const projection = record?.projection as Record<string, any> | null | undefined;

  if (!record || record.revoked || !projection) {
    return (
      <main className={styles.page}>
        <section className={styles.unavailable}>
          <a href="/adopt" className={styles.brand}>EMILIA / ADOPTION</a>
          <p className={styles.kicker}>OPERATING BOND</p>
          <h1>This public record is unavailable.</h1>
          <p>It may never have existed, the creating browser session may have revoked it, or it may have expired. Those states are intentionally indistinguishable.</p>
          <a href="/adopt" className={styles.button}>Run the candidate challenge →</a>
        </section>
      </main>
    );
  }

  const candidate = projection.candidate ?? {};
  const limits = projection.operating_limits ?? {};
  const observation = projection.assertion_observation ?? {};
  const pilotHref = `/pilot?artifact_id=${encodeURIComponent(shareId)}`;

  return (
    <main className={styles.page}>
      <section className={styles.sheet}>
        <header className={styles.header}>
          <a href="/adopt" className={styles.brand}>EMILIA / ADOPTION</a>
          <span>PUBLIC · REVOCABLE</span>
        </header>

        <div className={styles.hero}>
          <div className={styles.seal} aria-hidden="true">B</div>
          <div>
            <p className={styles.kicker}>OPERATING BOND · SYNTHETIC NO-EGRESS CHALLENGE</p>
            <h1>{candidate.label ?? 'Agent'}</h1>
            <p className={styles.candidateBoundary}>USER-SUPPLIED, UNVERIFIED CANDIDATE LABEL</p>
            <p>
              A user-present passkey ceremony used an adoption-local credential over this named
              candidate, one server-owned synthetic job, and one allowance. It did not verify a person,
              account, civil identity, or production authority.
            </p>
          </div>
        </div>

        <dl className={styles.facts}>
          <div><dt>Source kind</dt><dd>{candidate.source_kind ?? 'not disclosed'}</dd></div>
          <div><dt>Job template</dt><dd>{limits.job_template_id ?? 'unavailable'}</dd></div>
          <div><dt>Allowance</dt><dd>{limits.allowance_total ?? '—'} synthetic credits</dd></div>
          <div><dt>Per action</dt><dd>{limits.allowance_max_per_action ?? '—'} credits</dd></div>
          <div><dt>Maximum actions</dt><dd>{limits.max_actions ?? '—'}</dd></div>
          <div><dt>Maximum concurrency</dt><dd>{limits.max_concurrency ?? '—'}</dd></div>
          <div><dt>Network egress</dt><dd>{limits.network_egress ?? 'forbidden'}</dd></div>
          <div><dt>Observed</dt><dd>{observation.observed_at ?? record.created_at ?? 'Unavailable'}</dd></div>
        </dl>

        <section className={styles.integrity}>
          <p className={styles.kicker}>INTEGRITY REFERENCE</p>
          <div><span>Public record ID</span><code>{shareId}</code></div>
          <div><span>Operating Bond</span><code>{shortDigest(projection.bond_digest)}</code></div>
          <div><span>Candidate</span><code>{shortDigest(projection.candidate_digest)}</code></div>
          <div><span>Passkey assertion</span><code>{shortDigest(observation.assertion_digest)}</code></div>
        </section>

        <section className={styles.boundary}>
          <p className={styles.kicker}>CLAIM BOUNDARY</p>
          <h2>What this record does—and does not—say.</h2>
          <p>
            It records a bounded synthetic configuration and a user-present passkey ceremony.
            It is not identity verification, certification, a marketplace listing, money, custody,
            settlement, or authorization for any later real-world action.
          </p>
          <p>Report misleading or abusive labels to <a href="mailto:abuse@emiliaprotocol.ai">abuse@emiliaprotocol.ai</a>.</p>
        </section>

        <footer>
          <span>Anyone with this unlisted link can inspect it while it remains active.</span>
          <a href="/adopt">Continue the factual record →</a>
          <a href={pilotHref}>Scope the protected-workflow pilot →</a>
        </footer>
      </section>
    </main>
  );
}
