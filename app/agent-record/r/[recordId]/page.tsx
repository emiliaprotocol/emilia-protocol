// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

import { loadPublicAgentRecord } from '@/lib/agent-record/service';
import { getAgentRecordRuntimeReadiness } from '@/lib/agent-record/runtime-readiness';
import OwnerControls from './OwnerControls';
import styles from './record.module.css';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Agent Record · EMILIA',
  description: 'An unlisted, operator-signed observation of one verified synthetic Arena refusal.',
  robots: { index: false, follow: false },
};

function short(value: unknown): string {
  if (typeof value !== 'string') return 'Unavailable';
  return value.length > 38 ? `${value.slice(0, 22)}…${value.slice(-10)}` : value;
}

function Unavailable() {
  return (
    <main className={styles.page}>
      <section className={styles.unavailable}>
        <a href="/adopt" className={styles.brand}>EMILIA / AGENT RECORD</a>
        <p className={styles.kicker}>UNLISTED FACTUAL RECORD</p>
        <h1>This Agent Record is unavailable.</h1>
        <p>
          It may never have existed, may have expired, or may have been unpublished.
          Those states are intentionally indistinguishable.
        </p>
        <a href="/adopt" className={styles.primary}>Run the synthetic challenge →</a>
      </section>
    </main>
  );
}

function StoreUnavailable() {
  return (
    <main className={styles.page}>
      <section className={styles.unavailable} role="status">
        <a href="/adopt" className={styles.brand}>EMILIA / AGENT RECORD</a>
        <p className={styles.kicker}>STATUS UNAVAILABLE</p>
        <h1>This Agent Record cannot be checked right now.</h1>
        <p>
          The Agent Record service is temporarily unavailable. This page makes no claim about whether
          the record exists, is current, expired, or unpublished.
        </p>
        <a href="/adopt" className={styles.primary}>Return to the synthetic challenge →</a>
      </section>
    </main>
  );
}

export default async function AgentRecordPage({
  params,
}: {
  params: Promise<{ recordId: string }> | { recordId: string };
}) {
  const { recordId } = await params;
  const readiness = await getAgentRecordRuntimeReadiness();
  if (!readiness.ready) return <StoreUnavailable />;
  let result: Awaited<ReturnType<typeof loadPublicAgentRecord>> = null;
  let unavailable = false;
  try {
    result = await loadPublicAgentRecord({ recordId });
  } catch {
    unavailable = true;
  }

  if (unavailable) return <StoreUnavailable />;
  if (!result) return <Unavailable />;

  const projection = result.public_projection as Record<string, any>;
  const record = projection.record as Record<string, any>;
  const pilotHref = `/pilot?artifact_id=${encodeURIComponent(recordId)}`;

  return (
    <main className={styles.page}>
      <article className={styles.sheet}>
        <header className={styles.header}>
          <a href="/adopt" className={styles.brand}>EMILIA / AGENT RECORD</a>
          <span>PUBLIC BY OPAQUE LINK · REVOCABLE</span>
        </header>

        <section className={styles.hero}>
          <div className={styles.seal} aria-hidden="true">R</div>
          <div>
            <p className={styles.kicker}>OPERATOR-SIGNED FACTUAL OBSERVATION</p>
            <h1>One refusal. One bounded source.</h1>
            <p className={styles.lede}>
              This is an operator-signed observation of one verified Arena refusal bound to one
              Operating Bond. It records only that bounded synthetic event.
            </p>
          </div>
        </section>

        <dl className={styles.facts}>
          <div><dt>Record</dt><dd><code>{recordId}</code></dd></div>
          <div><dt>Operating Bond</dt><dd><code>{short(record.bond?.bond_digest)}</code></dd></div>
          <div><dt>Action</dt><dd><code>{short(record.action?.action_digest)}</code></dd></div>
          <div><dt>Refusal</dt><dd><code>{short(record.refusal?.refusal_digest)}</code></dd></div>
          <div><dt>Refused at</dt><dd>{record.refusal?.refused_at ?? 'Unavailable'}</dd></div>
          <div><dt>Observed at</dt><dd>{record.observed_at ?? 'Unavailable'}</dd></div>
          <div><dt>Public through</dt><dd>{record.retention_expires_at ?? 'Unavailable'}</dd></div>
          <div><dt>Signature</dt><dd>{projection.signature?.algorithm ?? 'Unavailable'} · {projection.signature?.key_id ?? 'Unavailable'}</dd></div>
        </dl>

        <section className={styles.boundary}>
          <p className={styles.kicker}>CLAIM BOUNDARY</p>
          <h2>A fact, not a credential.</h2>
          <p>
            This record is not identity, not certification, not marketplace reputation,
            not production coverage, and not future authorization. It does not say who controls
            an agent, that an agent is safe, or that any later action may execute.
          </p>
        </section>

        <OwnerControls recordId={recordId} />

        <footer className={styles.footer}>
          <span>Anyone with this exact unlisted link can inspect the observation while it remains current.</span>
          <a href="/adopt">Run the challenge →</a>
          <a href={pilotHref}>Scope the protected-workflow pilot →</a>
        </footer>
      </article>
    </main>
  );
}
