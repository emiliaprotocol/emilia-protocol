// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import type { LucideIcon } from 'lucide-react';
import { Check, LockKeyhole, ShieldCheck, Smartphone, TimerReset } from 'lucide-react';
import styles from './pair.module.css';

export const metadata: Metadata = {
  title: 'Pair EMILIA Approver',
  robots: { index: false, follow: false },
};

const CODE = /^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/;

function TrustFact({ icon: Icon, title, detail }: { icon: LucideIcon; title: string; detail: string }) {
  return (
    <div className={styles.trustFact}>
      <Icon aria-hidden="true" size={19} strokeWidth={1.8} />
      <div>
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
    </div>
  );
}

type PageProps = { searchParams: Promise<{ [key: string]: string | string[] | undefined }> };

export default async function MobilePairPage({ searchParams }: PageProps) {
  const query = await searchParams;
  const code = typeof query?.code === 'string' ? query.code.trim().toUpperCase() : '';
  const valid = CODE.test(code);

  return (
    <main className={styles.shell}>
      <section className={styles.brandBand} aria-label="EMILIA Approver">
        <div className={styles.brand}>
          <span className={styles.mark}><ShieldCheck aria-hidden="true" size={24} strokeWidth={1.8} /></span>
          <span>EMILIA</span>
          <small>Approver</small>
        </div>
        <p>Exact action. Named human. Verifiable decision.</p>
      </section>

      <section className={styles.workflow}>
        <div className={styles.content}>
          <div className={styles.kicker}>{valid ? 'Pair this device' : 'Pairing unavailable'}</div>
          <h1>{valid ? 'Connect to your organization.' : 'Request a new pairing link.'}</h1>
          <p className={styles.lede}>
            {valid
              ? 'Open EMILIA Approver and enter this one-time code. Pairing connects the app; it never approves an action.'
              : 'This link is missing a valid one-time code. Your organization can issue a fresh link without changing your approval credentials.'}
          </p>

          {valid ? (
            <div className={styles.codeBlock} aria-label={`One-time pairing code ${code}`}>
              <div className={styles.codeLabel}>
                <Smartphone aria-hidden="true" size={18} strokeWidth={1.8} />
                One-time pairing code
              </div>
              <div className={styles.code}>{code}</div>
              <div className={styles.ready}><Check aria-hidden="true" size={17} /> Ready to enter</div>
            </div>
          ) : (
            <div className={styles.refusal} role="status">
              <LockKeyhole aria-hidden="true" size={21} strokeWidth={1.8} />
              No device or account was changed.
            </div>
          )}

          <div className={styles.trustRow} aria-label="Pairing protections">
            <TrustFact icon={TimerReset} title="Short lived" detail="Expires automatically" />
            <TrustFact icon={LockKeyhole} title="Single use" detail="Replay is refused" />
            <TrustFact icon={ShieldCheck} title="No approval" detail="Actions stay blocked" />
          </div>
        </div>

        <footer className={styles.footer}>
          <span>EMILIA Protocol</span>
          <a href="mailto:security@emiliaprotocol.ai">Security</a>
          <a href="/legal/privacy">Privacy</a>
        </footer>
      </section>
    </main>
  );
}
