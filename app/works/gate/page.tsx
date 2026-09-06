// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { GATE_QUOTE_EMAIL, GATE_QUOTE_MAILTO, MARKETPLACE_GATE_OFFER } from '@/lib/works/gate-offer';
import styles from './gate.module.css';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Gate setup and support | EMILIA Marketplace',
  description: 'Run the open Gate yourself, or ask EMILIA to help protect one supported agent action. Agree the scope and price first. Payment never buys a passing result.',
  alternates: { canonical: '/works/gate' },
};

export default function MarketplaceGatePage() {
  if (!isWorksV0Enabled()) notFound();
  return <div className={styles.page}>
    <SiteNav activePage="works" />
    <main className={styles.main}>
      <nav aria-label="Breadcrumb"><Link href="/works">Marketplace</Link><span> / Gate setup</span></nav>
      <header className={styles.hero}>
        <p className={styles.eyebrow}>From understanding an agent to controlling its actions</p>
        <h1>Set the limits.<br />Then let it work.</h1>
        <p className={styles.lead}>A scan can flag a refund, a deployment or a permissions change. Gate checks whether a covered action may proceed, before the connected tool can execute it.</p>
        <p>You decide the rules. Routine work can run within standing authority. Exceptions come back to the person responsible.</p>
      </header>

      <section className={styles.offer} aria-labelledby="setup-title">
        <div>
          <p className={styles.eyebrow}>Help with one real workflow</p>
          <h2 id="setup-title">{MARKETPLACE_GATE_OFFER.name}</h2>
          <p>{MARKETPLACE_GATE_OFFER.scope} We agree the work and support terms with you before starting.</p>
          <ol>{MARKETPLACE_GATE_OFFER.included.map(item => <li key={item}>{item}</li>)}</ol>
        </div>
        <aside className={styles.quote}>
          <p className={styles.eyebrow}>Quote first</p>
          <h3>No charge until you agree.</h3>
          <p>Tell us the job and the tool it uses. We will confirm whether we can support it, then agree the scope and price.</p>
          <a className={styles.primary} href={GATE_QUOTE_MAILTO}>Ask for a Gate setup quote</a>
          <p className={styles.note}>Opens an email you can edit. Nothing is sent automatically. Your scan is not attached.</p>
          <p className={styles.note}>No email app? Write to <a href={`mailto:${GATE_QUOTE_EMAIL}`}>{GATE_QUOTE_EMAIL}</a>.</p>
          <p className={styles.note}>Self-service checkout is not open. There is no purchase, subscription or activation on this page.</p>
        </aside>
      </section>

      <section className={styles.section} aria-labelledby="open-gate-title">
        <h2 id="open-gate-title">Prefer to connect it yourself?</h2>
        <p>The open-source Gate stays free. The MCP starter can prepare one tool boundary and run local refusal checks. Paying EMILIA is not required to use the code or verify evidence.</p>
        <div className={styles.links}><Link href="/scan#run-local">Use the free Gate starter</Link><Link href="/works/scan">Run a free browser scan</Link></div>
        <p className={styles.note}>A wrapper only controls calls that pass through it. Production needs the credential-owning path, durable shared state, pinned policy and keys, and tested failure handling. A generated scaffold is not an active deployment.</p>
      </section>

      <section className={styles.section} aria-labelledby="qualification-title">
        <h2 id="qualification-title">The test result is not for sale.</h2>
        <p>Payment buys agreed engineering and support. It does not turn a scan, an installation or a failed test into a passing result.</p>
        <p>Qualification checks signed evidence for a named candidate, assignment and profile under explicit trust rules. A result must show its scope and freshness. It is not a safety rating, proof of good work or certification.</p>
        <Link href="/works/qualification">Check qualification evidence</Link>
      </section>
    </main>
    <SiteFooter />
  </div>;
}
