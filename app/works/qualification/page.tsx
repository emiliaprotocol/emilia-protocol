// SPDX-License-Identifier: Apache-2.0

import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import QualificationForm from './QualificationForm';
import styles from './qualification.module.css';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Check an Agent’s Qualification | EMILIA Marketplace',
  description: 'Verify signed evidence for one agent candidate, assignment and test policy. A scan, listing or payment cannot qualify an agent.',
  alternates: { canonical: '/works/qualification' },
};

export default function QualificationPage() {
  if (!isWorksV0Enabled()) notFound();
  return <div className={styles.page}>
    <SiteNav activePage="works" />
    <main className={styles.main}>
      <nav className={styles.breadcrumb} aria-label="Breadcrumb"><Link href="/works">Marketplace</Link><span> / Qualification</span></nav>
      <header className={styles.hero}>
        <div><p className={styles.eyebrow}>EMILIA Marketplace · Qualification</p>
          <h1>Qualified for<br /><em>which job?</em></h1></div>
        <div className={styles.heroCopy}><p className={styles.lead}>A useful result names the agent, the assignment and the tests behind it. Change any of those, and the old result is not enough.</p>
          <p>A free scan helps you inspect declared tools. Qualification checks signed evidence against a test policy and the operator’s latest trusted status observation. Neither step gives the agent permission to act.</p></div>
      </header>
      <div className={styles.workspace}>
      <QualificationForm />
      <aside className={styles.explanation} aria-labelledby="qualification-scope-title">
        <p className={styles.eyebrow}>What the result means</p>
        <h2 id="qualification-scope-title">A narrow answer you can inspect.</h2>
        <p>Think of a refund agent tested for one team’s refund rules. That result does not qualify a changed build, a different assignment or a different policy. It also does not prove Gate is installed or that a real refund happened.</p>
        <p>Missing, expired, revoked or conflicting evidence stays visible. We do not turn it into a pass. A paid service can cover testing or deployment work; it cannot buy a favorable result.</p>
        <p className={styles.help}>Hosted verification must be configured for your scope. If it is not, this page returns “unavailable.” There are no demo keys or automatically accepted uploads.</p>
      </aside>
      </div>
      <nav className={styles.next} aria-label="Other marketplace steps">
        <Link href="/works/scan">Start with a free scan</Link>
        <Link href="/works/gate">Ask about Gate setup and support</Link>
        <Link href="/works">Back to the marketplace</Link>
      </nav>
    </main>
    <SiteFooter />
  </div>;
}
