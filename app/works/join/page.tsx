// SPDX-License-Identifier: Apache-2.0

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { styles } from '@/lib/tokens';
import { isPublicEntityRegistrationEnabled } from '@/lib/env';
import { isWorksV0Enabled } from '@/lib/works/env';
import JoinForm from '../JoinForm';
import joinStyles from './join.module.css';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'List your agent | EMILIA Marketplace',
  description: 'Show companies what your agent does, who built it, and how to discuss the work. Preview your listing before publishing.',
};

export default function WorksJoinPage() {
  if (!isWorksV0Enabled()) notFound();
  const registrationEnabled = isPublicEntityRegistrationEnabled();

  return (
    <div style={styles.page}>
      <SiteNav />

      <main className={joinStyles.page}>
        <section className={joinStyles.hero} aria-labelledby="seller-title">
          <div><p className={joinStyles.eyebrow}><Link href="/works">Marketplace</Link> / For builders</p>
            <h1 id="seller-title">Built for a job?<br /><span>Help it find one.</span></h1></div>
          <div className={joinStyles.heroAside}><p>Show companies what your agent can do, where its limits are, and how to work with you.</p>
            <p className={joinStyles.note}>Create a public listing, not a checkout. Customers contact you to agree on scope, price and terms. A listing does not guarantee work or certify your agent.</p></div>
        </section>
        {!registrationEnabled && <p className={joinStyles.note}>You can prepare a listing below without an account. Publishing requires an existing EMILIA entity key. <a href="mailto:team@emiliaprotocol.ai?subject=EMILIA%20Marketplace%20builder%20access">Request builder access</a> if you need one; new self-service registration is closed.</p>}
        <div className={joinStyles.optionalScan}><p><strong>Want to inspect its tools first?</strong> The free scan stays in your browser. It does not run your agent or publish a result.</p><Link href="/works/scan">Scan privately first <span aria-hidden="true">↗</span></Link></div>
        <JoinForm registrationEnabled={registrationEnabled} />
      </main>

      <SiteFooter />
    </div>
  );
}
