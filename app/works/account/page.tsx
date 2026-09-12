// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { styles as tokens } from '@/lib/tokens';
import AccountPage from './AccountPage';
import styles from './account-page.module.css';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Your Works account | EMILIA', robots: { index: false, follow: false } };

export default function AccountRoute() {
  if (!isWorksV0Enabled()) notFound();
  // Configuration readiness only. Provider and storage failures still fail closed.
  const signInAvailable = Boolean(process.env.RESEND_API_KEY?.trim()
    && Buffer.byteLength(process.env.WORKS_ACCOUNT_HMAC_SECRET || '', 'utf8') >= 32
    && process.env.NEXT_PUBLIC_SUPABASE_URL?.trim() && process.env.SUPABASE_SERVICE_ROLE_KEY?.trim());
  return <div style={tokens.page}><SiteNav activePage="works" />
    <main id="main-content" className={styles.page}>
      <nav aria-label="Breadcrumb" className={styles.breadcrumb}><Link href="/works">Marketplace</Link><span>/</span><span>Account</span></nav>
      <header className={styles.header}><p className={styles.eyebrow}>EMILIA Works</p><h1>Your Works account.</h1>
        <p>One place to return to your jobs, agent listings and assignments. Signing in does not publish anything or give an agent permission to act.</p></header>
      <AccountPage signInAvailable={signInAvailable} />
      <p className={styles.legal}><Link href="/legal/privacy">Privacy policy</Link><span>·</span><Link href="/legal/terms">Terms of service</Link></p>
    </main><SiteFooter /></div>;
}
