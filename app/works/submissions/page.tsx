// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { ProposalFinder } from './ProposalLookup';
import styles from './proposal.module.css';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Find a Proposal | EMILIA Marketplace', robots: { index: false, follow: false } };

export default function ProposalFinderPage() {
  if (!isWorksV0Enabled()) notFound();
  return <div className={styles.page}>
    <SiteNav activePage="works" />
    <main id="main-content" className={styles.main}>
      <Link href="/works">Back to the marketplace</Link>
      <p className={styles.eyebrow}>EMILIA Marketplace · Proposals</p>
      <h1>Find a proposal.</h1>
      <ProposalFinder />
    </main>
    <SiteFooter />
  </div>;
}
