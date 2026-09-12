// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { validWorksId } from '@/lib/works/model';
import ProposalLookup from '../ProposalLookup';
import styles from '../proposal.module.css';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Recorded Proposal | EMILIA Marketplace',
  robots: { index: false, follow: false },
  referrer: 'no-referrer' as const,
};

export default async function ProposalPage({ params }: { params: Promise<{ id: string }> }) {
  if (!isWorksV0Enabled()) notFound();
  const { id } = await params;
  if (!validWorksId(id)) notFound();
  // No private record is fetched or embedded in server-rendered HTML or RSC.
  // A valid ID renders the same authentication page regardless of existence.
  return <div className={styles.page}>
    <SiteNav activePage="works" />
    <main id="main-content" className={styles.main}>
      <Link href="/works/submissions">Find another proposal</Link>
      <p className={styles.eyebrow}>EMILIA Marketplace · Proposals</p>
      <h1>Pick up where you left off.</h1>
      <ProposalLookup key={id} submissionId={id} />
    </main>
    <SiteFooter />
  </div>;
}
