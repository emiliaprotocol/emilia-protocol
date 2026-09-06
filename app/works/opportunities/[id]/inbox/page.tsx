// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { getWorksRecord } from '@/lib/works/store';
import type { OpportunityRecord } from '@/lib/works/model';
import ProposalInbox from './ProposalInbox';
import styles from './inbox.module.css';

export const dynamic = 'force-dynamic';
export const metadata = {
  title: 'Opportunity Responses | EMILIA Marketplace',
  robots: { index: false, follow: false },
};

export default async function InboxPage({ params }: { params: Promise<{ id: string }> }) {
  if (!isWorksV0Enabled()) notFound();
  const { id } = await params;
  // Public SSR loads the public opportunity only. Private proposals are never
  // server-rendered or embedded in the React Server Component response.
  const loaded = await getWorksRecord('opportunities', id);
  if (!loaded.ok && loaded.code !== 'store_unavailable') notFound();
  const opportunity = loaded.ok ? loaded.record as OpportunityRecord : null;
  if (opportunity?.example) notFound();
  return <div className={styles.page}>
    <SiteNav activePage="works" />
    <main id="main-content" className={styles.main}>
      <Link href={opportunity ? `/works/opportunities/${opportunity.opportunity_id}` : '/works/opportunities'}>Back to the opportunity</Link>
      <p className={styles.eyebrow}>EMILIA Marketplace · Responses</p>
      <h1>{opportunity?.title || 'Responses unavailable'}</h1>
      {opportunity ? <ProposalInbox key={opportunity.opportunity_id} opportunityId={opportunity.opportunity_id} />
        : <p role="status">The opportunity could not be loaded. No conclusion can be drawn about its responses. Please try again later.</p>}
    </main>
    <SiteFooter />
  </div>;
}
