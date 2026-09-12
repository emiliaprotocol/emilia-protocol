// SPDX-License-Identifier: Apache-2.0

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { color, styles } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import OpportunityForm from '../../OpportunityForm';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Post a job | EMILIA Marketplace',
  description: 'Describe the work, review your public job post and invite builders to propose an approach.',
};

export default function NewOpportunityPage() {
  if (!isWorksV0Enabled()) notFound();

  return (
    <div style={styles.page}>
      <SiteNav />
      <main id="main-content">
      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>
            <Link href="/works/opportunities" style={{ color: color.t3, textDecoration: 'none' }}>
              Jobs
            </Link>
            {' / Post'}
          </div>
          <h1 style={{ ...styles.h1, maxWidth: 800 }}>Start with the job.</h1>
          <p style={{ ...styles.body, maxWidth: 760, marginBottom: 0, fontSize: 20 }}>
            Tell builders what you need done and what a good result looks like.
            Review your draft before publishing. You only need your account key when you are ready to post.
          </p>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          <OpportunityForm />
        </div>
      </section>
      </main>
      <SiteFooter />
    </div>
  );
}
