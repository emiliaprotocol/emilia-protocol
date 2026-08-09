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
  title: 'Post an opportunity | EMILIA Works (Private Beta)',
  description: 'Post an inspectable opportunity with bounded funding and authority statements.',
};

export default function NewOpportunityPage() {
  if (!isWorksV0Enabled()) notFound();

  return (
    <div style={styles.page}>
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>
            <Link href="/works/opportunities" style={{ color: color.t3, textDecoration: 'none' }}>
              Opportunities
            </Link>
            {' / Post'}
          </div>
          <h1 style={{ ...styles.h1, maxWidth: 800 }}>Post an opportunity</h1>
          <p style={{ ...styles.body, maxWidth: 760, marginBottom: 0 }}>
            Describe the work and identify the sponsor. Funding and authority statements are recorded
            only as sponsor-ASSERTED or UNKNOWN here. This form cannot award VERIFIED status.
          </p>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          <OpportunityForm />
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
