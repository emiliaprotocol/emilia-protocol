// SPDX-License-Identifier: Apache-2.0

import { notFound } from 'next/navigation';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { styles } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import VerifyAuthorityRequest from './VerifyAuthorityRequest';

export const metadata = { title: 'Verify Authority Record request | EMILIA Works' };

export default function VerifyRequestPage() {
  if (!isWorksV0Enabled()) notFound();
  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 96 }}>
        <div style={styles.eyebrow}>EMILIA Works</div>
        <h1 style={styles.h1}>Verify your request</h1>
        <VerifyAuthorityRequest />
      </main>
      <SiteFooter />
    </div>
  );
}
