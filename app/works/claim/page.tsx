// SPDX-License-Identifier: Apache-2.0

import { notFound } from 'next/navigation';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { color, styles } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import ClaimAuthorityRecord from './ClaimAuthorityRecord';

export const metadata = {
  title: 'Claim an Authority Record · EMILIA Works',
  robots: { index: false, follow: false },
};

export default function ClaimPage() {
  if (!isWorksV0Enabled()) notFound();
  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ ...styles.section, paddingTop: 72, paddingBottom: 96 }}>
        <div style={styles.eyebrow}>Private owner ceremony</div>
        <h1 style={{ ...styles.h1, maxWidth: 780 }}>Claim, correct, then publish exact bytes</h1>
        <p style={{ ...styles.body, maxWidth: 720, color: color.t2 }}>
          A private public-source scan is not a public listing. Prove control of the named repository,
          correct the closed projection, and explicitly approve its current digest before it appears in EMILIA Works.
        </p>
        <ClaimAuthorityRecord />
      </main>
      <SiteFooter />
    </div>
  );
}
