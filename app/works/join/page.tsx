// SPDX-License-Identifier: Apache-2.0

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { color, styles } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import JoinForm from '../JoinForm';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'List your work | EMILIA Works (Private Beta)',
  description: 'Create an accountable builder profile and a first agent, app, or project listing.',
};

export default function WorksJoinPage() {
  if (!isWorksV0Enabled()) notFound();

  return (
    <div style={styles.page}>
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>
            <Link href="/works" style={{ color: color.t3, textDecoration: 'none' }}>Works</Link>
            {' / List your work'}
          </div>
          <h1 style={{ ...styles.h1, maxWidth: 800 }}>Create your builder profile and first listing</h1>
          <p style={{ ...styles.body, maxWidth: 760, marginBottom: 0 }}>
            Name the accountable person or legal entity behind the work, then describe one agent,
            app, or project. Profile and listing fields are supplied by you; they are not treated as
            verified simply because they appear on Works.
          </p>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          <JoinForm />
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
