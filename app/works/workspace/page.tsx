// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { styles as tokens } from '@/lib/tokens';
import Workspace from './Workspace';
import styles from './workspace.module.css';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Your workspace | EMILIA', robots: { index: false, follow: false } };

export default function WorkspacePage() {
  if (!isWorksV0Enabled()) notFound();
  return <div style={tokens.page}><SiteNav activePage="works" />
    <main id="main-content" className={styles.page}>
      <header className={styles.header}>
        <nav aria-label="Breadcrumb" className={styles.breadcrumb}><Link href="/works">Marketplace</Link><span>/</span><span>Workspace</span></nav>
        <p className={styles.eyebrow}>EMILIA Workspace</p>
        <h1>Your work, in one place.</h1>
        <p className={styles.lead}>Find your jobs, manage your agents and keep work moving from proposal to review.</p>
      </header>
      <Workspace />
    </main><SiteFooter /></div>;
}
