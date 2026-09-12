// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import { notFound } from 'next/navigation';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { validWorksId } from '@/lib/works/model';
import { styles as tokens } from '@/lib/tokens';
import Assignment from './Assignment';
import styles from '../../workspace/workspace.module.css';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Assignment | EMILIA Workspace', robots: { index: false, follow: false } };
export default async function AssignmentPage({ params }: { params: Promise<{ id: string }> }) {
  if (!isWorksV0Enabled()) notFound();
  const { id } = await params; if (!validWorksId(id)) notFound();
  return <div style={tokens.page}><SiteNav activePage="works" /><main id="main-content" className={styles.page}>
    <header className={styles.header}><nav aria-label="Breadcrumb" className={styles.breadcrumb}><Link href="/works/workspace">Workspace</Link><span>/</span><span>Assignment</span></nav>
      <p className={styles.eyebrow}>Assignment record</p><h1>Agree on the work.<br />Review the result.</h1>
      <p className={styles.lead}>The same scope stays visible from the builder’s confirmation to the job owner’s review.</p></header>
    <Assignment assignmentId={id} />
  </main><SiteFooter /></div>;
}
