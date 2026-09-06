// SPDX-License-Identifier: Apache-2.0
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { notFound } from 'next/navigation';
import { isWorksV0Enabled } from '@/lib/works/env';
import AgentScanner from './AgentScanner';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Free Agent Declaration Scan | EMILIA',
  description: 'Inspect declared agent tools in your browser. Find potential consequential actions and review gaps. No account, server upload or safety badge.',
  alternates: { canonical: '/works/scan' },
};

export default function AgentScanPage() {
  if (!isWorksV0Enabled()) notFound();
  return <><SiteNav /><AgentScanner /><SiteFooter /></>;
}
