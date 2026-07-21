// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import GraceLiveConsole from './GraceLiveConsole';

export const metadata: Metadata = {
  title: 'GRACE Live Control Room | EMILIA Protocol',
  description:
    'Run the GRACE reference circuit: mobile Class-A quorum, bounded COSA dispatch, independently signed meter evidence, Action State, and one-time settlement.',
};

export default function GraceLivePage() {
  return (
    <>
      <SiteNav activePage="GRACE" />
      <GraceLiveConsole />
      <SiteFooter />
    </>
  );
}
