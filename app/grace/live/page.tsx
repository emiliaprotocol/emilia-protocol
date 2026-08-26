// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import GraceLiveConsole from './GraceLiveConsole';

export const metadata: Metadata = {
  title: 'GRACE: A Safer Way for AI to Curtail Grid Load | EMILIA',
  description:
    'Watch one 18 MW reference curtailment move from two distinct approver signatures through adapter acknowledgment, a separately keyed meter statement, Action State, and one-time settlement admission.',
  alternates: { canonical: '/grace/live' },
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
