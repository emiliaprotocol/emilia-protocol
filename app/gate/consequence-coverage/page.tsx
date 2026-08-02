// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import CoverageConsole from './CoverageConsole';

export const metadata: Metadata = {
  title: 'Consequence Coverage | EMILIA Gate',
  description: 'Reconcile an independently signed system-of-record population against Gate receipts and surface effects that bypassed the consequence boundary.',
};

export default function ConsequenceCoveragePage() {
  return (
    <>
      <SiteNav activePage="Gate" />
      <CoverageConsole />
      <SiteFooter />
    </>
  );
}
