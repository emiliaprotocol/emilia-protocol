// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import ProgramIntegrityGate from './_components/ProgramIntegrityGate';

export const metadata: Metadata = {
  title: 'Amelia I + Program Integrity Gate | EMILIA',
  description:
    'Diagnose risky legacy workflows with Amelia I, then see a synthetic, PHI-free Gate demonstration of exact-action authorization, no-blind-replay handling, and portable evidence.',
};

export default function ProgramIntegrityPage() {
  return (
    <>
      <SiteNav activePage="Solutions" />
      <ProgramIntegrityGate />
      <SiteFooter />
    </>
  );
}
