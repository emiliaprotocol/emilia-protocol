// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import ProgramIntegrityGate from './_components/ProgramIntegrityGate';

export const metadata: Metadata = {
  title: 'Signal + Program Integrity Gate',
  description:
    'Diagnose risky legacy workflows with EMILIA Signal, then see a synthetic, PHI-free Gate demonstration of exact-action authorization, no-blind-replay handling, and portable evidence.',
  alternates: { canonical: '/health/program-integrity' },
};

export default function ProgramIntegrityPage() {
  return (
    <>
      <SiteNav activePage="Signal" />
      <ProgramIntegrityGate />
      <SiteFooter />
    </>
  );
}
