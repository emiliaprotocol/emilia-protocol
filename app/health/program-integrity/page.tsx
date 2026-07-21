// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import ProgramIntegrityGate from './_components/ProgramIntegrityGate';

export const metadata: Metadata = {
  title: 'Program Integrity Gate | EMILIA',
  description:
    'A synthetic, PHI-free reference demo showing exact-action authorization, fail-closed payment control, no-blind-replay handling, and portable program-integrity evidence.',
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
