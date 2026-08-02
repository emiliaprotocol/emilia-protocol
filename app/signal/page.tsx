// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import ProgramIntegrityGate from '../health/program-integrity/_components/ProgramIntegrityGate';

export const metadata: Metadata = {
  title: 'EMILIA Signal | Find the Consequence Boundary',
  description:
    'EMILIA Signal reconstructs consequential workflows from governed exports, surfaces source-linked review leads, and prepares the exact boundary EMILIA Gate can protect.',
  alternates: { canonical: '/signal' },
  openGraph: {
    title: 'EMILIA Signal',
    description: 'Find the consequential workflow. Bind the next decision. Preserve the evidence.',
    url: 'https://www.emiliaprotocol.ai/signal',
    type: 'website',
  },
};

export default function SignalPage(): React.ReactElement {
  return (
    <>
      <SiteNav activePage="Signal" />
      <ProgramIntegrityGate />
      <SiteFooter />
    </>
  );
}
