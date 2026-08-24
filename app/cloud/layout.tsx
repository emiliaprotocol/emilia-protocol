// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import CloudShell from './cloud-shell';

export const metadata: Metadata = {
  title: 'Gate Operations Prototype | EMILIA',
  description:
    'A non-operating implementation prototype for inspecting Gate policy, signoff, event, '
    + 'and evidence surfaces with synthetic or developer-configured test data.',
  robots: { index: false, follow: false },
  openGraph: {
    title: 'EMILIA Gate Operations Prototype',
    description:
      'Reference operations surfaces only. No hosted Cloud service, customer deployment, '
      + 'provider credentials, or production actuation.',
    url: 'https://www.emiliaprotocol.ai/cloud',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'EMILIA Gate Operations Prototype',
    description: 'A deindexed, non-operating reference interface for Gate operations.',
  },
};

export default function CloudLayout({ children }: { children: React.ReactNode }): React.ReactElement {
  return <CloudShell>{children}</CloudShell>;
}
