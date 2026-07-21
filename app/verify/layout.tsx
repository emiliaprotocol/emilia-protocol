// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Verify an Authorization Receipt — offline, in your browser',
  description:
    'Verify an EMILIA authorization receipt or Class-A device signoff entirely in your '
    + 'browser with pure public-key math. Nothing uploaded, no account, no server '
    + 'trusted — the open @emilia-protocol/verify package, running client-side.',
  alternates: { canonical: '/verify' },
  openGraph: {
    title: 'Verify an Authorization Receipt — offline, in your browser',
    description:
      'Drop a receipt or a Face ID device signoff and watch every cryptographic '
      + 'check verify client-side. Nothing leaves your machine.',
    url: 'https://www.emiliaprotocol.ai/verify',
  },
};

export default function VerifyLayout({ children }: { children: React.ReactNode }) {
  return children;
}
