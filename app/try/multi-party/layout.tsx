// SPDX-License-Identifier: Apache-2.0
// Metadata for /try/multi-party — the multi-party (two-person rule) demo. Built
// as a layout so the page itself can stay a client component.

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'The two-person rule for AI actions — multi-party approval demo — EMILIA Protocol',
  description:
    'A $40M release that needs an ordered quorum of three named humans — Program Officer, Authorizing Official, Inspector General — each binding to the exact action. Verify the quorum live in your browser; watch separation-of-duties reject a duplicate signer. Nothing uploaded.',
  alternates: { canonical: '/try/multi-party' },
  openGraph: {
    title: 'The two-person rule, cryptographically enforced — multi-party approval',
    description:
      'An ordered quorum of named humans, each bound to the exact action, verified offline in your browser with EP-QUORUM-v1.',
    url: 'https://www.emiliaprotocol.ai/try/multi-party',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'The two-person rule, cryptographically enforced',
    description: 'An ordered quorum of named humans, each bound to the exact action — verified live in your browser.',
  },
};

export default function MultiPartyLayout({ children }: { children: React.ReactNode }) {
  return children;
}
