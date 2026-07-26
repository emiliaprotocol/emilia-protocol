// Server layout providing metadata for the client-component /protocol page.
// Next.js: 'use client' pages can't export metadata; the server-component
// layout in the same route segment supplies it.

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Open Evidence Protocol for Consequential AI-Agent Actions',
  description:
    'The open verification substrate behind EMILIA Gate: exact-action evidence, pinned verification, '
    + 'one-time authorization, execution continuity, and portable proof.',
  alternates: { canonical: '/protocol' },
  openGraph: {
    title: 'EMILIA Protocol — Open Evidence for Consequential Machine Action',
    description:
      'Identity and policy remain inputs. EMILIA Protocol carries exact-action evidence across approval, execution, uncertainty, and remedy.',
    url: 'https://www.emiliaprotocol.ai/protocol',
    type: 'article',
  },
};

export default function ProtocolLayout({ children }: { children: React.ReactNode }) {
  return children;
}
