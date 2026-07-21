// Server layout providing metadata for the client-component /protocol page.
// Next.js: 'use client' pages can't export metadata; the server-component
// layout in the same route segment supplies it.

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'The Protocol — 4 Layers of Pre-Action Trust for AI Agents',
  description:
    'EMILIA Protocol composes four primitives — Eye, Handshake, Signoff, Commit — to '
    + 'gate every consequential AI agent action behind a verified cryptographic ceremony.',
  alternates: { canonical: '/protocol' },
  openGraph: {
    title: 'The Protocol — 4 Layers of Pre-Action Trust for AI Agents',
    description:
      'Eye → Handshake → Signoff → Commit. The composable trust ceremony ' +
      'for AI agent action authorization, formally verified.',
    url: 'https://www.emiliaprotocol.ai/protocol',
    type: 'article',
  },
};

export default function ProtocolLayout({ children }: { children: React.ReactNode }) {
  return children;
}
