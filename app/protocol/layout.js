// Server layout providing metadata for the client-component /protocol page.
// Next.js: 'use client' pages can't export metadata; the server-component
// layout in the same route segment supplies it.

export const metadata = {
  title: 'The Protocol — 4 Layers of Pre-Action Trust for AI Agents',
  description:
    'EMILIA Protocol composes four primitives — Eye, Handshake, Signoff, ' +
    'Commit — that gate every consequential AI agent action behind a ' +
    'cryptographic ceremony. 26 TLA+ theorems verified, 35 Alloy facts, ' +
    'Apache 2.0. Read the full protocol.',
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

export default function ProtocolLayout({ children }) {
  return children;
}
