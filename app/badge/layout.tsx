import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Works with EMILIA — Integration Badge',
  description:
    'Grab the "Works with EMILIA" badge for your agent, app, or platform. '
    + 'Copy-paste Markdown, HTML, or reStructuredText. For real integrators — '
    + 'it signals that irreversible actions require a named human\'s signoff.',
  alternates: { canonical: '/badge' },
  openGraph: {
    title: 'Works with EMILIA — Integration Badge',
    description:
      'Show your users that consequential actions require a named human\'s '
      + 'signoff, with an offline-verifiable receipt. Copy-paste embed codes.',
    url: 'https://www.emiliaprotocol.ai/badge',
    type: 'website',
  },
  keywords: [
    'Works with EMILIA badge',
    'EMILIA integration badge',
    'agent trust badge',
    'human in the loop badge',
    'AI agent accountability badge',
  ],
};

export default function BadgeLayout({ children }: { children: React.ReactNode }) {
  return children;
}
