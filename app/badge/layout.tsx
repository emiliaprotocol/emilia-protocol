import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Works with EMILIA — Integration Badge',
  description:
    'Grab the "Works with EMILIA" badge for your agent, app, or platform. '
    + 'Copy-paste Markdown, HTML, or reStructuredText. For real integrators, '
    + 'it signals finite customer authority and policy evidence on configured protected paths.',
  alternates: { canonical: '/badge' },
  openGraph: {
    title: 'Works with EMILIA — Integration Badge',
    description:
      'Signal finite customer authority and portable evidence on configured protected paths. '
      + 'Named-human signoff applies when the customer mandate or local policy requires it.',
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
