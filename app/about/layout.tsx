import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'About EMILIA | Management for Your AI Workforce',
  description:
    'EMILIA is building the workspace for people responsible for AI work, with Gate enforcing ' +
    'customer authority on configured paths and an open protocol underneath.',
  alternates: { canonical: '/about' },
  openGraph: {
    title: 'About EMILIA',
    description:
      'The company, the workforce product and the open Protocol. Give every agent a job, set its authority, and know what happened.',
    url: 'https://www.emiliaprotocol.ai/about',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol team',
    'EMILIA Protocol founders',
    'AI workforce management',
    'authorization infrastructure for agentic AI',
  ],
};

export default function AboutLayout({ children }: { children: React.ReactNode }) {
  return children;
}
