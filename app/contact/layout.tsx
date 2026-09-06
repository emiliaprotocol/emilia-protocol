import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Contact EMILIA | Discuss Your AI Workflow',
  description:
    'Discuss one AI workflow with EMILIA: the job, its owner, the authority it needs and how you will review the work. Workforce evaluations, integrations and inquiries.',
  alternates: { canonical: '/contact' },
  openGraph: {
    title: 'Discuss Your AI Workflow with EMILIA',
    description:
      'Start with one workflow and a named owner. The workforce product is a private local alpha; scope and production readiness are agreed separately.',
    url: 'https://www.emiliaprotocol.ai/contact',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol contact',
    'AI workforce evaluation',
    'partnership inquiry',
    'security disclosure',
  ],
};

export default function ContactLayout({ children }: { children: React.ReactNode }) {
  return children;
}
