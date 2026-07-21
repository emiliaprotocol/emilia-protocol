import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Pilot EMILIA in a High-Risk Workflow',
  description:
    'Start with one action class — payment changes, delegated approvals, ' +
    'operator overrides, or agent execution — and prove the control ' +
    'value fast.',
  alternates: { canonical: '/partners' },
  openGraph: {
    title: 'Pilot EMILIA Protocol',
    description:
      'Pick one high-risk action class and prove the control value in a ' +
      'time-boxed pilot.',
    url: 'https://www.emiliaprotocol.ai/partners',
    type: 'article',
  },
  keywords: [
    'EMILIA Protocol pilot',
    'pre-action authorization pilot',
    'AI agent pilot program',
    'fraud-defense pilot',
  ],
};

export default function PartnersLayout({ children }: { children: React.ReactNode }) {
  return children;
}
