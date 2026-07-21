import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'GRACE — EMILIA Gate Energy Profile',
  description:
    'An EMILIA Gate solution profile for bounded energy-control actions and portable proof-of-curtailment evidence. Reference implementation, not a claimed grid deployment.',
  alternates: { canonical: '/grace' },
  openGraph: {
    title: 'GRACE — EMILIA Gate Energy Profile',
    description:
      'Compose authorization, execution, and measurement evidence for configured energy-control boundaries.',
    url: 'https://www.emiliaprotocol.ai/grace',
    type: 'website',
  },
};

export default function GraceLayout({ children }: { children: React.ReactNode }) {
  return children;
}
