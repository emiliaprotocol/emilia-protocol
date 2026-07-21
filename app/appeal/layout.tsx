import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Appeal — Challenge an EP Decision or Receipt',
  description:
    'File an appeal against an EMILIA Protocol authorization decision or ' +
    'a published trust receipt. Structured dispute process with ' +
    'evidentiary support and named resolution authority.',
  alternates: { canonical: '/appeal' },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'EMILIA Protocol Appeal',
    description:
      'File an appeal against an authorization decision or published ' +
      'receipt.',
    url: 'https://www.emiliaprotocol.ai/appeal',
    type: 'website',
  },
  keywords: [
    'EP appeal',
    'trust receipt dispute',
    'authorization decision appeal',
  ],
};

export default function AppealLayout({ children }: { children: React.ReactNode }) {
  return children;
}
