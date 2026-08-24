import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Approver Reference Apps for Exact-Action Signoff | EMILIA',
  description:
    'Open iOS, Android, Swift, and Kotlin reference artifacts for exact-action '
    + 'human decisions when a customer-owned Gate policy requires fresh signoff.',
  alternates: { canonical: '/product/accountable-signoff' },
  robots: { index: true, follow: true },
  openGraph: {
    title: 'EMILIA Approver Reference Apps',
    description:
      'Reference clients capture a device-bound decision over exact action bytes. '
      + 'They are a Gate capture surface, not a standalone production control.',
    url: 'https://www.emiliaprotocol.ai/product/accountable-signoff',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'EMILIA Approver Reference Apps',
    description: 'Exact-action signoff reference clients for buyer-controlled Gate deployments.',
  },
  keywords: [
    'exact action human approval',
    'AI agent accountable signoff',
    'device bound action approval',
    'CAID action fingerprint',
  ],
};

export default function AccountableSignoffLayout({ children }: { children: React.ReactNode }) {
  return children;
}
