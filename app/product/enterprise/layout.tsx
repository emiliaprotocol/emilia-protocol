import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Enterprise Gate Implementation Pathways | EMILIA Protocol',
  description:
    'Inspect reference components and separately scoped implementation paths for customer-controlled Gate deployments. No generally available managed service or production deployment is claimed.',
  alternates: { canonical: '/product/enterprise' },
  openGraph: {
    title: 'Enterprise Gate Implementation Pathways',
    description:
      'Reference components, explicit limitations, and buyer-specific implementation work after a nonproduction boundary assessment.',
    url: 'https://www.emiliaprotocol.ai/product/enterprise',
    type: 'article',
  },
  keywords: [
    'enterprise AI governance',
    'privileged access management',
    'PAM AI integration',
    'zero trust action',
    'consequence boundary implementation',
  ],
};

export default function EnterpriseProductLayout({ children }: { children: React.ReactNode }) {
  return children;
}
