import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Privacy Policy — EMILIA Protocol',
  description:
    'How EMILIA Protocol collects, uses, and protects personal data. ' +
    'Aligned with GDPR, UK GDPR, and CCPA. Functions as the working ' +
    'data processing addendum until an executed customer-specific DPA ' +
    'supersedes it.',
  alternates: { canonical: '/legal/privacy' },
  openGraph: {
    title: 'EMILIA Protocol Privacy Policy',
    description: 'Data collection, processing, retention, and rights.',
    url: 'https://www.emiliaprotocol.ai/legal/privacy',
    type: 'article',
  },
};

export default function PrivacyLayout({ children }: { children: React.ReactNode }) {
  return children;
}
