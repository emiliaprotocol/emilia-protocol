/** AI Trust Desk historical-evaluation metadata. @license Apache-2.0 */

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Historical AI Trust Desk Evaluation',
  description:
    'Archived evaluation of a questionnaire-drafting and trust-page concept. '
    + 'AI Trust Desk is not a current commercial EMILIA offer.',
  alternates: { canonical: '/trust-desk' },
  robots: { index: false, follow: false, nocache: true },
  openGraph: {
    title: 'Historical AI Trust Desk Evaluation',
    description: 'Archived product-evaluation surface. No current orders, intake, checkout, delivery, or service-level commitment.',
    url: 'https://www.emiliaprotocol.ai/trust-desk',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'Historical AI Trust Desk Evaluation',
    description: 'Archived evaluation surface, not a current commercial offer.',
  },
};

export default function TrustDeskLayout({ children }: { children: React.ReactNode }) {
  return children;
}
