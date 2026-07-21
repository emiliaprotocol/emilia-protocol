import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Contact — Pilot, Partnership, and Press Inquiries',
  description:
    'Reach EMILIA Protocol for pilot programs, integration partnerships, ' +
    'security disclosures, press, and procurement conversations.',
  alternates: { canonical: '/contact' },
  openGraph: {
    title: 'Contact EMILIA Protocol',
    description:
      'Pilot, partnership, security, and procurement contact channels.',
    url: 'https://www.emiliaprotocol.ai/contact',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol contact',
    'pilot inquiry',
    'partnership inquiry',
    'security disclosure',
  ],
};

export default function ContactLayout({ children }: { children: React.ReactNode }) {
  return children;
}
