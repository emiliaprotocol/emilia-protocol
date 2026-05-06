export const metadata = {
  title: 'Legal — EMILIA Protocol',
  description:
    'Privacy policy, terms of service, acceptable-use policy, sub-processor ' +
    'list, and data-processing addendum for EMILIA Protocol. Working ' +
    'documents pending counsel finalization.',
  alternates: { canonical: '/legal' },
  openGraph: {
    title: 'EMILIA Protocol Legal',
    description:
      'Privacy, terms, acceptable use, and sub-processors.',
    url: 'https://www.emiliaprotocol.ai/legal',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol legal',
    'EMILIA Protocol privacy policy',
    'EMILIA Protocol terms',
    'EMILIA Protocol DPA',
    'EMILIA Protocol sub-processors',
  ],
};

export default function LegalLayout({ children }) {
  return children;
}
