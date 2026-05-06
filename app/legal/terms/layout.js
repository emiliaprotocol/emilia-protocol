export const metadata = {
  title: 'Terms of Service — EMILIA Protocol',
  description:
    'Terms governing use of the emiliaprotocol.ai website, the EP Cloud ' +
    'service, the open-source reference runtime, and the published SDKs.',
  alternates: { canonical: '/legal/terms' },
  openGraph: {
    title: 'EMILIA Protocol Terms of Service',
    description: 'Terms for the websites, hosted service, and open-source artifacts.',
    url: 'https://www.emiliaprotocol.ai/legal/terms',
    type: 'article',
  },
};

export default function TermsLayout({ children }) {
  return children;
}
