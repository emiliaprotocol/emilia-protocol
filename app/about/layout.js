export const metadata = {
  title: 'About — EMILIA Protocol',
  description:
    'The team and advisors behind EMILIA Protocol — the open standard for ' +
    'verifiable pre-action authorization in AI agent and high-risk-action ' +
    'workflows. Apache 2.0, formally verified, in production.',
  alternates: { canonical: '/about' },
  openGraph: {
    title: 'About EMILIA Protocol',
    description:
      'Team, advisors, and mission of the open pre-action authorization standard.',
    url: 'https://www.emiliaprotocol.ai/about',
    type: 'profile',
  },
  keywords: [
    'EMILIA Protocol team',
    'EMILIA Protocol founders',
    'AI authorization standard team',
    'pre-action authorization team',
  ],
};

export default function AboutLayout({ children }) {
  return children;
}
