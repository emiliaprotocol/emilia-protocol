export const metadata = {
  title: 'Adopt EMILIA — Integrate Pre-Action Authorization',
  description:
    'Three-step adoption guide. Install the SDK, gate one high-risk action ' +
    'in observe mode for two weeks, flip to enforce. ' +
    '@emilia-protocol/sdk on npm; Python and Go ports in progress.',
  alternates: { canonical: '/adopt' },
  openGraph: {
    title: 'Adopt EMILIA Protocol in Three Steps',
    description:
      'Install the SDK, gate one action in observe mode, flip to enforce.',
    url: 'https://www.emiliaprotocol.ai/adopt',
    type: 'article',
  },
};

export default function AdoptLayout({ children }) {
  return children;
}
