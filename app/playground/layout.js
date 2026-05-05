export const metadata = {
  title: 'Playground — Try the Protocol Live',
  description:
    'Interactive EMILIA Protocol playground. Initiate a handshake, request ' +
    'a signoff, consume a receipt — see the full ceremony in your browser. ' +
    'No login required for the public-test entity.',
  alternates: { canonical: '/playground' },
  openGraph: {
    title: 'EMILIA Protocol Playground — Live Trust Ceremony Demo',
    description:
      'Run the full protocol ceremony in your browser. Initiate, sign off, ' +
      'consume — receipts you can verify offline.',
    url: 'https://www.emiliaprotocol.ai/playground',
    type: 'website',
  },
};

export default function PlaygroundLayout({ children }) {
  return children;
}
