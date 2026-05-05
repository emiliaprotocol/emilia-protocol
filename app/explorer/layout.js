export const metadata = {
  title: 'Explorer — Verify Any EMILIA Receipt Publicly',
  description:
    'Public verifier for EMILIA Protocol receipts. Paste a receipt ID or ' +
    'evidence packet, get cryptographic verification — like Etherscan for ' +
    'AI action authorization. Zero-dependency offline verification also ' +
    'available via @emilia-protocol/verify on npm.',
  alternates: { canonical: '/explorer' },
  openGraph: {
    title: 'Trust Receipt Explorer — Verify AI Action Authorization',
    description:
      'Public, transparent, cryptographically verified receipts. Like ' +
      'Etherscan for trust.',
    url: 'https://www.emiliaprotocol.ai/explorer',
    type: 'website',
  },
};

export default function ExplorerLayout({ children }) {
  return children;
}
