export const metadata = {
  title: 'Trust & Security — EMILIA Protocol',
  description:
    'Security posture, compliance roadmap, and responsible-disclosure ' +
    'process for EMILIA Protocol. Apache 2.0 reference runtime with formal ' +
    'verification (26 TLA+ theorems, 35 Alloy facts) in CI; SOC 2 Type I, ' +
    'external cryptographic-protocol review, and bug bounty in roadmap.',
  alternates: { canonical: '/security' },
  openGraph: {
    title: 'EMILIA Protocol Trust & Security',
    description:
      'Compliance posture, formal verification, and disclosure policy.',
    url: 'https://www.emiliaprotocol.ai/security',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol security',
    'EMILIA Protocol SOC 2',
    'EMILIA Protocol compliance',
    'AI authorization security',
    'pre-action authorization compliance',
    'NIST AI RMF',
    'EU AI Act',
    'responsible disclosure AI',
  ],
};

export default function SecurityLayout({ children }) {
  return children;
}
