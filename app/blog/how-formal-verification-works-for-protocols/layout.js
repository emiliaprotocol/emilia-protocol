export const metadata = {
  title: 'How Formal Verification Works for Protocols (TLA+ and Alloy)',
  description:
    'A practical primer on TLA+ and Alloy: what each tool proves, how they ' +
    'differ, and why pre-action authorization protocols benefit from both. ' +
    'Worked example from EMILIA Protocol\'s 26 TLA+ theorems and 35 Alloy ' +
    'facts.',
  alternates: { canonical: '/blog/how-formal-verification-works-for-protocols' },
  openGraph: {
    title: 'How Formal Verification Works for Protocols',
    description:
      'TLA+ proves temporal properties. Alloy bounds-checks structural ' +
      'invariants. A primer with examples from a verified AI auth protocol.',
    url: 'https://www.emiliaprotocol.ai/blog/how-formal-verification-works-for-protocols',
    type: 'article',
    publishedTime: '2026-04-18T00:00:00.000Z',
  },
  keywords: [
    'formal verification protocols',
    'TLA+ tutorial',
    'Alloy tutorial',
    'protocol verification',
    'TLA+ vs Alloy',
    'formal methods AI',
    'verified protocol',
  ],
};

export default function BlogFormalVerificationLayout({ children }) {
  return children;
}
