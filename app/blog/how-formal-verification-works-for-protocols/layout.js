export const metadata = {
  title: 'We Formally Verified an AI-Safety Protocol — Here\'s the Proof',
  description:
    'An AI agent cannot take an irreversible action without a signed human ' +
    'approval — and we proved it. How EMILIA Protocol\'s 26 TLA+ invariants ' +
    'and 35 Alloy facts machine-check the authorization ceremony on every ' +
    'commit, and what that does (and does not) guarantee.',
  alternates: { canonical: '/blog/how-formal-verification-works-for-protocols' },
  openGraph: {
    title: 'We Formally Verified an AI-Safety Protocol — Here\'s the Proof',
    description:
      'Most AI governance is policy PDFs. EMILIA\'s core safety guarantee is ' +
      'machine-checked with TLA+ and Alloy on every commit. Read the proofs.',
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
