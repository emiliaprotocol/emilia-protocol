export const metadata = {
  title: 'Government Use Case — Benefit Integrity & Caseworker Override Control',
  description:
    'Pre-execution trust enforcement for SNAP, Medicaid, unemployment, and ' +
    'federal payment systems. Block benefit-redirection fraud and caseworker ' +
    'override abuse before the change executes. Compliance-mapped to NIST AI ' +
    'RMF and federal AI executive orders.',
  alternates: { canonical: '/use-cases/government' },
  openGraph: {
    title: 'EMILIA Protocol for Government Benefit Integrity',
    description:
      'Block benefit-redirection fraud before payment direction can change. ' +
      'NIST AI RMF mapped, observe-mode rollout, evidence packets for IG/GAO.',
    url: 'https://www.emiliaprotocol.ai/use-cases/government',
    type: 'article',
  },
  keywords: [
    'benefit redirection fraud',
    'SNAP fraud prevention',
    'Medicaid fraud prevention',
    'caseworker override control',
    'government AI controls',
    'NIST AI RMF compliance',
    'federal AI executive order',
  ],
};

export default function GovUseCaseLayout({ children }) {
  return children;
}
