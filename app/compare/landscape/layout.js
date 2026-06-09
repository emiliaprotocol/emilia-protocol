export const metadata = {
  title: 'AI Agent Action-Governance Landscape — EMILIA vs HumanLayer, Tenet, CIBA & DRP',
  description:
    'An honest map of the agent action-governance category: EMILIA vs HumanLayer ' +
    '(approval routing), Tenet (gates + hash-chain audit), CIBA/WorkOS (auth-layer ' +
    'approval), the IETF Delegation Receipt Protocol, and DIY. What each does well, and ' +
    'where EMILIA differs — formal verification, an offline-verifiable receipt, and ' +
    'enforced separation of duties.',
  alternates: { canonical: '/compare/landscape' },
  openGraph: {
    title: 'The AI Agent Action-Governance Landscape',
    description:
      'EMILIA vs HumanLayer, Tenet, CIBA/WorkOS, and the IETF Delegation Receipt Protocol — ' +
      'conceded strengths and honest differences.',
    url: 'https://www.emiliaprotocol.ai/compare/landscape',
    type: 'article',
  },
  keywords: [
    'AI agent approval',
    'HumanLayer alternative',
    'Tenet alternative',
    'Delegation Receipt Protocol',
    'CIBA agent authorization',
    'agent action governance',
    'tamper-evident agent audit trail',
    'human approval AI agent irreversible actions',
  ],
};

export default function CompareLandscapeLayout({ children }) {
  return children;
}
