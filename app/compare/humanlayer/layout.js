export const metadata = {
  title: 'EMILIA Protocol vs HumanLayer — Approval Plumbing vs Provable Authorization',
  description:
    'HumanLayer routes agent approvals to Slack or email — great for human-in-the-loop UX. ' +
    'EMILIA binds the signoff to the exact action, consumes it once, and mints an ' +
    'offline-verifiable authorization receipt. Approval convenience vs cryptographic evidence — which you need, and when.',
  alternates: { canonical: '/compare/humanlayer' },
  openGraph: {
    title: 'EMILIA Protocol vs HumanLayer',
    description:
      'Approval plumbing vs provable authorization. Keep the Slack approval — change what it proves.',
    url: 'https://www.emiliaprotocol.ai/compare/humanlayer',
    type: 'article',
  },
  keywords: [
    'HumanLayer alternative',
    'HumanLayer vs EMILIA',
    'agent approval workflow',
    'human in the loop AI agents',
    'verifiable human signoff',
    'provable authorization agents',
    'agent action accountability',
  ],
};

export default function CompareHumanLayerLayout({ children }) {
  return children;
}
