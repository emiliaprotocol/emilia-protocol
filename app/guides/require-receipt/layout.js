export const metadata = {
  title: 'Require a Receipt in One Endpoint — the 402 loop for agent tools',
  description:
    'No receipt, no irreversible action. Make any service refuse an irreversible call unless a '
    + 'valid authorization receipt rides with it: the caller gets a 402 describing exactly what to '
    + 'bring, a well-behaved agent obtains a receipt and retries, and you verify it offline — no '
    + 'EMILIA backend. One middleware (@emilia-protocol/require-receipt), framework-agnostic, '
    + 'fail-closed.',
  alternates: { canonical: '/guides/require-receipt' },
  openGraph: {
    title: 'Require a receipt in one endpoint — the 402 loop',
    description:
      'A tiny demand-side middleware: irreversible action without proof → 402 EMILIA Receipt '
      + 'Required → agent obtains a receipt, retries → verified offline. No receipt, no irreversible action.',
    url: 'https://www.emiliaprotocol.ai/guides/require-receipt',
    type: 'article',
  },
  keywords: [
    '402 receipt required',
    'require a receipt',
    'agent authorization middleware',
    'no receipt no irreversible action',
    'x402 agent commerce',
    'MCP tool authorization',
    'offline receipt verification',
    'agent self-serve authorization',
    'irreversible action guardrail',
    'EMILIA require-receipt',
  ],
};

export default function RequireReceiptGuideLayout({ children }) {
  return children;
}
