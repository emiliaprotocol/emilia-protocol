import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Add Receipt Required to an MCP Server in 10 Minutes',
  description:
    'No receipt, no irreversible action. Publish an Action Risk Manifest, wrap one dangerous MCP '
    + 'tool, return 428 Receipt Required until the agent brings an EP-RECEIPT-v1, then verify '
    + 'offline, consume before mutation, and refuse replay.',
  alternates: { canonical: '/guides/require-receipt' },
  openGraph: {
    title: 'Add Receipt Required to an MCP server in 10 minutes',
    description:
      'The adoption rail for agent tools: Action Risk Manifest -> 428 Receipt Required -> signed receipt '
      + '-> consume before mutation -> replay refused.',
    url: 'https://www.emiliaprotocol.ai/guides/require-receipt',
    type: 'article',
  },
  keywords: [
    '428 receipt required',
    'require a receipt',
    'Action Risk Manifest',
    'agent authorization middleware',
    'no receipt no irreversible action',
    'MCP tool authorization',
    'offline receipt verification',
    'agent self-serve authorization',
    'MCP human signoff',
    'AI agent receipt',
    'irreversible action guardrail',
    'EMILIA require-receipt',
  ],
};

export default function RequireReceiptGuideLayout({ children }: { children: React.ReactNode }) {
  return children;
}
