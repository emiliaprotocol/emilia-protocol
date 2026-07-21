import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Add Receipt Required to an MCP Server in 10 Minutes',
  description:
    'No receipt, no irreversible action. Publish an Action Control Manifest, return a parameter-bound '
    + '428 challenge, acquire a Class-A receipt through EP-APPROVAL-v1, verify offline, consume before '
    + 'mutation, and refuse replay.',
  alternates: { canonical: '/guides/require-receipt' },
  openGraph: {
    title: 'Add Receipt Required to an MCP server in 10 minutes',
    description:
      'The adoption rail for agent tools: Action Control Manifest -> 428 Receipt Required -> human approval '
      + '-> signed receipt -> consume before mutation -> replay refused.',
    url: 'https://www.emiliaprotocol.ai/guides/require-receipt',
    type: 'article',
  },
  keywords: [
    '428 receipt required',
    'require a receipt',
    'Action Control Manifest',
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
