import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA Protocol vs Permit.io — Authorization and Exact-Action Authority',
  description:
    'Permit.io enforces fine-grained authorization (RBAC/ABAC/ReBAC) for AI ' +
    'agents. EMILIA adds finite exact-action authority and portable evidence, with ' +
    'named-human signoff only when the customer mandate or local policy requires it.',
  alternates: { canonical: '/compare/permit-io' },
  openGraph: {
    title: 'EMILIA Protocol vs Permit.io',
    description:
      'Permit.io handles fine-grained authorization. EMILIA adds finite exact-action authority ' +
      'and an authorization receipt verifiable offline against pinned keys.',
    url: 'https://www.emiliaprotocol.ai/compare/permit-io',
    type: 'article',
  },
  keywords: [
    'Permit.io vs EMILIA Protocol',
    'Permit.io alternative',
    'AI agent authorization vs human signoff',
    'fine-grained authorization AI agents',
    'RBAC ABAC ReBAC AI agents',
    'human in the loop agent actions',
    'agent action accountability',
  ],
};
export default function ComparePermitLayout({ children }: { children: React.ReactNode }) {
  return children;
}
