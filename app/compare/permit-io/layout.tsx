import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA Protocol vs Permit.io — Authorization vs Accountable Signoff',
  description:
    'Permit.io enforces fine-grained authorization (RBAC/ABAC/ReBAC) for AI ' +
    'agents. EMILIA adds a named human’s signoff before an irreversible ' +
    'action plus an offline-verifiable authorization receipt. How they differ, and ' +
    'why they are strongest together.',
  alternates: { canonical: '/compare/permit-io' },
  openGraph: {
    title: 'EMILIA Protocol vs Permit.io',
    description:
      'Authorization decides what an agent may do. EMILIA’s receipt proves a named human ' +
      'approved the exact irreversible action, with an offline-verifiable receipt.',
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
