import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Authorization Evidence Chain -05 — Evidence Satisfaction for One Exact Action',
  description:
    'Document 04 in the EMILIA canonical path. EP-AEC -05 evaluates whether natively verified, '
    + 'action-matched evidence satisfies a relying party’s explicit requirement for one exact '
    + 'material action. SATISFIED is evidence, not local authorization, execution, or proof of complete mediation.',
  alternates: { canonical: '/evidence-chain' },
  openGraph: {
    title: 'EP-AEC -05 — evidence satisfaction for one exact action',
    description:
      'The composition object and verifier that checks required artifacts under their native '
      + 'rules, matches them to one exact material action, and returns SATISFIED or UNSATISFIED. '
      + 'The executor authorizes separately.',
    url: 'https://www.emiliaprotocol.ai/evidence-chain',
    type: 'article',
  },
  keywords: [
    'authorization evidence chain',
    'compose agent authorization receipts',
    'verify multiple agent receipts offline',
    'offline evidence satisfaction agent action',
    'agent authorization composition',
    'canonical action binding',
    'cross-receipt verification',
    'heterogeneous receipt verification',
    'delegation receipt policy receipt human authorization',
    'EP-AEC',
    'agent receipt convergence',
    'fail-closed authorization verifier',
  ],
};

export default function EvidenceChainLayout({ children }: { children: React.ReactNode }) {
  return children;
}
