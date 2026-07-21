import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Authorization Evidence Chains — Compose Agent Receipts into One Verdict',
  description:
    'A dozen IETF drafts define receipts for an AI agent’s action — delegation, '
    + 'policy/permit, decision, and human-authorization receipts — all on the same '
    + 'canonical substrate. EP-AEC defines the missing layer: how a relying party verifies '
    + 'that several heterogeneous receipts all bind the same action and each verify under '
    + 'their own rules, yielding a single offline, fail-closed SATISFIED or UNSATISFIED evidence verdict. The executor authorizes separately. Open protocol, '
    + 'tri-language verifiers, filed Internet-Draft.',
  alternates: { canonical: '/evidence-chain' },
  openGraph: {
    title: 'EP-AEC — the layer that composes agent-authorization receipts',
    description:
      'Not a 13th receipt format. The composition object and verifier that takes the '
      + 'delegation, policy, and human-authorization receipts for one action and returns a '
      + 'single offline SATISFIED/UNSATISFIED evidence verdict — the verifier-side convergence point for the agent '
      + 'authorization field.',
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
