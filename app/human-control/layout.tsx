/**
 * Human-Control vertical landing page (SEO + program/prime/oversight surface).
 *
 * Positions EMILIA as an action-bound approval-evidence layer for autonomous
 * systems, with customer-authored mappings to selected oversight references.
 * See PIP-013 (Human-Oversight Profile) and docs/briefs/HUMAN_CONTROL_BRIEF.md.
 *
 * @license Apache-2.0
 */
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Action-Bound Approval Evidence for Autonomous Systems — EMILIA',
  description:
    'Verify that an accepted enrolled credential signed an exact autonomous action or finite '
    + 'mandate. Customer-authored evidence mappings can support an authorized oversight review; '
    + 'a receipt does not establish civil identity or legal compliance.',
  alternates: { canonical: '/human-control' },
  openGraph: {
    title: 'Make Required Approval Evidence Checkable',
    description:
      'Action-bound evidence for an accepted enrolled approver credential, with finite mandates, '
      + 'optional quorum, offline verification, and explicit limits. Apache-2.0.',
    url: 'https://www.emiliaprotocol.ai/human-control',
    type: 'website',
  },
  keywords: [
    'meaningful human control',
    'verifiable human oversight',
    'human in the loop AI',
    'human on the loop',
    'DoD Directive 3000.09 evidence mapping',
    'autonomy in weapon systems human judgment',
    'EU AI Act Article 14 human oversight',
    'autonomous weapons accountability',
    'human control evidence layer',
    'AI agent human authorization receipt',
    'auditable human oversight autonomous systems',
    'NIST AI RMF human oversight',
  ],
};

export default function HumanControlLayout({ children }: { children: React.ReactNode }) {
  return children;
}
