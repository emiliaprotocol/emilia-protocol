/**
 * Human-Control vertical landing page (SEO + program/prime/oversight surface).
 *
 * Positions EMILIA as the verifiable "meaningful human control" evidence layer
 * for autonomous systems — mapping the receipt primitive to DoD Directive 3000.09,
 * EU AI Act Article 14, NIST AI RMF, and the CCW/LAWS human-control requirement.
 * See PIP-013 (Human-Oversight Profile) and docs/briefs/HUMAN_CONTROL_BRIEF.md.
 *
 * @license Apache-2.0
 */
export const metadata = {
  title: 'Verifiable Meaningful Human Control for Autonomous Systems — EMILIA',
  description:
    'Everyone requires a human in the loop; no one can prove it. EMILIA produces an '
    + 'offline-verifiable receipt that a named human authorized the exact autonomous action — '
    + 'the evidence layer for DoD Directive 3000.09, EU AI Act Article 14, and NIST AI RMF.',
  alternates: { canonical: '/human-control' },
  openGraph: {
    title: 'Verifiable Meaningful Human Control for Autonomous Systems',
    description:
      'Turn "meaningful human control" from doctrine into a cryptographic artifact: an '
      + 'offline-verifiable receipt proving a named human authorized the exact action. '
      + 'Two-person quorum, rules-of-engagement scoping, fail-closed, air-gap ready. Apache-2.0.',
    url: 'https://www.emiliaprotocol.ai/human-control',
    type: 'website',
  },
  keywords: [
    'meaningful human control',
    'verifiable human oversight',
    'human in the loop AI',
    'human on the loop',
    'DoD Directive 3000.09 compliance',
    'autonomy in weapon systems human judgment',
    'EU AI Act Article 14 human oversight',
    'autonomous weapons accountability',
    'human control evidence layer',
    'AI agent human authorization receipt',
    'auditable human oversight autonomous systems',
    'NIST AI RMF human oversight',
  ],
};

export default function HumanControlLayout({ children }) {
  return children;
}
