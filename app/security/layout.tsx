import type { Metadata } from 'next';
import proofStats from '@/lib/proof-stats.json';

const evidence = `${proofStats.securityCase.claims} executable security claims, `
  + `${proofStats.tamarin.verifiedObligations} composed Tamarin obligations, `
  + `${proofStats.conformance.vectors} conformance vectors, and `
  + `${proofStats.externalImplementation.hostilityCases} external hostility cases`;

export const metadata: Metadata = {
  title: 'Product Security — Rerunnable Evidence for EMILIA Gate',
  description:
    `EMILIA Gate and Protocol security evidence backed by ${evidence}. `
    + 'Includes shipped controls, formal scope, assumptions, exclusions, conformance, and disclosure policy.',
  alternates: { canonical: '/security' },
  openGraph: {
    title: 'EMILIA Product Security',
    description:
      `Machine-verifiable security evidence: ${evidence}.`,
    url: 'https://www.emiliaprotocol.ai/security',
    type: 'website',
  },
  keywords: [
    'EMILIA Protocol security',
    'EMILIA Protocol SOC 2',
    'EMILIA Protocol compliance',
    'AI authorization security',
    'pre-action authorization compliance',
    'NIST AI RMF',
    'EU AI Act',
    'responsible disclosure AI',
  ],
};

export default function SecurityLayout({ children }: { children: React.ReactNode }) {
  return children;
}
