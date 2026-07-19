import proofStats from '@/lib/proof-stats.json';

const description =
  `Machine-verifiable EMILIA engineering evidence: ${proofStats.securityCase.claims} executable `
  + `security claims, ${proofStats.tamarin.verifiedObligations} composed Tamarin obligations, `
  + `${proofStats.conformance.vectors} conformance vectors, and external Rust hostility testing.`;

export const metadata = {
  title: 'Engineering Evidence — Machine-Verifiable Security Case',
  description,
  alternates: { canonical: '/proof' },
  openGraph: {
    title: 'EMILIA Engineering Evidence — Security Claims You Can Execute',
    description,
    url: 'https://www.emiliaprotocol.ai/proof',
    type: 'article',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Engineering Evidence',
    description,
  },
  keywords: [
    'EMILIA Protocol security evidence',
    'Tamarin formal verification AI authorization',
    'machine-verifiable security case',
    'AI agent authorization conformance',
    'Dolev-Yao model AI agents',
    'authorization receipt security proof',
  ],
};

export default function ProofLayout({ children }) {
  return children;
}
