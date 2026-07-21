import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA Gate Solution Profiles',
  description:
    'Solution profiles for applying EMILIA Gate to MCP tool calls, government, financial, energy, enterprise, and multi-party action boundaries.',
  alternates: { canonical: '/use-cases' },
  openGraph: {
    title: 'EMILIA Gate Solution Profiles',
    description:
      'One consequence firewall, adapted to configured action and evidence requirements.',
    url: 'https://www.emiliaprotocol.ai/use-cases',
    type: 'article',
  },
};

export default function UseCasesLayout({ children }: { children: React.ReactNode }) {
  return children;
}
