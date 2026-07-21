import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Model-to-Matter - A verifiable clearance boundary for AI-designed experiments',
  description:
    'Model-to-Matter is a verifiable clearance boundary between frontier models and '
    + 'physical execution. Before an automated lab runs an AI-proposed step, the executor '
    + 'requires offline-verifiable evidence that every pinned authority cleared this exact '
    + 'action, once. It composes with screening; it does not replace it.',
  alternates: { canonical: '/model-to-matter' },
  openGraph: {
    title: 'EMILIA Model-to-Matter',
    description:
      'A verifiable clearance boundary between frontier models and physical execution. '
      + 'Six evidence legs, executor-pinned policy, single-use clearance, fail-closed.',
    url: 'https://www.emiliaprotocol.ai/model-to-matter',
    type: 'article',
  },
  keywords: [
    'autonomous laboratory authorization',
    'self-driving lab safety',
    'AI-designed experiment clearance',
    'cloud lab authorization gate',
    'DNA synthesis authorization receipt',
    'biosecurity human authorization',
    'complete mediation reference monitor',
    'frontier model physical execution control',
    'model to matter',
    'AI biosecurity accountability',
  ],
};

export default function ModelToMatterLayout({ children }: { children: React.ReactNode }) {
  return children;
}
