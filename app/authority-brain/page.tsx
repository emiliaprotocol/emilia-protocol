// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import AuthorityBrainExperience from '@/components/authority-brain/AuthorityBrainExperience';

export const metadata: Metadata = {
  title: 'Authority Brain: See Where Your AI Can Act',
  description:
    'Run EMILIA Authority Brain locally to map declared AI-agent actions and blind spots, decide which consequences need authority, and generate a reviewed MCP protection scaffold.',
  alternates: { canonical: '/authority-brain' },
  keywords: [
    'AI agent authority map',
    'AI agent security scanner',
    'MCP security scanner',
    'human approval for AI agents',
    'AI agent consequence firewall',
    'local AI governance tool',
  ],
  openGraph: {
    images: ['/opengraph-image'],
    title: 'Your AI can act. Map both sides first.',
    description:
      'Map declared actions, blind spots, and expected evidence. Decide what needs authority, then put customer-owned Gate in force at a completely mediated executor.',
    url: 'https://www.emiliaprotocol.ai/authority-brain',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    images: ['/twitter-image'],
    title: 'EMILIA Authority Brain',
    description: 'Map what an agent declares it can reach, decide what it may do, and define where authenticated evidence should return.',
  },
};

export default function AuthorityBrainPage(): React.ReactElement {
  return <AuthorityBrainExperience />;
}
