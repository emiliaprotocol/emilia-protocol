// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import AuthorityBrainExperience from '@/components/authority-brain/AuthorityBrainExperience';

export const metadata: Metadata = {
  title: 'Authority Brain — Map and Protect AI Agent Actions',
  description:
    'Run EMILIA Authority Brain locally to discover visible AI-agent action surfaces, review proposed authority requirements and blind spots, and generate a reviewed MCP protection scaffold.',
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
    title: 'See where your AI can act',
    description:
      'Discover visible action surfaces, review the Authority Map, and put a human in control before a consequential machine action.',
    url: 'https://www.emiliaprotocol.ai/authority-brain',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'EMILIA Authority Brain',
    description: 'See where your AI can act. Put a human in control before it matters.',
  },
};

export default function AuthorityBrainPage(): React.ReactElement {
  return <AuthorityBrainExperience />;
}
