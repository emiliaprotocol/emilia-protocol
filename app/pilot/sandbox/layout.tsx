// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Run an Observe-Mode Pilot Yourself — EMILIA Protocol',
  description:
    'Provision a scoped key, send your high-risk agent/operator actions through the gate in observe mode, and get the automated report of what would have required a named human approval. No sales call, nothing blocked.',
  alternates: { canonical: '/pilot/sandbox' },
};

export default function SandboxLayout({ children }: { children: React.ReactNode }) {
  return children;
}
