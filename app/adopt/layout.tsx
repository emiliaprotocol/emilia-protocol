// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Agent Adoption Challenge',
  description:
    'Describe an agent candidate, choose a synthetic job and allowance, add a user-present passkey ceremony, '
    + 'and watch the Arena evaluate an exact no-egress action.',
  alternates: { canonical: '/adopt' },
  openGraph: {
    title: 'Draft an Operating Bond for an agent candidate.',
    description:
      'A no-signup, no-egress candidate challenge with synthetic credits, bounded actions, '
      + 'a user-present passkey ceremony, and explicit publication.',
    url: '/adopt',
    type: 'website',
  },
};

export default function AdoptLayout({ children }: { children: React.ReactNode }) {
  return children;
}
