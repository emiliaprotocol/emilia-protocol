// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';

import CaidPlayground from './CaidPlayground';
import { buildCaidComparison } from './model';
import { BASELINE_CAID_INPUT } from './types';

export const metadata: Metadata = {
  title: 'CAID Playground | One Exact Action, One Portable Identifier',
  description:
    'Compute a canactid URI with the CAID reference implementation. Keep the exact typed action and the identifier stays the same; change a material field and it changes.',
  alternates: { canonical: '/caid' },
  openGraph: {
    title: 'One exact action. One portable identifier.',
    description:
      'Try the CAID reference implementation and see how a change to a payment amount or destination breaks an exact-action match.',
    url: 'https://www.emiliaprotocol.ai/caid',
    type: 'website',
  },
};

export default function CaidPage() {
  return <CaidPlayground initialComparison={buildCaidComparison(BASELINE_CAID_INPUT)} />;
}
