// SPDX-License-Identifier: Apache-2.0
// Metadata for /pilot (page itself is a client component).

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Request a Protected-Workflow Pilot — One Workflow, 90 Days — EMILIA Protocol',
  description:
    'Scope one fixed 90-day, $25K nonproduction pilot for a buyer-selected consequence boundary. Any production activation requires a separate Gate Implementation.',
  alternates: { canonical: '/pilot' },
};

export default function PilotLayout({ children }: { children: React.ReactNode }) {
  return children;
}
