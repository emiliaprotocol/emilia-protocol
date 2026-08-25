// SPDX-License-Identifier: Apache-2.0
// Metadata for /pilot (page itself is a client component).

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Request a Protected-Workflow Pilot — One Workflow, 90 Days',
  description:
    'Scope one protected workflow for one fixed 90-day, $25K pilot: synthetic and read-only validation first, then production only through a buyer-approved Gate boundary.',
  alternates: { canonical: '/pilot' },
};

export default function PilotLayout({ children }: { children: React.ReactNode }) {
  return children;
}
