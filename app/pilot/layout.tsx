// SPDX-License-Identifier: Apache-2.0
// Metadata for /pilot (page itself is a client component).

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Request a Managed Gate Pilot — One Workflow, 60 Days — EMILIA Protocol',
  description:
    'Scope one consequential workflow for a fixed 60-day engagement: observe first, configure the evidence and approval policy, then enforce only after customer approval.',
  alternates: { canonical: '/pilot' },
};

export default function PilotLayout({ children }: { children: React.ReactNode }) {
  return children;
}
