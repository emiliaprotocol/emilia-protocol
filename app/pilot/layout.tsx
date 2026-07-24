// SPDX-License-Identifier: Apache-2.0
// Metadata for /pilot (page itself is a client component).

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Request a Managed Gate Pilot — One Workflow, 60 Days — EMILIA Protocol',
  description:
    'Scope one consequential workflow for a fixed 60-day Amelia I diagnostic: synthetic first, then a governed read-only export, source-linked findings, and a Gate implementation decision.',
  alternates: { canonical: '/pilot' },
};

export default function PilotLayout({ children }: { children: React.ReactNode }) {
  return children;
}
