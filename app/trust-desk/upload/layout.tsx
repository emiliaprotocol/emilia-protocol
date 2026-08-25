// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
  title: { absolute: 'AI Trust Desk Intake' },
  description: 'Secure intake for an already scoped AI Trust Desk engagement.',
  alternates: { canonical: '/trust-desk/upload' },
  robots: { index: false, follow: false },
};

export default function TrustDeskUploadLayout({ children }: { children: ReactNode }) {
  return children;
}
