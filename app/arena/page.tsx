// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import ArenaExperience from './ArenaExperience';

export const metadata: Metadata = {
  title: 'EMILIA Arena — Give Your Agent an Allowance',
  description: 'Run a synthetic AI-agent allowance challenge. Watch EMILIA Gate permit in-bounds actions, refuse out-of-bounds actions, and issue a shareable signed refusal.',
  alternates: { canonical: '/arena' },
  openGraph: {
    images: ['/opengraph-image'],
    title: 'Give your agent an allowance, not your account.',
    description: 'A public, synthetic challenge for bounded AI-agent authority. No money or production credentials are connected.',
    url: '/arena',
  },
};

export default function ArenaPage() {
  return (
    <>
      <SiteNav activePage="Arena" />
      <ArenaExperience />
      <SiteFooter />
    </>
  );
}
