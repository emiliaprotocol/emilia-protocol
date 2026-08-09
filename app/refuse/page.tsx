// SPDX-License-Identifier: Apache-2.0
//
// /refuse — Watch It Refuse: a public demo of the authorization decision
// layer. The visitor types a consequential agent action; the page runs the
// real EMILIA evaluation and shows the refusal (or, via an explicit demo
// ceremony, the full receipt lifecycle). No action is ever executed.
//
// Entirely absent (404) unless WATCH_IT_REFUSE=1.

import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { isWatchItRefuseEnabled } from '@/lib/env';
import WatchItRefuseExperience from './WatchItRefuseExperience';

export const dynamic = 'force-dynamic';

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

function firstParam(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

export async function generateMetadata(
  { searchParams }: { searchParams: SearchParams },
): Promise<Metadata> {
  const params = await searchParams;
  const shared = (firstParam(params.q) || '').replace(/\s+/g, ' ').trim().slice(0, 140);
  const title = 'Watch It Refuse | EMILIA Protocol';
  const description = shared
    ? `An agent was told to "${shared}". Run the live no-evidence authorization evaluation and inspect its typed refusal. No action is performed.`
    : 'Type any consequential agent action and watch the live no-evidence authorization evaluation refuse it. No action is performed.';
  const og = new URLSearchParams();
  if (shared) og.set('t', shared);
  return {
    title,
    description,
    alternates: { canonical: '/refuse' },
    openGraph: {
      title: shared
        ? `"${shared}": REFUSAL DEMO`
        : 'Watch It Refuse',
      description,
      url: '/refuse',
      images: [{ url: `/api/refuse/og?${og.toString()}`, width: 1200, height: 630 }],
    },
    twitter: { card: 'summary_large_image' },
  };
}

export default function RefusePage() {
  if (!isWatchItRefuseEnabled()) notFound();
  return (
    <>
      <SiteNav />
      <WatchItRefuseExperience />
      <SiteFooter />
    </>
  );
}
