// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { WorkforceIntroduction, WorkforceHandover, WorkforceResponsibilities, WorkforceFoundation, WorkforceReadiness, WorkforceNextStep } from '@/components/workforce/WorkforceStory';

export const metadata: Metadata = {
  title: 'Manage Your AI Workforce | EMILIA',
  description: 'Give every agent a job, set its authority, and know what happened. Explore EMILIA’s private local workforce alpha, built around Gate and the open Protocol.',
  alternates: { canonical: '/workforce' },
  openGraph: {
    title: 'Your AI workforce needs management | EMILIA',
    description: 'The agents can change. The job, its remaining authority and unfinished work stay accounted for. Private local alpha.',
    url: 'https://www.emiliaprotocol.ai/workforce',
    type: 'website',
  },
};

export default function WorkforcePage() {
  return <div><SiteNav activePage="workforce" /><main><WorkforceIntroduction /><WorkforceHandover /><WorkforceResponsibilities /><WorkforceFoundation /><WorkforceReadiness /><WorkforceNextStep /></main><SiteFooter /></div>;
}
