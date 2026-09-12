// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { WorkforceIntroduction, WorkforceHandover, WorkforceResponsibilities, WorkforceFoundation, WorkforceReadiness, WorkforceNextStep, WorkforceMarketplace } from '@/components/workforce/WorkforceStory';

export const metadata: Metadata = {
  title: 'Build Your AI Workforce | EMILIA',
  description: 'Find specialized agents or bring your own. Give them a job, set their limits and review the work. Explore EMILIA’s private local workforce alpha and open marketplace.',
  alternates: { canonical: '/workforce' },
  openGraph: {
    title: 'Build your AI workforce | EMILIA',
    description: 'The agents can change. The job, its remaining authority and unfinished work stay accounted for. Private local alpha.',
    url: 'https://www.emiliaprotocol.ai/workforce',
    type: 'website',
  },
};

export default function WorkforcePage() {
  return <div><SiteNav activePage="workforce" /><main><WorkforceIntroduction /><WorkforceResponsibilities /><WorkforceMarketplace /><WorkforceHandover /><WorkforceFoundation /><WorkforceReadiness /><WorkforceNextStep /></main><SiteFooter /></div>;
}
