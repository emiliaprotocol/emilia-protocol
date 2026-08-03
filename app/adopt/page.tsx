// SPDX-License-Identifier: Apache-2.0
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { getAgentRecordRuntimeReadiness } from '@/lib/agent-record/runtime-readiness';
import AdoptExperience from './AdoptExperience';

export default async function AdoptPage() {
  const agentRecordReadiness = await getAgentRecordRuntimeReadiness();
  return (
    <>
      <SiteNav activePage="adopt" />
      <AdoptExperience agentRecordReady={agentRecordReadiness.ready} />
      <SiteFooter />
    </>
  );
}
