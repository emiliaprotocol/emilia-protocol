// SPDX-License-Identifier: Apache-2.0
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { runActionEscrowScenario } from '@/examples/action-escrow/scenario.mjs';
import ActionEscrowExperience from './ActionEscrowExperience';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Action Escrow Contractor Demo',
  description:
    'A kitchen-renovation milestone demo with separate document verification, exact homeowner and contractor release approvals, simulated external custody, one-time Gate release, and portable evidence.',
};

export default async function ActionEscrowPage() {
  const scenario = await runActionEscrowScenario();

  return (
    <>
      <SiteNav activePage="Action Escrow" />
      <ActionEscrowExperience data={scenario.view} />
      <SiteFooter />
    </>
  );
}
