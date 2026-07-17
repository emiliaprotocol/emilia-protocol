// SPDX-License-Identifier: Apache-2.0
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import GateControlPlane from './GateControlPlane';

export const metadata = {
  title: 'EMILIA Gate Control Plane | Enforcement, Witness, Settlement',
  description: 'Run the reference three-plane proof: executor enforcement, independent network observation, coverage, metering, and fail-closed settlement eligibility.',
};

export default function GateControlPlanePage() {
  return (
    <>
      <SiteNav activePage="Gate" />
      <GateControlPlane />
      <SiteFooter />
    </>
  );
}
