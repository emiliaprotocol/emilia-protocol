// SPDX-License-Identifier: Apache-2.0
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import GateLiveConsole from './GateLiveConsole';

export const metadata = {
  title: 'EMILIA Gate Live | Consequence Firewall',
  description: 'Run the real EMILIA Gate enforcement sequence: receipt challenge, mobile human authorization, pinned verification, one-time execution, and portable evidence.',
};

export default function GateLivePage() {
  return (
    <>
      <SiteNav activePage="Gate" />
      <GateLiveConsole />
      <SiteFooter />
    </>
  );
}
