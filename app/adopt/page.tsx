// SPDX-License-Identifier: Apache-2.0
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import AdoptExperience from './AdoptExperience';

export default function AdoptPage() {
  return (
    <>
      <SiteNav activePage="adopt" />
      <AdoptExperience />
      <SiteFooter />
    </>
  );
}
