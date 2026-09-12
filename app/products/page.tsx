// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { ProductStoryHub } from '@/components/product-story/ProductStory';
import { WorkforceEntry } from '@/components/workforce/WorkforceStory';

export const metadata: Metadata = {
  title: 'EMILIA Workforce, Gate and the Open Protocol',
  description:
    'Manage AI work through EMILIA’s workforce workspace. Explore Gate, the open Protocol and the supporting tools for mapping, approval and evidence review.',
  alternates: { canonical: '/products' },
};

export default function ProductsPage(): React.ReactElement {
  return (
    <div>
      <SiteNav activePage="products" />
      <main>
        <WorkforceEntry />
        <ProductStoryHub />
      </main>
      <SiteFooter />
    </div>
  );
}
