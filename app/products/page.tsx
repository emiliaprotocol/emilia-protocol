// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { ProductStoryHub } from '@/components/product-story/ProductStory';

export const metadata: Metadata = {
  title: 'EMILIA Product System: One Authority Story for Consequential AI Actions',
  description:
    'See how Authority Brain, EMILIA Gate, Approver, the open Protocol, and the Assurance Plane work as one system from discovery through independent re-performance.',
  alternates: { canonical: '/products' },
};

export default function ProductsPage(): React.ReactElement {
  return (
    <div>
      <SiteNav activePage="products" />
      <main>
        <ProductStoryHub />
      </main>
      <SiteFooter />
    </div>
  );
}
