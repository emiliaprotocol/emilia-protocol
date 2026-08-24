import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Sub-processors — EMILIA Protocol',
  description:
    'Public vendor inventory for the current EMILIA website, repository, and ' +
    'designed commercial components. Not a live customer DPA schedule.',
  alternates: { canonical: '/legal/sub-processors' },
  openGraph: {
    title: 'EMILIA Protocol Sub-processors',
    description: 'Vendor inventory, stated roles, data categories, and current scope.',
    url: 'https://www.emiliaprotocol.ai/legal/sub-processors',
    type: 'article',
  },
};

export default function SubProcessorsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
