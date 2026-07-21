import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'EMILIA | Investor Overview',
  robots: { index: false, follow: false },
};

export default function InvestorsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
