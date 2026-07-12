import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import snapshot from '@/lib/standards-observatory.snapshot.json';
import ObservatoryClient from './ObservatoryClient';
import './observatory.css';

export const metadata = {
  title: 'Standards Observatory',
  description: 'A revision-aware, source-locked map of authorization, identity, evidence, and agent-protocol standards.',
  alternates: { canonical: '/observatory' },
  openGraph: {
    title: 'EMILIA Standards Observatory',
    description: 'See what the standards actually say, what is moving, and which interoperability layers remain open.',
    url: '/observatory',
  },
};

export default function ObservatoryPage() {
  return (
    <>
      <SiteNav activePage="Observatory" />
      <ObservatoryClient snapshot={snapshot} />
      <SiteFooter />
    </>
  );
}
