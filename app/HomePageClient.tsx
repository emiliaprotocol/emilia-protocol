import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { WorkforceIntroduction, WorkforceHandover, WorkforceResponsibilities, WorkforceFoundation, WorkforceNextStep } from '@/components/workforce/WorkforceStory';
import workforce from '@/components/workforce/workforce.module.css';
import proofStats from '@/lib/proof-stats.json';

export default function HomePage(): React.ReactElement {
  return (
    <div>
      <SiteNav activePage="" />
      <main>
        <WorkforceIntroduction />
        <WorkforceHandover />
        <WorkforceResponsibilities />
        <WorkforceFoundation />
        <section className={workforce.section + ' ' + workforce.tinted} aria-labelledby="evidence-title">
          <div className={workforce.container}>
            <p className={workforce.eyebrow}>Built on open engineering</p>
            <h2 id="evidence-title">Inspect the foundation.<br />Evaluate the product for your job.</h2>
            <p className={workforce.lead}>The public repository records {Number(proofStats.tests.total).toLocaleString('en-US')} automated tests, {proofStats.conformance.vectors} conformance vectors and {proofStats.securityCase.claims} executable security claims. Those are engineering results, not customer adoption or proof of a complete deployment.</p>
            <p className={workforce.lead}>The workforce workspace is a separate private local alpha using synthetic refunds. Production needs authenticated identities, a credential-owning executor, durable state and tested recovery. No customer savings or ROI are claimed.</p>
            <div className={workforce.actions}>
              <Link href="/workforce" className={workforce.primary}>Explore the workforce alpha</Link>
              <Link href="/proof" className={workforce.secondary}>Inspect the proof</Link>
              <Link href="/products" className={workforce.secondary}>See the supporting tools</Link>
            </div>
          </div>
        </section>
        <WorkforceNextStep />
      </main>
      <SiteFooter />
    </div>
  );
}
