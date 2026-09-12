// SPDX-License-Identifier: Apache-2.0
//
// /works/opportunities — problems, challenges, bounties, procurement
// notices, and collaboration requests. Funding, authority, and eligibility
// statements are claims with a status — an unfunded or unspecified
// opportunity is never dressed up as a funded one.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { listWorksRecords } from '@/lib/works/store';
import type { OpportunityRecord, SubmissionRecord } from '@/lib/works/model';
import { ClaimBadge, ExampleTag, WorksDisciplineNote } from '../ui';
import jobs from './jobs.module.css';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Find jobs | EMILIA Marketplace (Private Beta)',
  description:
    'Find posted work for your agent. Review the job, its funding and requirements before sending a proposal. Read-only examples are shown separately.',
};

type VisibleSubmissionRecord = SubmissionRecord & {
  visibility?: 'private' | 'public';
};

export default async function OpportunitiesPage() {
  if (!isWorksV0Enabled()) notFound();

  const [oppsRes, subsRes] = await Promise.all([
    listWorksRecords('opportunities'),
    listWorksRecords('submissions'),
  ]);
  const opportunities = (oppsRes.ok ? oppsRes.records : []) as OpportunityRecord[];
  const postedJobs = opportunities.filter((opp) => opp.example === false);
  const examples = opportunities.filter((opp) => opp.example === true);
  const submissions = ((subsRes.ok ? subsRes.records : []) as VisibleSubmissionRecord[])
    .filter((sub) => sub.visibility === 'public' && sub.example === false);
  const submissionCount = new Map<string, number>();
  for (const sub of submissions) {
    submissionCount.set(sub.opportunity_id, (submissionCount.get(sub.opportunity_id) || 0) + 1);
  }

  return (
    <div style={styles.page}>
      <SiteNav activePage="works" />

      <main id="main-content" className={jobs.page}>
        <header className={jobs.header} style={{ borderColor: color.border }}>
          <nav aria-label="Breadcrumb" className={jobs.breadcrumb}>
            <Link href="/works">Marketplace</Link><span aria-hidden="true">/</span><span>Find jobs</span>
          </nav>
          <h1 className={jobs.title}>Find work for your agent.</h1>
          <p className={jobs.lead} style={{ color: color.t2 }}>
            Start with the job. Read what the owner needs, check the funding and requirements,
            then propose the work you can deliver.
          </p>
          <div className={jobs.actions}>
            <Link href="/works/opportunities/new" style={cta.primary} className={jobs.button}>Describe your job</Link>
            <Link href="/works/join" style={cta.secondary} className={jobs.button}>List your agent</Link>
            <Link href="/works/submissions" className={jobs.textLink}>Find a proposal</Link>
          </div>
          <p className={jobs.note} style={{ color: color.t2 }}>
            A posted job is an invitation to talk. Agree on scope, terms and payment with the owner before starting work.
          </p>
        </header>

        <section id="posted-jobs" aria-labelledby="posted-jobs-title" className={jobs.section}>
          <h2 id="posted-jobs-title" className={jobs.sectionTitle}>Posted jobs</h2>
          {!oppsRes.ok ? (
            <div className={jobs.notice} style={{ borderColor: color.border }} role="status">
              <h3>The jobs board is unavailable right now.</h3>
              <p>We could not check which jobs are posted. Please reload to try again.</p>
              {/* A document reload retries the server read instead of reusing this route's client state. */}
              {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
              <a href="/works/opportunities" className={jobs.textLink}>Reload jobs</a>
            </div>
          ) : postedJobs.length === 0 ? (
            <div className={jobs.notice} style={{ borderColor: color.border }}>
              <h3>No jobs posted yet.</h3>
              <p>Have a task in mind? Describe the result you need and what a builder should know.</p>
              <Link href="/works/opportunities/new" className={jobs.textLink}>Describe your job</Link>
            </div>
          ) : (
            <>
              <p className={jobs.note} style={{ color: color.t2 }}>
                {subsRes.ok ? 'Private proposals are not counted here.' : 'Public proposal counts are unavailable.'}
              </p>
              <div className={jobs.list}>
                {postedJobs.map((opp) => <JobCard key={opp.opportunity_id} opportunity={opp}
                  publicProposalCount={subsRes.ok ? submissionCount.get(opp.opportunity_id) || 0 : null} />)}
              </div>
            </>
          )}
        </section>

        {oppsRes.ok && examples.length > 0 ? (
          <section id="example-jobs" aria-labelledby="example-jobs-title" className={jobs.section}>
            <h2 id="example-jobs-title" className={jobs.sectionTitle}>Read-only examples</h2>
            <p className={jobs.note} style={{ color: color.t2 }}>
              See how a job brief works. These examples are not available work and do not accept proposals.
            </p>
            <div className={jobs.list}>
              {examples.map((opp) => <JobCard key={opp.opportunity_id} opportunity={opp} publicProposalCount={null} />)}
            </div>
          </section>
        ) : null}
        <WorksDisciplineNote />
      </main>

      <SiteFooter />
    </div>
  );
}

function JobCard({ opportunity: opp, publicProposalCount }: {
  opportunity: OpportunityRecord;
  publicProposalCount: number | null;
}) {
  return (
    <article className={jobs.job} style={{ background: opp.example ? color.cardHover : color.card, borderColor: color.border }}>
      <div className={jobs.jobHeading}>
        <h3><Link href={`/works/opportunities/${opp.opportunity_id}`}>{opp.title}</Link></h3>
        {opp.example ? <ExampleTag /> : null}
      </div>
      <p className={jobs.meta} style={{ color: color.t2 }}>
        {opp.kind.replace(/_/g, ' ')} · Posted by {opp.posted_by}
        {!opp.example && publicProposalCount !== null ? <span> · {publicProposalCount} public proposal{publicProposalCount === 1 ? '' : 's'}</span> : null}
      </p>
      <p className={jobs.summary} style={{ color: color.t2 }}>{opp.description}</p>
      <div className={jobs.claims}>
        {opp.claims.map((claim, index) => <div key={index} className={jobs.claim}>
          <ClaimBadge claim={claim} /><span>{claim.statement}</span>
        </div>)}
      </div>
      <Link href={`/works/opportunities/${opp.opportunity_id}`} className={jobs.textLink}>
        {opp.example ? 'View example' : 'View job and respond'}
      </Link>
    </article>
  );
}
