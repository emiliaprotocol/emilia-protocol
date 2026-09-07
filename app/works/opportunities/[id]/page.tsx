// SPDX-License-Identifier: Apache-2.0
//
// /works/opportunities/[id] — one opportunity with its claim-status
// statements and the submissions builders have made against it.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { getWorksRecord, listWorksRecords } from '@/lib/works/store';
import type {
  BuilderRecord,
  ListingRecord,
  OpportunityRecord,
  SubmissionRecord,
} from '@/lib/works/model';
import { ClaimCard, ExampleTag, WorksDisciplineNote } from '../../ui';
import SubmissionForm from '../../SubmissionForm';
import jobs from '../jobs.module.css';

export const dynamic = 'force-dynamic';

type VisibleSubmissionRecord = SubmissionRecord & {
  visibility?: 'private' | 'public';
};

export default async function OpportunityPage({ params }: {
  params: Promise<{ id: string }>;
}) {
  if (!isWorksV0Enabled()) notFound();
  const { id } = await params;
  const oppRes = await getWorksRecord('opportunities', id);
  if (!oppRes.ok) {
    if (oppRes.code !== 'store_unavailable') notFound();
    return <div style={styles.page}>
      <SiteNav activePage="works" />
      <main id="main-content" className={jobs.page}>
        <header className={jobs.header} style={{ borderColor: color.border }}>
          <h1 className={jobs.title}>This job could not be loaded right now.</h1>
          <p className={jobs.lead}>We could not check the job record. Please reload to try again.</p>
          <div className={jobs.actions}>
            <a href={`/works/opportunities/${encodeURIComponent(id)}`} className={jobs.textLink}>Reload job</a>
            <Link href="/works/opportunities" className={jobs.textLink}>Back to jobs</Link>
          </div>
        </header>
      </main>
      <SiteFooter />
    </div>;
  }
  const opportunity = oppRes.record as OpportunityRecord;

  const [subsRes, buildersRes, listingsRes] = await Promise.all([
    listWorksRecords('submissions'),
    listWorksRecords('builders'),
    listWorksRecords('listings'),
  ]);
  const submissions = ((subsRes.ok ? subsRes.records : []) as VisibleSubmissionRecord[])
    .filter((sub) => sub.opportunity_id === opportunity.opportunity_id)
    .filter((sub) => opportunity.example
      ? sub.example === true
      : sub.visibility === 'public' && sub.example === false);
  const builderById = new Map(
    ((buildersRes.ok ? buildersRes.records : []) as BuilderRecord[])
      .map((b) => [b.builder_id, b]),
  );
  const listingById = new Map(
    ((listingsRes.ok ? listingsRes.records : []) as ListingRecord[])
      .map((l) => [l.listing_id, l]),
  );

  return (
    <div style={styles.page}>
      <SiteNav activePage="works" />

      <main id="main-content" className={jobs.page}>
        <header className={jobs.header} style={{ borderColor: color.border }}>
          <nav aria-label="Breadcrumb" className={jobs.breadcrumb}>
            <Link href="/works/opportunities">Find jobs</Link>
            <span aria-hidden="true">/</span><span>{opportunity.kind.replace(/_/g, ' ')}</span>
          </nav>
          <div className={jobs.jobHeading}>
            <h1 className={jobs.title} style={{ marginBottom: 0 }}>{opportunity.title}</h1>
            {opportunity.example ? <ExampleTag /> : null}
          </div>
          <div className={jobs.owner} style={{ color: color.t2 }}>
            <span>Posted by {opportunity.posted_by}</span>
            <a href={opportunity.contact_route}>
              {opportunity.contact_route.replace(/^mailto:/, '')}
            </a>
          </div>
        </header>

        <section className={jobs.section} aria-labelledby="job-brief-title">
          <h2 id="job-brief-title" className={jobs.sectionTitle}>The job</h2>
          <p className={jobs.brief} style={{ color: color.t2 }}>{opportunity.description}</p>

          {opportunity.claims.length > 0 ? (
            <>
              <h2 className={jobs.sectionTitle}>Funding and requirements</h2>
              <p className={jobs.note} style={{ color: color.t2 }}>
                Check who stands behind each statement and what it covers. A posted budget is not a payment held by EMILIA.
              </p>
              <div style={{ display: 'grid', gap: 16, marginBottom: 48 }}>
                {opportunity.claims.map((claim, index) => <ClaimCard key={index} claim={claim} />)}
              </div>
            </>
          ) : null}

          {!opportunity.example ? <div className={jobs.inbox} style={{ borderColor: color.border }}>
            <p>Did you post this job? Read proposals with the same API key you used to post it.</p>
            <Link href={`/works/opportunities/${opportunity.opportunity_id}/inbox`} className={jobs.button} style={cta.secondary} prefetch={false}>Open your private proposal inbox</Link>
          </div> : null}
          <h2 className={jobs.sectionTitle}>{opportunity.example ? 'About this example' : 'Send a proposal'}</h2>
          {opportunity.example ? (
            <div className={jobs.notice} style={{ borderColor: color.border }}>
              <p>
                This is a read-only example opportunity. It shows how a job and its proposals are presented.
                It is not available work and does not accept proposals.
              </p>
              <div className={jobs.actions}>
                <Link href="/works/opportunities" style={cta.secondary} className={jobs.button}>
                  Browse posted jobs
                </Link>
                <Link href="/works/opportunities/new" style={cta.primary} className={jobs.button}>
                  Describe your job
                </Link>
              </div>
            </div>
          ) : (
            <SubmissionForm
              opportunityId={opportunity.opportunity_id}
              sponsorName={opportunity.posted_by}
              sponsorContactRoute={opportunity.contact_route}
            />
          )}

        </section>

        <section className={jobs.responses} aria-labelledby="job-proposals-title">
          <h2 id="job-proposals-title" className={jobs.sectionTitle}>{opportunity.example ? 'Example proposals' : 'Public proposals'}</h2>
          {!opportunity.example ? <p className={jobs.note} style={{ color: color.t2 }}>Private proposals do not appear on this page.</p> : null}
          {!subsRes.ok ? (
            <div className={jobs.notice} style={{ borderColor: color.border }} role="status">
              <h3>{opportunity.example ? 'Example proposals are unavailable right now.' : 'Public proposals are unavailable right now.'}</h3>
              <p>The job brief is still available. Please reload to check its proposals.</p>
              <a href={`/works/opportunities/${opportunity.opportunity_id}`} className={jobs.textLink}>Reload proposals</a>
            </div>
          ) : <>
            {submissions.length > 0 && (!buildersRes.ok || !listingsRes.ok) ? (
              <p className={jobs.note} style={{ color: color.t2 }} role="status">
                Some builder or agent details could not be loaded. The proposal text and recorded IDs are shown below.
              </p>
            ) : null}
          <div className={jobs.list}>
            {submissions.map((sub) => {
              const builder = builderById.get(sub.builder_id);
              const listing = sub.listing_id ? listingById.get(sub.listing_id) : null;
              return (
                <article key={sub.submission_id} className={jobs.proposal} style={{ background: color.card, borderColor: color.border }}>
                  <div className={jobs.proposalHeader}>
                    <div>
                      {builder ? (
                        <Link href={`/works/builders/${builder.builder_id}`}>
                          {builder.name}
                        </Link>
                      ) : (
                        <span>{sub.builder_id}</span>
                      )}
                      {sub.example ? <ExampleTag /> : null}
                    </div>
                    {listing ? (
                      <Link href={`/works/listings/${listing.listing_id}`}>
                        with {listing.name}
                      </Link>
                    ) : sub.listing_id ? <span>Agent ID: {sub.listing_id}</span> : null}
                  </div>
                  <p style={{ color: color.t2 }}>
                    {sub.proposal}
                  </p>
                  {sub.team && sub.team.length > 0 ? (
                    <div className={jobs.team} style={{ color: color.t2 }}>
                      Team: {sub.team.join(', ')}
                    </div>
                  ) : null}
                </article>
              );
            })}
            {submissions.length === 0 ? (
              <p className={jobs.note} style={{ color: color.t2 }}>{opportunity.example ? 'No example proposals recorded.' : 'No public proposals yet.'}</p>
            ) : null}
          </div>
          </>}
        </section>
        <WorksDisciplineNote />
      </main>

      <SiteFooter />
    </div>
  );
}
