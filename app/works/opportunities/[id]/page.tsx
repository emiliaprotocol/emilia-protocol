// SPDX-License-Identifier: Apache-2.0
//
// /works/opportunities/[id] — one opportunity with its claim-status
// statements and the submissions builders have made against it.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { getWorksRecord, listWorksRecords } from '@/lib/works/store';
import type {
  BuilderRecord,
  ListingRecord,
  OpportunityRecord,
  SubmissionRecord,
} from '@/lib/works/model';
import { ClaimCard, ExampleTag, SectionTitle, WorksDisciplineNote } from '../../ui';
import SubmissionForm from '../../SubmissionForm';

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
  if (!oppRes.ok) notFound();
  const opportunity = oppRes.record as OpportunityRecord;

  const [subsRes, buildersRes, listingsRes] = await Promise.all([
    listWorksRecords('submissions'),
    listWorksRecords('builders'),
    listWorksRecords('listings'),
  ]);
  const submissions = ((subsRes.ok ? subsRes.records : []) as VisibleSubmissionRecord[])
    .filter((sub) => sub.opportunity_id === opportunity.opportunity_id)
    .filter((sub) => sub.visibility === 'public' || sub.example === true);
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
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>
            <Link href="/works/opportunities" style={{ color: color.t3, textDecoration: 'none' }}>
              Opportunities
            </Link>
            {` / ${opportunity.kind.replace(/_/g, ' ')}`}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h1 style={{ ...styles.h1, marginBottom: 0, maxWidth: 820 }}>{opportunity.title}</h1>
            {opportunity.example ? <ExampleTag /> : null}
          </div>
          <div style={{ fontSize: 14, color: color.t3, margin: '16px 0 0' }}>
            Posted by {opportunity.posted_by} ·{' '}
            <a href={opportunity.contact_route} style={{ color: color.t1 }}>
              {opportunity.contact_route.replace(/^mailto:/, '')}
            </a>
          </div>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          <p style={{ ...styles.body, maxWidth: 820 }}>{opportunity.description}</p>

          {opportunity.claims.length > 0 ? (
            <>
              <SectionTitle>Funding, authority, and eligibility</SectionTitle>
              <div style={{ display: 'grid', gap: 16, marginBottom: 48 }}>
                {opportunity.claims.map((claim, index) => <ClaimCard key={index} claim={claim} />)}
              </div>
            </>
          ) : null}

          <SectionTitle>Respond</SectionTitle>
          {opportunity.example ? (
            <div style={{ ...styles.card, marginBottom: 48 }}>
              <p style={{ ...styles.body, margin: '0 0 16px' }}>
                This is a read-only example opportunity. It demonstrates claim status and response
                structure, but it does not accept submissions.
              </p>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <Link href="/works/opportunities" style={cta.secondary} className="ep-cta-secondary">
                  Browse live opportunities
                </Link>
                <Link href="/works/opportunities/new" style={cta.primary} className="ep-cta">
                  Post a live opportunity
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

          <SectionTitle>Public submissions</SectionTitle>
          <div style={{ display: 'grid', gap: 16 }}>
            {submissions.map((sub) => {
              const builder = builderById.get(sub.builder_id);
              const listing = sub.listing_id ? listingById.get(sub.listing_id) : null;
              return (
                <div key={sub.submission_id} style={{
                  background: color.card, border: `1px solid ${color.border}`,
                  borderRadius: radius.base, padding: '20px 24px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                      {builder ? (
                        <Link href={`/works/builders/${builder.builder_id}`} style={{
                          fontWeight: 700, fontSize: 15, color: color.t1, textDecoration: 'none',
                        }}>
                          {builder.name}
                        </Link>
                      ) : (
                        <span style={{ fontWeight: 700, fontSize: 15, color: color.t1 }}>{sub.builder_id}</span>
                      )}
                      {sub.example ? <ExampleTag /> : null}
                    </div>
                    {listing ? (
                      <Link href={`/works/listings/${listing.listing_id}`} style={{
                        fontFamily: font.mono, fontSize: 12, color: color.t3, textDecoration: 'none',
                      }}>
                        with {listing.name}
                      </Link>
                    ) : null}
                  </div>
                  <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: 0 }}>
                    {sub.proposal}
                  </p>
                  {sub.team && sub.team.length > 0 ? (
                    <div style={{ fontSize: 13, color: color.t3, marginTop: 10 }}>
                      Team: {sub.team.join(', ')}
                    </div>
                  ) : null}
                </div>
              );
            })}
            {submissions.length === 0 ? (
              <div style={{ fontSize: 14, color: color.t3 }}>No public submissions yet.</div>
            ) : null}
          </div>

          <WorksDisciplineNote />
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
