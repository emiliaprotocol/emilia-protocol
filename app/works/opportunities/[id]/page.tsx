// SPDX-License-Identifier: Apache-2.0
//
// /works/opportunities/[id] — one opportunity with its claim-status
// statements and the submissions builders have made against it.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { getWorksRecord, listWorksRecords } from '@/lib/works/store';
import type {
  BuilderRecord,
  ListingRecord,
  OpportunityRecord,
  SubmissionRecord,
} from '@/lib/works/model';
import { ClaimCard, ExampleTag, SectionTitle, WorksDisciplineNote } from '../../ui';

export const dynamic = 'force-dynamic';

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
  const submissions = ((subsRes.ok ? subsRes.records : []) as SubmissionRecord[])
    .filter((sub) => sub.opportunity_id === opportunity.opportunity_id);
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

          <SectionTitle>Submissions</SectionTitle>
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
              <div style={{ fontSize: 14, color: color.t3 }}>No submissions yet.</div>
            ) : null}
          </div>

          <div style={{
            marginTop: 32, padding: '16px 20px', background: '#F5F5F4',
            border: `1px solid ${color.border}`, borderRadius: radius.base,
            fontSize: 13, color: color.t2, lineHeight: 1.7,
          }}>
            Builders respond through the authenticated API:{' '}
            <span style={{ fontFamily: font.mono, fontSize: 12 }}>
              POST /api/works/submissions
            </span>{' '}
            with a Cloud API key, referencing this opportunity id.
          </div>

          <WorksDisciplineNote />
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
