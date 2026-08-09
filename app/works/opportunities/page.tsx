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
import { styles, color, font, radius } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { listWorksRecords } from '@/lib/works/store';
import type { OpportunityRecord, SubmissionRecord } from '@/lib/works/model';
import { ClaimBadge, ExampleTag, WorksDisciplineNote } from '../ui';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Opportunities | EMILIA Marketplace (Private Beta)',
  description:
    'Problems, challenges, bounties, procurement notices, and collaboration requests — with claim-status discipline on every funding and eligibility statement.',
};

export default async function OpportunitiesPage() {
  if (!isWorksV0Enabled()) notFound();

  const [oppsRes, subsRes] = await Promise.all([
    listWorksRecords('opportunities'),
    listWorksRecords('submissions'),
  ]);
  const opportunities = (oppsRes.ok ? oppsRes.records : []) as OpportunityRecord[];
  const submissions = (subsRes.ok ? subsRes.records : []) as SubmissionRecord[];
  const submissionCount = new Map<string, number>();
  for (const sub of submissions) {
    submissionCount.set(sub.opportunity_id, (submissionCount.get(sub.opportunity_id) || 0) + 1);
  }

  return (
    <div style={styles.page}>
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 56 }}>
          <div style={styles.eyebrow}>
            <Link href="/works" style={{ color: color.t3, textDecoration: 'none' }}>Marketplace</Link>
            {' / Opportunities'}
          </div>
          <h1 style={{ ...styles.h1, maxWidth: 760 }}>Opportunities</h1>
          <p style={{ ...styles.body, maxWidth: 680, marginBottom: 0 }}>
            Problems, challenges, bounties, procurement notices, and collaboration requests posted
            by any account. Funding, authority, and eligibility statements carry a claim status —
            check the status before you build.
          </p>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          <div style={{ display: 'grid', gap: 16 }}>
            {opportunities.map((opp) => (
              <div key={opp.opportunity_id} style={{
                background: color.card, border: `1px solid ${color.border}`,
                borderRadius: radius.base, padding: '24px 28px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <Link href={`/works/opportunities/${opp.opportunity_id}`} style={{
                      fontFamily: font.sans, fontSize: 18, fontWeight: 700,
                      color: color.t1, textDecoration: 'none',
                    }}>
                      {opp.title}
                    </Link>
                    {opp.example ? <ExampleTag /> : null}
                  </div>
                  <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3 }}>
                    {opp.kind.replace(/_/g, ' ')} · {submissionCount.get(opp.opportunity_id) || 0} submission{(submissionCount.get(opp.opportunity_id) || 0) === 1 ? '' : 's'}
                  </div>
                </div>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: '12px 0 16px', maxWidth: 820 }}>
                  {opp.description}
                </p>
                <div style={{ display: 'grid', gap: 8 }}>
                  {opp.claims.map((claim, index) => (
                    <div key={index} style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <ClaimBadge claim={claim} />
                      <span style={{ fontSize: 13, color: color.t2, lineHeight: 1.6 }}>{claim.statement}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
            {opportunities.length === 0 ? (
              <div style={{ ...styles.card, color: color.t3, fontSize: 14 }}>
                No opportunities posted yet.
              </div>
            ) : null}
          </div>

          <WorksDisciplineNote />
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
