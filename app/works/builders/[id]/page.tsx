// SPDX-License-Identifier: Apache-2.0
//
// /works/builders/[id] — builder profile: the accountable person or legal
// entity behind the work, disclosed affiliations, a contact route, their
// listings, activity feed, and capability cards.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { getWorksRecord, listWorksRecords } from '@/lib/works/store';
import type {
  ActivityRecord,
  BuilderRecord,
  CapabilityCardRecord,
  ListingRecord,
} from '@/lib/works/model';
import { ClaimCard, ExampleTag, SectionTitle, Tag, WorksDisciplineNote } from '../../ui';

export const dynamic = 'force-dynamic';

export default async function BuilderProfile({ params }: {
  params: Promise<{ id: string }>;
}) {
  if (!isWorksV0Enabled()) notFound();
  const { id } = await params;
  const builderRes = await getWorksRecord('builders', id);
  if (!builderRes.ok) notFound();
  const builder = builderRes.record as BuilderRecord;

  const [listingsRes, cardsRes, activityRes] = await Promise.all([
    listWorksRecords('listings'),
    listWorksRecords('cards'),
    listWorksRecords('activity'),
  ]);
  const listings = ((listingsRes.ok ? listingsRes.records : []) as ListingRecord[])
    .filter((l) => l.builder_id === builder.builder_id);
  const cards = ((cardsRes.ok ? cardsRes.records : []) as CapabilityCardRecord[])
    .filter((c) => c.builder_id === builder.builder_id);
  const activity = ((activityRes.ok ? activityRes.records : []) as ActivityRecord[])
    .filter((a) => a.builder_id === builder.builder_id)
    .sort((a, b) => String(b.occurred_at).localeCompare(String(a.occurred_at)));

  return (
    <div style={styles.page}>
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>
            <Link href="/works" style={{ color: color.t3, textDecoration: 'none' }}>Marketplace</Link>
            {' / Builder'}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h1 style={{ ...styles.h1, marginBottom: 0 }}>{builder.name}</h1>
            {builder.example ? <ExampleTag /> : null}
          </div>
          <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, margin: '12px 0 16px' }}>
            {builder.kind === 'legal_entity' ? 'Legal entity' : 'Person'}
          </div>
          {builder.summary ? (
            <p style={{ ...styles.body, maxWidth: 680, marginBottom: 16 }}>{builder.summary}</p>
          ) : null}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
            {builder.affiliations.map((aff) => (
              <Tag key={`${aff.name}-${aff.relation}`}>{`${aff.name} — ${aff.relation}`}</Tag>
            ))}
          </div>
          <div style={{ fontSize: 14, color: color.t2 }}>
            Contact:{' '}
            <a href={builder.contact_route} style={{ color: color.t1 }}>
              {builder.contact_route.replace(/^mailto:/, '')}
            </a>
          </div>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          <SectionTitle>Listings</SectionTitle>
          <div style={{ display: 'grid', gap: 12, marginBottom: 48 }}>
            {listings.map((listing) => (
              <Link key={listing.listing_id} href={`/works/listings/${listing.listing_id}`} style={{
                display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap',
                background: color.card, border: `1px solid ${color.border}`,
                borderRadius: radius.base, padding: '16px 20px', textDecoration: 'none',
              }}>
                <span style={{ fontWeight: 700, color: color.t1, fontSize: 15 }}>{listing.name}</span>
                <span style={{ fontFamily: font.mono, fontSize: 12, color: color.t3 }}>
                  {listing.kind} · {listing.status}
                </span>
              </Link>
            ))}
            {listings.length === 0 ? (
              <div style={{ fontSize: 14, color: color.t3 }}>No listings yet.</div>
            ) : null}
          </div>

          <SectionTitle>Capability cards</SectionTitle>
          <div style={{ display: 'grid', gap: 16, marginBottom: 48 }}>
            {cards.map((card) => <ClaimCard key={card.card_id} claim={card.claim} />)}
            {cards.length === 0 ? (
              <div style={{ fontSize: 14, color: color.t3 }}>No capability cards yet.</div>
            ) : null}
          </div>

          <SectionTitle>Activity</SectionTitle>
          <div style={{ display: 'grid', gap: 0 }}>
            {activity.map((item) => (
              <div key={item.activity_id} style={{
                display: 'grid', gridTemplateColumns: '110px 1fr', gap: 16,
                borderBottom: `1px solid ${color.border}`, padding: '14px 0',
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, paddingTop: 2 }}>
                  {item.occurred_at.slice(0, 10)}
                </div>
                <div>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 1, textTransform: 'uppercase', color: color.gold }}>
                      {item.type.replace(/_/g, ' ')}
                    </span>
                    <a href={item.source_url} style={{ fontSize: 14, color: color.t1, fontWeight: 600 }} rel="noopener noreferrer">
                      {item.title}
                    </a>
                  </div>
                  <div style={{ fontSize: 13, color: color.t3, lineHeight: 1.6, marginTop: 4 }}>
                    {item.scope}
                  </div>
                </div>
              </div>
            ))}
            {activity.length === 0 ? (
              <div style={{ fontSize: 14, color: color.t3 }}>No activity recorded yet.</div>
            ) : null}
          </div>

          <WorksDisciplineNote />
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
