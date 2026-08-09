// SPDX-License-Identifier: Apache-2.0
//
// /works/listings/[id] — one listing: repository and service URLs, license,
// supported tasks, interfaces, operating constraints, status, capability
// cards, and the listing's activity records.

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

export default async function ListingPage({ params }: {
  params: Promise<{ id: string }>;
}) {
  if (!isWorksV0Enabled()) notFound();
  const { id } = await params;
  const listingRes = await getWorksRecord('listings', id);
  if (!listingRes.ok) notFound();
  const listing = listingRes.record as ListingRecord;

  const [builderRes, cardsRes, activityRes] = await Promise.all([
    getWorksRecord('builders', listing.builder_id),
    listWorksRecords('cards'),
    listWorksRecords('activity'),
  ]);
  const builder = builderRes.ok ? (builderRes.record as BuilderRecord) : null;
  const cards = ((cardsRes.ok ? cardsRes.records : []) as CapabilityCardRecord[])
    .filter((c) => c.listing_id === listing.listing_id);
  const activity = ((activityRes.ok ? activityRes.records : []) as ActivityRecord[])
    .filter((a) => a.listing_id === listing.listing_id)
    .sort((a, b) => String(b.occurred_at).localeCompare(String(a.occurred_at)));

  return (
    <div style={styles.page}>
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>
            <Link href="/works" style={{ color: color.t3, textDecoration: 'none' }}>Marketplace</Link>
            {' / Listing'}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h1 style={{ ...styles.h1, marginBottom: 0 }}>{listing.name}</h1>
            {listing.example ? <ExampleTag /> : null}
          </div>
          {builder ? (
            <div style={{ margin: '12px 0 16px' }}>
              <Link href={`/works/builders/${builder.builder_id}`} style={{ fontSize: 14, color: color.t3, textDecoration: 'none' }}>
                by {builder.name}
              </Link>
            </div>
          ) : null}
          <p style={{ ...styles.body, maxWidth: 720, marginBottom: 20 }}>{listing.summary}</p>

          <dl style={{ margin: 0, display: 'grid', gap: 10, maxWidth: 820 }}>
            <FactRow label="Kind" value={listing.kind} />
            <FactRow label="Status" value={listing.status} />
            <FactRow label="License" value={listing.license || 'unspecified'} />
            {listing.repository_url ? (
              <FactRow label="Repository" value={listing.repository_url} href={listing.repository_url} />
            ) : null}
            {listing.service_url ? (
              <FactRow label="Service" value={listing.service_url} href={listing.service_url} />
            ) : null}
          </dl>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 20 }}>
            {listing.supported_tasks.map((task) => <Tag key={`t-${task}`}>{task}</Tag>)}
            {listing.interfaces.map((iface) => <Tag key={`i-${iface}`}>{iface}</Tag>)}
          </div>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          {listing.operating_constraints.length > 0 ? (
            <>
              <SectionTitle>Operating constraints</SectionTitle>
              <ul style={{ ...styles.list, marginBottom: 48, maxWidth: 820 }}>
                {listing.operating_constraints.map((constraint) => (
                  <li key={constraint} style={{ fontSize: 14 }}>{constraint}</li>
                ))}
              </ul>
            </>
          ) : null}

          <SectionTitle>Capability cards</SectionTitle>
          <div style={{ display: 'grid', gap: 16, marginBottom: 48 }}>
            {cards.map((card) => <ClaimCard key={card.card_id} claim={card.claim} />)}
            {cards.length === 0 ? (
              <div style={{ fontSize: 14, color: color.t3 }}>No capability cards yet.</div>
            ) : null}
          </div>

          <SectionTitle>Activity</SectionTitle>
          <div>
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

function FactRow({ label, value, href }: { label: string; value: string; href?: string }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 12 }}>
      <dt style={{
        fontFamily: font.mono, fontSize: 11, letterSpacing: 1,
        textTransform: 'uppercase', color: color.t3, paddingTop: 2,
      }}>
        {label}
      </dt>
      <dd style={{ margin: 0, fontSize: 14, color: color.t2, overflowWrap: 'anywhere' }}>
        {href ? (
          <a href={href} style={{ color: color.t1 }} rel="noopener noreferrer">{value}</a>
        ) : value}
      </dd>
    </div>
  );
}
