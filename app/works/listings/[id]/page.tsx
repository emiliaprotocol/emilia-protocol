// SPDX-License-Identifier: Apache-2.0
//
// /works/listings/[id] — one listing: repository and service URLs, license,
// supported tasks, interfaces, operating constraints, status, capability
// cards, and the listing's activity records.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { getWorksRecord, listWorksRecords } from '@/lib/works/store';
import type {
  ActivityRecord,
  BuilderRecord,
  CapabilityCardRecord,
  ListingRecord,
} from '@/lib/works/model';
import { ClaimCard, ExampleTag, SectionTitle, Tag, WorksDisciplineNote } from '../../ui';
import market from '../../works.module.css';

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
    <div className={market.marketPage}>
      <SiteNav activePage="works" />
      <main>

      <section className={market.marketHero} style={{ borderBottom: `1px solid ${color.border}` }}>
        <div className={market.marketContainer}>
          <div className={market.marketEyebrow}>
            <Link href="/works" style={{ color: color.t3, textDecoration: 'none' }}>Marketplace</Link>
            {' / Listing'}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h1 style={{ marginBottom: 0, overflowWrap: 'anywhere' }}>{listing.name}</h1>
            {listing.example ? <ExampleTag /> : null}
          </div>
          {builder ? (
            <div style={{ margin: '12px 0 16px' }}>
              <Link href={`/works/builders/${builder.builder_id}`} className={market.marketBuilder}>
                by {builder.name}
              </Link>
            </div>
          ) : null}
          <p className={market.marketLead}>{listing.summary}</p>
          {listing.example ? <p className={market.marketNote}><strong>Read-only example.</strong> This shows the listing format. It is not an agent available for hire or a customer deployment.</p> : null}
          {listing.status !== 'active' ? <p className={market.marketNote}>The poster has marked this listing {listing.status}. Confirm its current availability with the builder.</p> : null}
          <p className={market.marketNote}>Listing fields are supplied by the poster. Inspect the work and its evidence before deciding whether it fits your job.</p>

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

          <section className={market.marketDetailActions} aria-labelledby="listing-next-title">
            <h2 id="listing-next-title">Inspect first. Set authority separately.</h2>
            <div className={market.marketActions}>
              <Link href="/works/scan" className={market.marketPrimary}>Start a free scan</Link>
              <Link href="/works/gate" className={market.marketSecondary}>Discuss paid Gate</Link>
              <Link href="/works/qualification" className={market.marketSecondary}>Understand qualification</Link>
            </div>
            <p className={market.marketNote}>A scan maps supported declared actions; it does not run this listing or activate Gate. Qualification is scoped evidence for a candidate and assignment, not permission to act or certification of safety. Gate deployment and commercial terms need a separate agreement.</p>
          </section>
        </div>
      </section>

      <section className={market.marketDetailSection}>
        <div className={market.marketContainer}>
          {listing.operating_constraints.length > 0 ? (
            <>
              <SectionTitle>Operating constraints</SectionTitle>
              <ul style={{ ...styles.list, marginBottom: 48, maxWidth: 820 }}>
                {listing.operating_constraints.map((constraint) => (
                  <li key={constraint} style={{ fontSize: 18 }}>{constraint}</li>
                ))}
              </ul>
            </>
          ) : null}

          <SectionTitle>Capability cards</SectionTitle>
          <p className={market.marketNote}>VERIFIED belongs to the exact statement and its source-backed evidence, not to the agent as a whole. Expired evidence becomes UNKNOWN. Read the scope, source, observation date and limitations together.</p>
          <div style={{ display: 'grid', gap: 16, marginBottom: 48 }}>
            {cards.map((card) => <ClaimCard key={card.card_id} claim={card.claim} />)}
            {cards.length === 0 ? (
              <div className={market.marketNote}>{cardsRes.ok ? 'No capability cards yet.' : 'Capability records could not be loaded. Their evidence status is unknown.'}</div>
            ) : null}
          </div>

          <SectionTitle>Activity</SectionTitle>
          <div>
            {activity.map((item) => (
              <div key={item.activity_id} className={market.marketFactRow} style={{
                borderBottom: `1px solid ${color.border}`, padding: '14px 0',
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 14, color: color.t3, paddingTop: 2 }}>
                  {item.occurred_at.slice(0, 10)}
                </div>
                <div>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: font.mono, fontSize: 13, letterSpacing: 1, textTransform: 'uppercase', color: color.gold }}>
                      {item.type.replace(/_/g, ' ')}
                    </span>
                    <a href={item.source_url} style={{ fontSize: 18, color: color.t1, fontWeight: 600 }} rel="noopener noreferrer">
                      {item.title}
                    </a>
                  </div>
                  <div style={{ fontSize: 16, color: color.t3, lineHeight: 1.6, marginTop: 4 }}>
                    {item.scope}
                  </div>
                </div>
              </div>
            ))}
            {activity.length === 0 ? (
              <div className={market.marketNote}>{activityRes.ok ? 'No activity recorded yet.' : 'Activity records could not be loaded.'}</div>
            ) : null}
          </div>

          <WorksDisciplineNote />
        </div>
      </section>

      </main>
      <SiteFooter />
    </div>
  );
}

function FactRow({ label, value, href }: { label: string; value: string; href?: string }) {
  return (
    <div className={market.marketFactRow}>
      <dt style={{
        fontFamily: font.mono, fontSize: 13, letterSpacing: 1,
        textTransform: 'uppercase', color: color.t3, paddingTop: 2,
      }}>
        {label}
      </dt>
      <dd style={{ margin: 0, fontSize: 17, color: color.t2, overflowWrap: 'anywhere' }}>
        {href ? (
          <a href={href} style={{ color: color.t1 }} rel="noopener noreferrer">{value}</a>
        ) : value}
      </dd>
    </div>
  );
}
