// SPDX-License-Identifier: Apache-2.0
//
// /works — the EMILIA Marketplace directory: builders list what they are building,
// show the work, and become discoverable. Server-rendered, flag-gated
// (WORKS_V0=1), filterable by task, interface, license, and activity type
// through a plain GET form — no client JS.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import { isWorksV0Enabled } from '@/lib/works/env';
import { listWorksRecords } from '@/lib/works/store';
import type {
  ActivityRecord,
  BuilderRecord,
  CapabilityCardRecord,
  ListingRecord,
} from '@/lib/works/model';
import { ClaimBadge, ExampleTag, Tag, WorksDisciplineNote } from './ui';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'EMILIA Marketplace (Private Beta) — The Verified Market for Autonomous Work',
  description:
    'An open directory of builders, agents, and projects where every material claim carries a status, a scope, a source, and its limitations.',
};

type SearchParams = Record<string, string | string[] | undefined>;

function one(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value)?.trim() || '';
}

function matches(listing: ListingRecord, filters: {
  q: string; task: string; iface: string; license: string;
}): boolean {
  if (filters.task && !listing.supported_tasks.includes(filters.task)) return false;
  if (filters.iface && !listing.interfaces.includes(filters.iface)) return false;
  if (filters.license && (listing.license || '') !== filters.license) return false;
  if (filters.q) {
    const haystack = [
      listing.name, listing.summary, listing.license || '',
      ...listing.supported_tasks, ...listing.interfaces,
    ].join(' ').toLowerCase();
    if (!haystack.includes(filters.q.toLowerCase())) return false;
  }
  return true;
}

export default async function WorksDirectory({ searchParams }: {
  searchParams: Promise<SearchParams>;
}) {
  if (!isWorksV0Enabled()) notFound();
  const params = await searchParams;
  const filters = {
    q: one(params.q),
    task: one(params.task),
    iface: one(params.interface),
    license: one(params.license),
    activity: one(params.activity),
  };

  const [listingsRes, buildersRes, cardsRes, activityRes] = await Promise.all([
    listWorksRecords('listings'),
    listWorksRecords('builders'),
    listWorksRecords('cards'),
    listWorksRecords('activity'),
  ]);
  const listings = (listingsRes.ok ? listingsRes.records : []) as ListingRecord[];
  const builders = (buildersRes.ok ? buildersRes.records : []) as BuilderRecord[];
  const cards = (cardsRes.ok ? cardsRes.records : []) as CapabilityCardRecord[];
  const activity = (activityRes.ok ? activityRes.records : []) as ActivityRecord[];

  const builderById = new Map(builders.map((b) => [b.builder_id, b]));
  const activeByListing = new Map<string, Set<string>>();
  for (const item of activity) {
    if (!activeByListing.has(item.listing_id)) activeByListing.set(item.listing_id, new Set());
    activeByListing.get(item.listing_id)!.add(item.type);
  }

  const allTasks = [...new Set(listings.flatMap((l) => l.supported_tasks))].sort();
  const allInterfaces = [...new Set(listings.flatMap((l) => l.interfaces))].sort();
  const allLicenses = [...new Set(listings.map((l) => l.license).filter(Boolean) as string[])].sort();
  const allActivityTypes = [...new Set(activity.map((a) => a.type))].sort();

  const visible = listings.filter((listing) => {
    if (!matches(listing, filters)) return false;
    if (filters.activity && !activeByListing.get(listing.listing_id)?.has(filters.activity)) return false;
    return true;
  });

  return (
    <div style={styles.page}>
      <SiteNav />

      <section style={{ borderBottom: `1px solid ${color.border}` }}>
        <div style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 64 }}>
          <div style={styles.eyebrow}>EMILIA Marketplace · Private beta</div>
          <h1 style={{ ...styles.h1, maxWidth: 760 }}>
            The verified market for autonomous work
          </h1>
          <p style={{ ...styles.body, maxWidth: 680 }}>
            An open directory of builders, agents, and projects. List what you are building,
            show the work, become discoverable. Every material claim carries a status, a scope,
            a source, and its limitations — VERIFIED and ASSERTED are never the same thing here.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/works/opportunities" style={cta.secondary}>Browse opportunities</Link>
            <a href="https://github.com/emiliaprotocol/emilia-protocol" style={cta.ghost}>
              Source on GitHub
            </a>
          </div>
        </div>
      </section>

      <section>
        <div style={{ ...styles.sectionWide, paddingTop: 48, paddingBottom: 96 }}>
          {/* Filters — plain GET form, server-rendered */}
          <form method="get" action="/works" style={{
            display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end',
            padding: '20px 24px', background: color.card,
            border: `1px solid ${color.border}`, borderRadius: radius.base, marginBottom: 32,
          }}>
            <FilterField label="Search">
              <input name="q" defaultValue={filters.q} placeholder="Name, task, interface"
                style={{ ...styles.input, width: 220 }} />
            </FilterField>
            <FilterSelect label="Task" name="task" value={filters.task} options={allTasks} />
            <FilterSelect label="Interface" name="interface" value={filters.iface} options={allInterfaces} />
            <FilterSelect label="License" name="license" value={filters.license} options={allLicenses} />
            <FilterSelect label="Activity" name="activity" value={filters.activity} options={allActivityTypes} />
            <button type="submit" style={{ ...cta.primary, padding: '12px 20px' }}>Filter</button>
          </form>

          <div style={{
            fontFamily: font.mono, fontSize: 12, color: color.t3,
            letterSpacing: 1, textTransform: 'uppercase', marginBottom: 16,
          }}>
            {visible.length} of {listings.length} listings
          </div>

          <div style={{ display: 'grid', gap: 16 }}>
            {visible.map((listing) => {
              const builder = builderById.get(listing.builder_id);
              const listingCards = cards.filter((c) => c.listing_id === listing.listing_id);
              return (
                <div key={listing.listing_id} style={{
                  background: color.card, border: `1px solid ${color.border}`,
                  borderRadius: radius.base, padding: '24px 28px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        <Link href={`/works/listings/${listing.listing_id}`} style={{
                          fontFamily: font.sans, fontSize: 18, fontWeight: 700,
                          color: color.t1, textDecoration: 'none',
                        }}>
                          {listing.name}
                        </Link>
                        {listing.example ? <ExampleTag /> : null}
                      </div>
                      {builder ? (
                        <Link href={`/works/builders/${builder.builder_id}`} style={{
                          fontSize: 13, color: color.t3, textDecoration: 'none',
                        }}>
                          {builder.name}
                        </Link>
                      ) : null}
                    </div>
                    <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3 }}>
                      {listing.kind} · {listing.license || 'license unspecified'} · {listing.status}
                    </div>
                  </div>

                  <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: '12px 0 16px', maxWidth: 820 }}>
                    {listing.summary}
                  </p>

                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: listingCards.length ? 16 : 0 }}>
                    {listing.supported_tasks.map((task) => <Tag key={`t-${task}`}>{task}</Tag>)}
                    {listing.interfaces.map((iface) => <Tag key={`i-${iface}`}>{iface}</Tag>)}
                  </div>

                  {listingCards.slice(0, 2).map((card) => (
                    <div key={card.card_id} style={{
                      display: 'flex', alignItems: 'flex-start', gap: 12,
                      borderTop: `1px solid ${color.border}`, paddingTop: 12, marginTop: 12,
                    }}>
                      <ClaimBadge claim={card.claim} />
                      <span style={{ fontSize: 13, color: color.t2, lineHeight: 1.6 }}>
                        {card.claim.statement}
                      </span>
                    </div>
                  ))}
                </div>
              );
            })}
            {visible.length === 0 ? (
              <div style={{ ...styles.card, color: color.t3, fontSize: 14 }}>
                No listings match these filters.
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

function FilterField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: 'grid', gap: 6 }}>
      <span style={{
        fontFamily: font.mono, fontSize: 11, letterSpacing: 1,
        textTransform: 'uppercase', color: color.t3,
      }}>
        {label}
      </span>
      {children}
    </label>
  );
}

function FilterSelect({ label, name, value, options }: {
  label: string; name: string; value: string; options: string[];
}) {
  return (
    <FilterField label={label}>
      <select name={name} defaultValue={value} style={{ ...styles.input, width: 180 }}>
        <option value="">All</option>
        {options.map((option) => (
          <option key={option} value={option}>{option}</option>
        ))}
      </select>
    </FilterField>
  );
}
