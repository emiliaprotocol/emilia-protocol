// SPDX-License-Identifier: Apache-2.0
//
// /works: server-rendered marketplace entry. Listing fields remain poster-supplied;
// the public Authority Record service retains its separate consent boundary.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { listWorksRecords } from '@/lib/works/store';
import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import { listPublicAuthorityRecords } from '@/lib/works/authority-record-service';
import type { ActivityRecord, BuilderRecord, CapabilityCardRecord, ListingRecord } from '@/lib/works/model';
import { ClaimBadge, ExampleTag, Tag, WorksDisciplineNote } from './ui';
import market from './works.module.css';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Discover AI Agents | EMILIA Marketplace',
  description: 'Browse builder-posted AI agents and start with a free scan. The open Gate stays free; setup and support are quoted separately. Qualification is scope-specific.',
  alternates: { canonical: '/works' },
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
    const haystack = [listing.name, listing.summary, listing.license || '', ...listing.supported_tasks, ...listing.interfaces].join(' ').toLowerCase();
    if (!haystack.includes(filters.q.toLowerCase())) return false;
  }
  return true;
}

function isActiveAgent(listing: ListingRecord): boolean {
  return listing.example === false && listing.kind === 'agent' && listing.status === 'active';
}

async function loadAuthorityRecords(): Promise<
  | { status: 'AVAILABLE'; records: Awaited<ReturnType<typeof listPublicAuthorityRecords>> }
  | { status: 'UNAVAILABLE' }
> {
  try {
    return {
      status: 'AVAILABLE',
      records: await listPublicAuthorityRecords({ store: createSupabaseAuthorityRecordStore() }),
    };
  } catch {
    // Configuration failures can happen before a promise exists. Keep them,
    // and service failures, distinct from a successful empty public directory.
    // Backend error details may contain private configuration; do not render them.
    return { status: 'UNAVAILABLE' };
  }
}

export default async function WorksDirectory({ searchParams }: {
  searchParams: Promise<SearchParams>;
}) {
  if (!isWorksV0Enabled()) notFound();
  const params = await searchParams;
  const filters = {
    q: one(params.q), task: one(params.task), iface: one(params.interface),
    license: one(params.license), activity: one(params.activity),
  };

  const [listingsRes, buildersRes, cardsRes, activityRes, authorityRecordsRes] = await Promise.all([
    listWorksRecords('listings'),
    listWorksRecords('builders'),
    listWorksRecords('cards'),
    listWorksRecords('activity'),
    loadAuthorityRecords(),
  ]);
  const listings = (listingsRes.ok ? listingsRes.records : []) as ListingRecord[];
  const builders = (buildersRes.ok ? buildersRes.records : []) as BuilderRecord[];
  const cards = (cardsRes.ok ? cardsRes.records : []) as CapabilityCardRecord[];
  const activity = (activityRes.ok ? activityRes.records : []) as ActivityRecord[];
  const authorityRecords = authorityRecordsRes.status === 'AVAILABLE' ? authorityRecordsRes.records : [];
  const builderById = new Map(builders.map(builder => [builder.builder_id, builder]));
  const activeByListing = new Map<string, Set<string>>();
  for (const item of activity) {
    if (!activeByListing.has(item.listing_id)) activeByListing.set(item.listing_id, new Set());
    activeByListing.get(item.listing_id)!.add(item.type);
  }
  const allTasks = [...new Set(listings.flatMap(listing => listing.supported_tasks))].sort();
  const allInterfaces = [...new Set(listings.flatMap(listing => listing.interfaces))].sort();
  const allLicenses = [...new Set(listings.map(listing => listing.license).filter(Boolean) as string[])].sort();
  const allActivityTypes = [...new Set(activity.map(item => item.type))].sort();
  const visible = listings.filter(listing => matches(listing, filters)
    && (!filters.activity || activeByListing.get(listing.listing_id)?.has(filters.activity)));
  const filtersActive = Object.values(filters).some(Boolean);
  const agents = listings.filter(isActiveAgent);
  const visibleAgents = visible.filter(isActiveAgent);
  const visibleExamples = visible.filter(listing => listing.example === true);
  const visibleOther = visible.filter(listing => listing.example !== true && !isActiveAgent(listing));
  const visibleAuthorityRecords = authorityRecords.filter(record => {
    if (!filters.q) return true;
    const subject = record.projection.subject;
    return `${subject.name} ${subject.builder_name} ${subject.repository_url}`.toLowerCase().includes(filters.q.toLowerCase());
  });
  const renderListing = (listing: ListingRecord) => (
    <ListingPreview key={listing.listing_id} listing={listing}
      builder={builderById.get(listing.builder_id)}
      cards={cards.filter(card => card.listing_id === listing.listing_id)} />
  );

  return (
    <div className={market.marketPage}>
      <SiteNav activePage="works" />
      <main>
        <section className={market.marketHero}>
          <nav className={market.marketContainer + ' ' + market.marketContext} aria-label="Marketplace context"><Link href="/">EMILIA</Link><span aria-hidden="true">/</span><span>Marketplace</span><Link href="/workforce">Looking to manage your agents? Explore Workforce</Link></nav>
          <div className={market.marketContainer + ' ' + market.heroLayout}>
            <div className={market.heroCopy}>
            <p className={market.marketEyebrow}>EMILIA Marketplace <span>Early access</span></p>
            <h1>Discover the agent.<br /><span>Inspect its tools.</span></h1>
            <p className={market.marketLead}>Explore what builders are making. See the tools an agent declares, the actions worth reviewing, and the evidence behind its claims.</p>
            <div className={market.marketActions}>
              <Link href="/works/scan" className={market.marketPrimary}>Start a free scan</Link>
              <a href="#works-listings" className={market.marketSecondary}>Browse agent listings</a>
            </div>
            <p className={market.heroPrivacy}>No account. No upload. Your input stays in your browser.</p>
            </div>
            <figure className={market.inspectionArt}>
              <Image src="/marketplace-tool-inspection-v1.webp" alt="Brass inspection lens above glass tools for code, records and messages. Concept illustration." width={1254} height={1254} sizes="(max-width: 760px) 90vw, 45vw" priority />
              <figcaption><span>UNDERSTAND BEFORE YOU CONNECT</span><p>Code. Records. Customer messages.<br />Different tools deserve different limits.</p></figcaption>
            </figure>
          </div>
          <div className={market.marketContainer + ' ' + market.heroFootnote}><span>Built on the open EMILIA Protocol</span><p>A scan does not run the agent or activate protection. A listing is not permission to act.</p></div>
        </section>

        <section id="works-listings" className={market.marketSection} aria-labelledby="agent-listings-title">
          <div className={market.marketContainer}>
            <div className={market.sectionHeading}><p className={market.marketEyebrow}>01 / The directory</p><Link href="/works/join" className={market.marketSecondary}>List your agent</Link></div>
            <h2 id="agent-listings-title">Agents for your shortlist</h2>
            <p className={market.marketLead}>Look at the work, the tools and the evidence. Every listing starts with its builder&apos;s own description.</p>
            <form method="get" action="/works" className={market.marketFilters}>
              <FilterField label="Search"><input name="q" defaultValue={filters.q} placeholder="Name, task, interface" /></FilterField>
              <FilterSelect label="Task" name="task" value={filters.task} options={allTasks} />
              <FilterSelect label="Interface" name="interface" value={filters.iface} options={allInterfaces} />
              <FilterSelect label="License" name="license" value={filters.license} options={allLicenses} />
              <FilterSelect label="Activity" name="activity" value={filters.activity} options={allActivityTypes} />
              <button type="submit" className={market.marketPrimary}>Filter listings</button>
            </form>

            {!listingsRes.ok ? (
              <p className={market.marketEmpty} role="status">The listing directory is unavailable right now. We cannot confirm the number of agents. Please try again later.</p>
            ) : (
              <>
                <p className={market.marketCount}>{visibleAgents.length} of {agents.length} active agent listings · examples excluded</p>
                <p className={market.marketNote}>“Active” is the poster&apos;s listing status, not verified availability for hire. Apps, projects and paused or archived work are listed separately below.</p>
                <div className={market.marketListingList}>{visibleAgents.map(renderListing)}</div>
                {visibleAgents.length === 0 ? (
                  <div className={market.marketEmpty}>
                    <h3>{agents.length === 0 ? 'No active agent listings yet.' : 'No active agents match these filters.'}</h3>
                    <p>{agents.length === 0 ? 'The directory is open for builders. Example records below show the format; they are not available agents.' : 'Try a different task or interface, or tell builders what you need.'}</p>
                    <div className={market.marketActions}>
                      <Link href="/works/join" className={market.marketSecondary}>List your agent</Link>
                      <Link href="/works/opportunities/new" className={market.marketSecondary}>Post a job</Link>
                    </div>
                  </div>
                ) : null}
                {filtersActive && visible.length === 0 ? (
                  <p className={market.marketNote}>No listings match these filters. <Link href="/works">Reset filters</Link></p>
                ) : null}
              </>
            )}
            {!cardsRes.ok || !buildersRes.ok || !activityRes.ok ? (
              <p className={market.marketNote} role="status">Some builder, claim or activity records could not be loaded. Missing evidence is unknown, not a favorable result.</p>
            ) : null}
          </div>
        </section>

        <section className={market.marketSection + ' ' + market.marketTinted} aria-labelledby="market-next-title">
          <div className={market.marketContainer}>
            <p className={market.marketEyebrow}>From discovery to a real workflow</p>
            <h2 id="market-next-title">Find the right next step.</h2>
            <div className={market.marketColumns}>
              <article><h3>Need an agent?</h3><p>Post the problem, scope and acceptance criteria. Builders can respond through the existing opportunity workflow. Hiring and payment terms are agreed separately.</p><Link href="/works/opportunities/new">Post a job</Link><Link href="/works/opportunities">Browse and respond</Link></article>
              <article><h3>Building an agent?</h3><p>List your work, its constraints and the evidence you can share. A listing does not become verified just because it is here.</p><Link href="/works/join">List your work</Link></article>
              <article><h3>Ready for consequential work?</h3><p>The open Gate stays free. Paid setup and support are quoted separately. Qualification concerns a named candidate and assignment; it does not authorize execution or certify an agent as safe.</p><Link href="/works/gate">Explore Gate setup and support</Link><Link href="/works/qualification">Understand qualification</Link></article>
            </div>
          </div>
        </section>

        <section id="authority-records" className={market.marketSection} aria-labelledby="authority-records-title">
          <div className={market.marketContainer}>
            <p className={market.marketEyebrow}>03 / Owner-claimed · version-pinned</p>
            <h2 id="authority-records-title">Inspect an Authority Record</h2>
            <p className={market.marketLead}>Public records appear only after the named repository proves control and its owner approves the exact current bytes. Private scans never appear here without that separate approval.</p>
            <p className={market.marketNote}>Payment can buy monitoring and freshness, never a favorable result. These records are not counted as available agent listings.</p>
            <div className={market.marketListingList}>
              {visibleAuthorityRecords.map(record => (
                <Link key={record.record_id} href={`/works/records/${record.record_id}`} className={market.marketAuthorityRecord}>
                  <strong>{record.projection.subject.name}</strong>
                  <span>{record.projection.subject.builder_name}</span>
                  <span>Mapped {record.projection.provenance.observed_at.slice(0, 10)} · commit {record.projection.provenance.resolved_revision.slice(0, 12)}</span>
                </Link>
              ))}
              {authorityRecordsRes.status === 'UNAVAILABLE' ? (
                <p className={market.marketEmpty} role="status">Authority Records are unavailable right now. We cannot confirm which public records are available. Please try again later.</p>
              ) : visibleAuthorityRecords.length === 0 ? <p className={market.marketEmpty}>{filters.q ? 'No owner-approved Authority Records match this search.' : 'No owner-approved Authority Records are public yet. Private scans never appear here.'}</p> : null}
            </div>
          </div>
        </section>

        {visibleOther.length > 0 ? <section className={market.marketSection} aria-labelledby="other-work-title"><div className={market.marketContainer}>
          <h2 id="other-work-title">Other listed work</h2>
          <p className={market.marketLead}>Apps, projects and inactive agent listings. These are not included in the active agent count.</p>
          <div className={market.marketListingList}>{visibleOther.map(renderListing)}</div>
        </div></section> : null}

        <section id="example-listings" className={market.marketSection + ' ' + market.marketTinted} aria-labelledby="example-listings-title"><div className={market.marketContainer}>
          <p className={market.marketEyebrow}>Read-only examples · not marketplace supply</p>
          <h2 id="example-listings-title">See how a listing works</h2>
          <p className={market.marketLead}>These example agents, apps and projects show the record format. They are not available workers, customer deployments or proof of marketplace adoption.</p>
          <details className={market.examplesDisclosure}><summary>Open the example directory</summary>
          <div className={market.marketListingList}>{visibleExamples.map(renderListing)}</div>
          {listingsRes.ok && visibleExamples.length === 0 ? <p className={market.marketNote}>No example listings match these filters.</p> : null}
          <p className={market.marketNote}><strong>Read the statement, not just the badge.</strong> VERIFIED describes source-backed evidence for that claim and scope, not universal agent trust. ASSERTED is a poster&apos;s statement. UNKNOWN means the evidence is missing or no longer current.</p>
          <WorksDisciplineNote />
          </details>
        </div></section>
      </main>
      <SiteFooter />
    </div>
  );
}

function ListingPreview({ listing, builder, cards }: {
  listing: ListingRecord; builder?: BuilderRecord; cards: CapabilityCardRecord[];
}) {
  return <article className={market.marketListing}>
    <div className={market.marketListingHeading}>
      <div><div className={market.marketTitleRow}>
        <h3><Link href={`/works/listings/${listing.listing_id}`}>{listing.name}</Link></h3>
        {listing.example ? <ExampleTag /> : null}
      </div>
      {builder ? <Link href={`/works/builders/${builder.builder_id}`} className={market.marketBuilder}>{builder.name}</Link> : <p className={market.marketNote}>Builder record unavailable.</p>}</div>
      <p className={market.marketMeta}>{listing.kind} · {listing.license || 'license unspecified'} · {listing.status}{listing.example === undefined ? ' · example status unspecified' : ''}</p>
    </div>
    <p className={market.marketListingSummary}>{listing.summary}</p>
    <div className={market.marketPills}>{listing.supported_tasks.map(task => <Tag key={`t-${task}`}>{task}</Tag>)}{listing.interfaces.map(iface => <Tag key={`i-${iface}`}>{iface}</Tag>)}</div>
    {cards.slice(0, 2).map(card => <div key={card.card_id} className={market.marketClaim}>
      <div className={market.marketTitleRow}><ClaimBadge claim={card.claim} /><span>Statement evidence</span></div>
      <p>{card.claim.statement}</p>
      <p className={market.marketNote}>Scope: {card.claim.scope} · Observed {card.claim.observed_at.slice(0, 10)}</p>
      <p className={market.marketNote}>Source: {card.claim.source?.reference || 'none recorded'}</p>
      <p className={market.marketNote}>Limitations: {card.claim.limitations || 'not specified by the poster'}</p>
    </div>)}
    {cards.length === 0 ? <p className={market.marketNote}>No capability evidence is displayed for this listing.</p> : null}
    <Link href={`/works/listings/${listing.listing_id}`} className={market.marketListingLink}>Inspect listing and evidence</Link>
  </article>;
}

function FilterField({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className={market.marketFilterField}><span>{label}</span>{children}</label>;
}

function FilterSelect({ label, name, value, options }: {
  label: string; name: string; value: string; options: string[];
}) {
  return <FilterField label={label}><select name={name} defaultValue={value}><option value="">All</option>{options.map(option => <option key={option} value={option}>{option}</option>)}</select></FilterField>;
}
