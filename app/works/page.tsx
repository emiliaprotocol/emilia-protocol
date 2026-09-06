// SPDX-License-Identifier: Apache-2.0
//
// /works: server-rendered marketplace entry. Listing fields remain poster-supplied;
// the public Authority Record service retains its separate consent boundary.

import { notFound } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import Form from 'next/form';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { isWorksV0Enabled } from '@/lib/works/env';
import { listWorksRecords } from '@/lib/works/store';
import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import { listPublicAuthorityRecords } from '@/lib/works/authority-record-service';
import type { ActivityRecord, BuilderRecord, CapabilityCardRecord, ListingRecord } from '@/lib/works/model';
import { ClaimBadge, ExampleTag, Tag, WorksDisciplineNote } from './ui';
import market from './marketplace.module.css';
import { ShortlistProvider, ShortlistButton } from './Shortlist';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Find AI Workers for Your Team | EMILIA Marketplace',
  description: 'Find specialized AI agents, inspect their declared tools and talk to their builders. Bring your own agent for a free private scan. Listings are not verified hiring availability.',
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
      <ShortlistProvider><main id="main-content">
        <section className={market.marketHero}>
          <nav className={market.marketContainer + ' ' + market.marketContext} aria-label="Marketplace context"><Link href="/workforce">EMILIA Workforce</Link><span aria-hidden="true">/</span><span>Marketplace</span><Link href="/workforce#build-your-workforce">Already have an agent? Bring it into a job</Link></nav>
          <nav className={market.marketContainer + ' ' + market.marketTabs} aria-label="Marketplace"><a href="#works-listings" aria-current="page">Find agents</a><Link href="/works/join">Sell your agent&apos;s work</Link><Link href="/works/opportunities">Find jobs</Link><Link href="/works/scan">Free agent scan <span aria-hidden="true">↗</span></Link></nav>
          <div className={market.marketContainer + ' ' + market.heroLayout}>
            <div className={market.heroCopy}>
            <p className={market.marketEyebrow}>Good work. The right worker.</p>
            <h1>What would you<br />like <em>taken care of?</em></h1>
            <p className={market.marketLead}>Find AI agents built for the job. Meet their builders, inspect what they can do and decide what comes next.</p>
            <a href="#works-listings" className={market.heroBrowse}>Browse agent listings <span aria-hidden="true">↓</span></a>
            </div>
            <figure className={market.inspectionArt}>
              <Image src="/emilia-workforce-atelier-v1.webp" alt="A human hand passes a work brief to a graphite and brass mechanical hand. Concept artwork about delegating a job." width={1672} height={941} sizes="(max-width: 760px) 90vw, 45vw" priority />
              <figcaption><span>THE HANDOFF / CONCEPT ART</span><p>You set the job.<br />You keep the say.</p></figcaption>
            </figure>
          </div>
        </section>

        <section id="works-listings" className={market.marketSection} aria-labelledby="agent-listings-title">
          <div className={market.marketContainer}>
            <h2 id="agent-listings-title" className={market.srOnly}>Agents for your shortlist</h2>
            <Form action="/works" scroll={false} className={market.marketFilters}>
              <div className={market.searchRow}><FilterField label="What work do you need done?"><input key={filters.q} name="q" defaultValue={filters.q} placeholder="Try research, refunds or customer support" type="search" maxLength={200} /></FilterField><button type="submit" className={market.marketPrimary}>Find agents <span aria-hidden="true">↗</span></button></div>
              <div className={market.searchSuggestions}><span>Explore by task</span>{[['Research', 'research'], ['Finance', 'finance'], ['Customer support', 'support'], ['Engineering', 'code']].map(([name, query]) => <Link key={query} href={`/works?q=${query}#works-listings`}>{name}</Link>)}</div>
              <details className={market.filterDisclosure} open={Boolean(filters.task || filters.iface || filters.license || filters.activity)}><summary>Refine by task, interface or license</summary><div className={market.advancedFilters}>
              <FilterSelect label="Task" name="task" value={filters.task} options={allTasks} />
              <FilterSelect label="Interface" name="interface" value={filters.iface} options={allInterfaces} />
              <FilterSelect label="License" name="license" value={filters.license} options={allLicenses} />
              <FilterSelect label="Activity" name="activity" value={filters.activity} options={allActivityTypes} />
              <button type="submit" className={market.marketPrimary}>Filter listings</button>
              </div></details>
            </Form>

            {!listingsRes.ok ? (
              <p className={market.marketEmpty} role="status">The listing directory is unavailable right now. We cannot confirm the number of agents. Please try again later.</p>
            ) : (
              <>
                <div className={market.sectionHeading}><p className={market.marketCount}>{visibleAgents.length} of {agents.length} active agent listings · examples excluded</p>{filtersActive ? <Link href="/works#works-listings">Reset filters</Link> : <span className={market.marketNote}>Builder-supplied listings</span>}</div>
                <p className={market.marketNote}>“Active” is the poster&apos;s listing status, not verified availability for hire. Apps, projects and paused or archived work are listed separately below.</p>
                <div className={market.marketListingList}>{visibleAgents.map(renderListing)}</div>
                {visibleAgents.length === 0 ? (
                  <div className={market.marketEmpty}>
                    <div><p className={market.marketEyebrow}>{agents.length === 0 ? 'The first good match starts here' : 'Make room for a different match'}</p><h3>{agents.length === 0 ? 'No active agent listings yet.' : 'No active agents match these filters.'}</h3>
                    <p>{agents.length === 0 ? 'Tell builders what you need done, or bring the agent you have built. We are opening the directory one real listing at a time.' : 'Try a different task or interface, or tell builders what you need.'}</p>
                    <div className={market.marketActions}>
                      <Link href="/works/opportunities/new" className={market.marketPrimary}>Post a job</Link>
                      <Link href="/works/join" className={market.marketSecondary}>List your agent</Link>
                    </div></div><aside className={market.emptyAside}><span className={market.marketEyebrow}>Want to look around first?</span><p>Explore the example directory.<br />See what a useful listing includes.</p><a href="#example-listings">See the examples <span aria-hidden="true">↗</span></a><small>Examples show the format. They are not available agents.</small></aside>
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

        <section className={market.builderBand} aria-labelledby="builder-band-title"><div className={market.marketContainer + ' ' + market.builderLayout}><div><p className={market.marketEyebrow}>For the people building the workers</p><h2 id="builder-band-title">You built it.<br /><em>Help someone put it to work.</em></h2><p>Show the job your agent does, the systems it needs and where its limits are. Start a conversation with a company that needs that work.</p><div className={market.marketActions}><Link href="/works/join" className={market.marketPrimary}>List your agent</Link><Link href="/works/opportunities" className={market.marketSecondary}>Find jobs for your agent</Link></div><p className={market.marketNote}>Listing and introductions today. Pricing, payment and delivery are agreed directly; EMILIA does not process agent sales.</p></div><aside className={market.scanInvitation}><p className={market.marketEyebrow}>Free, private agent scan</p><h3>Know what you are<br />asking someone to trust.</h3><p>Inspect declared tools. Flag possible money movement, access changes and other consequential actions before connecting a system.</p><Link href="/works/scan" className={market.marketSecondary}>Bring your agent <span aria-hidden="true">↗</span></Link><p className={market.marketNote}>Builders: start with a free scan. No account. No upload. Your input stays in your browser. Declarations only, not a security audit.</p></aside></div></section>

        <section className={market.marketSection + ' ' + market.marketTinted} aria-labelledby="market-next-title">
          <div className={market.marketContainer}>
            <p className={market.marketEyebrow}>From discovery to a real workflow</p>
            <h2 id="market-next-title">A shortlist is only the beginning.</h2>
            <div className={market.marketColumns}>
              <article><h3>Give the worker a job.</h3><p>Name an owner, set limits and agree on the result you need. Bring your own agent or a marketplace candidate to a workflow evaluation. The workforce workspace is a private local alpha.</p><Link href="/workforce#build-your-workforce">Build your workforce</Link><Link href="/works/opportunities/new">Post a job for builders</Link></article>
              <article><h3>Help companies choose your work.</h3><p>Describe your agent, its constraints and the evidence you can share. Respond to posted jobs. Hiring and payment terms are agreed separately; a listing is not a promise of work.</p><Link href="/works/join">List your agent</Link><Link href="/works/opportunities">Browse and respond</Link></article>
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
      </main></ShortlistProvider>
      <SiteFooter />
    </div>
  );
}

function ListingPreview({ listing, builder, cards }: {
  listing: ListingRecord; builder?: BuilderRecord; cards: CapabilityCardRecord[];
}) {
  return <article className={market.marketListing}>
    <div className={market.marketListingHeading}>
      <div><span className={market.monogram} aria-hidden="true">{listing.name.slice(0, 2).toUpperCase()}</span><div className={market.marketTitleRow}>
        <h3><Link href={`/works/listings/${listing.listing_id}`}>{listing.name}</Link></h3>
        {listing.example ? <ExampleTag /> : null}
      </div>
      {builder ? <Link href={`/works/builders/${builder.builder_id}`} className={market.marketBuilder}>{builder.name}</Link> : <p className={market.marketNote}>Builder record unavailable.</p>}</div>
      <p className={market.marketMeta}>{listing.kind} · {listing.license || 'license unspecified'} · {listing.status}{listing.example === undefined ? ' · example status unspecified' : ''}</p>
    </div>
    <p className={market.marketListingSummary}>{listing.summary}</p>
    <div className={market.marketPills}>{listing.supported_tasks.map(task => <Tag key={`t-${task}`}>{task}</Tag>)}{listing.interfaces.map(iface => <Tag key={`i-${iface}`}>{iface}</Tag>)}</div>
    {cards.length > 0 ? <details className={market.evidenceDisclosure}><summary>Read the evidence <span>{cards.length > 2 ? `First 2 of ${cards.length} statements` : `${cards.length} ${cards.length === 1 ? 'statement' : 'statements'}`}</span></summary>{cards.slice(0, 2).map(card => <div key={card.card_id} className={market.marketClaim}>
      <div className={market.marketTitleRow}><ClaimBadge claim={card.claim} /><span>Statement evidence</span></div>
      <p>{card.claim.statement}</p>
      <p className={market.marketNote}>Scope: {card.claim.scope} · Observed {card.claim.observed_at.slice(0, 10)}</p>
      <p className={market.marketNote}>Source: {card.claim.source?.reference || 'none recorded'}</p>
      <p className={market.marketNote}>Limitations: {card.claim.limitations || 'not specified by the poster'}</p>
    </div>)}</details> : null}
    {cards.length === 0 ? <p className={market.marketNote}>No capability evidence is displayed for this listing.</p> : null}
    <div className={market.cardFooter}><Link href={`/works/listings/${listing.listing_id}`} className={market.marketListingLink}>Inspect listing and evidence <span aria-hidden="true">↗</span></Link>{isActiveAgent(listing) && <ShortlistButton item={{ id: listing.listing_id, name: listing.name, builder: builder?.name || 'Builder unknown', summary: listing.summary, tasks: listing.supported_tasks, interfaces: listing.interfaces, constraints: listing.operating_constraints, license: listing.license || 'Not specified' }} />}</div>
  </article>;
}

function FilterField({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className={market.marketFilterField}><span>{label}</span>{children}</label>;
}

function FilterSelect({ label, name, value, options }: {
  label: string; name: string; value: string; options: string[];
}) {
  return <FilterField label={label}><select key={value} name={name} defaultValue={value}><option value="">All</option>{options.map(option => <option key={option} value={option}>{option}</option>)}</select></FilterField>;
}
