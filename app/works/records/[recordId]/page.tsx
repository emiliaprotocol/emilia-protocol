// SPDX-License-Identifier: Apache-2.0

import Link from 'next/link';
import Image from 'next/image';
import { notFound } from 'next/navigation';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { color, font, radius, styles } from '@/lib/tokens';
import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import { getPublicAuthorityRecord } from '@/lib/works/authority-record-service';
import { resolveAuthorityRecordGitHubRef } from '@/lib/works/authority-record-freshness';
import { evaluateAuthorityRecordFreshness } from '@/lib/works/authority-record';
import { isWorksV0Enabled } from '@/lib/works/env';
import { readAuthorityRecordDemandCounts } from '@/lib/works/demand-service';
import { createSupabaseAuthorityDemandStore } from '@/lib/works/demand-store';
import RequestAuthorityRecord from './RequestAuthorityRecord';

export const dynamic = 'force-dynamic';

export default async function AuthorityRecordPage({ params }: {
  params: Promise<{ recordId: string }>;
}) {
  if (!isWorksV0Enabled()) notFound();
  const { recordId } = await params;
  const record = await getPublicAuthorityRecord({
    recordId, store: createSupabaseAuthorityRecordStore(),
  });
  if (!record) notFound();
  const projection = record.projection;
  const observedDate = projection.provenance.observed_at.slice(0, 10);
  const commit = projection.provenance.resolved_revision;
  const freshness = evaluateAuthorityRecordFreshness(
    projection,
    await resolveAuthorityRecordGitHubRef({
      repositoryUrl: projection.subject.repository_url,
      watchedRef: projection.provenance.watched_ref,
    }),
  );
  let demand = { verified_requesters: 0, verified_organizations: 0 };
  try {
    demand = await readAuthorityRecordDemandCounts({
      recordId, store: createSupabaseAuthorityDemandStore(),
    });
  } catch {
    // Exact counts are optional display data. Never estimate when unavailable.
  }

  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 96 }}>
        <Link href="/works" style={{ color: color.t3, textDecoration: 'none' }}>← EMILIA Works</Link>
        <div style={{ ...styles.eyebrow, marginTop: 28 }}>Versioned Authority Record</div>
        <h1 style={{ ...styles.h1, marginBottom: 8 }}>{projection.subject.name}</h1>
        <p style={{ ...styles.body, color: color.t2, marginTop: 0 }}>{projection.subject.builder_name}</p>

        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 14, margin: '32px 0',
        }}>
          <Fact label="Mapped by EMILIA" value={`${observedDate} against commit ${commit.slice(0, 12)}`} />
          <Fact label="Owner-approved bytes" value={record.record_digest} mono />
          <Fact label="Watched ref" value={projection.provenance.watched_ref} mono />
          <Fact label="Record expires" value={projection.provenance.expires_at.slice(0, 10)} />
          <Fact label="Watched ref status" value={freshness.status} />
        </div>

        {freshness.status === 'STALE' ? (
          <section style={{ ...styles.card, borderColor: '#b7791f' }}>
            <strong>Visible update detected</strong>
            <p style={{ color: color.t3, marginBottom: 0 }}>
              The watched ref now resolves to commit {freshness.current_revision.slice(0, 12)}.
              This record still describes {freshness.observed_revision.slice(0, 12)} and should be rescanned.
            </p>
          </section>
        ) : freshness.status === 'UNAVAILABLE' || freshness.status === 'INDETERMINATE' ? (
          <section style={{ ...styles.card }}>
            <strong>Freshness not established</strong>
            <p style={{ color: color.t3, marginBottom: 0 }}>
              EMILIA could not establish the current watched-ref revision. The record is not labeled stale.
            </p>
          </section>
        ) : null}

        <section style={{ marginTop: 40 }}>
          <h2 style={styles.h2}>Observed authority surface</h2>
          <div style={{ display: 'grid', gap: 12 }}>
            {projection.surfaces.map((surface) => (
              <div key={surface.surface_id} style={{
                padding: 20, border: `1px solid ${color.border}`, borderRadius: radius.base,
                background: color.card,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                  <strong>{surface.label}</strong>
                  <span style={{ fontFamily: font.mono, color: color.t3, fontSize: 12 }}>
                    {surface.evidence_status} · {surface.enforcement_status}
                  </span>
                </div>
                <div style={{ color: color.t3, fontSize: 13, marginTop: 8 }}>
                  {surface.action_class} → {surface.consequence_class}
                </div>
              </div>
            ))}
          </div>
        </section>

        {projection.owner_statement ? (
          <section style={{ ...styles.card, marginTop: 32 }}>
            <div style={styles.eyebrow}>Seller asserted</div>
            <p style={{ color: color.t2, marginBottom: 0 }}>{projection.owner_statement.statement}</p>
          </section>
        ) : null}

        <section style={{ ...styles.card, marginTop: 32 }}>
          <strong>What this record does not say</strong>
          <p style={{ color: color.t3, marginBottom: 0 }}>
            This is a scoped mapping of public evidence at one revision. It is not a certification,
            safety rating, completeness claim, or proof that every execution path is mediated.
          </p>
        </section>

        <RequestAuthorityRecord
          recordId={record.record_id}
          verifiedRequesters={demand.verified_requesters}
          verifiedOrganizations={demand.verified_organizations}
        />

        <div style={{ marginTop: 28 }}>
          {/* Text equivalent: Mapped by EMILIA on a date against a commit. */}
          <Image
            src={`/api/works/authority-records/${record.record_id}/badge`}
            alt={`Mapped by EMILIA on ${observedDate} against commit ${commit.slice(0, 12)}`}
            width={620}
            height={34}
            unoptimized
            style={{ width: 'auto', maxWidth: '100%', height: 34 }}
          />
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ padding: 18, border: `1px solid ${color.border}`, borderRadius: radius.base }}>
      <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginBottom: 8 }}>{label}</div>
      <div style={{ fontFamily: mono ? font.mono : font.sans, fontSize: mono ? 12 : 14, overflowWrap: 'anywhere' }}>
        {value}
      </div>
    </div>
  );
}
