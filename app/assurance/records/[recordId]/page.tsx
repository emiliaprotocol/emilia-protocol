// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import {
  CLAIM_ASSURANCE_REFERENCE_API_PATH,
  CLAIM_ASSURANCE_REFERENCE_RECORD_ID,
  getClaimAssuranceReferenceRecord,
} from '@/lib/assurance-reference';
import { color, font, radius, styles } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Synthetic Assurance Record | EMILIA Protocol',
  description: 'A content-addressed, deterministic, reference-only Claim Assurance record that can be replayed offline.',
};

export const dynamicParams = false;

export function generateStaticParams(): Array<{ recordId: string }> {
  return [{ recordId: CLAIM_ASSURANCE_REFERENCE_RECORD_ID }];
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ ...styles.card, padding: '18px 20px' }}>
      <div style={{ ...styles.eyebrow, marginBottom: 8 }}>{label}</div>
      <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t1, overflowWrap: 'anywhere', lineHeight: 1.6 }}>
        {value}
      </div>
    </div>
  );
}

export default async function ClaimAssuranceRecordPage({ params }: {
  params: Promise<{ recordId: string }>;
}) {
  const { recordId } = await params;
  const record = getClaimAssuranceReferenceRecord(recordId);
  if (!record) notFound();

  const replayCommand = `npm --prefix packages/verify run build\nnode examples/claim-assurance-reference/generate.mjs --check`;

  return (
    <div style={styles.page}>
      <SiteNav activePage="assurance" />
      <main style={{ ...styles.sectionWide, paddingTop: 56, paddingBottom: 96 }}>
        <Link href="/assurance" style={{ color: color.t3, textDecoration: 'none', fontSize: 14 }}>
          ← Assurance
        </Link>

        <div style={{
          marginTop: 28,
          padding: '14px 18px',
          border: `1px solid ${color.gold}`,
          borderRadius: radius.base,
          color: color.t1,
          background: color.card,
          fontFamily: font.mono,
          fontSize: 12,
          letterSpacing: 0.5,
        }}>
          SYNTHETIC REFERENCE RECORD. No customer, production deployment, certificate, or real institutional source is represented.
        </div>

        <section style={{ maxWidth: 820, padding: '52px 0 28px' }}>
          <div style={{ ...styles.eyebrow, color: color.goldDark }}>EP-ASSURANCE-RECORD-v1</div>
          <h1 style={styles.h1}>A claim became verifiable evidence.</h1>
          <p style={{ ...styles.body, fontSize: 18, maxWidth: 760 }}>
            This fixed fictional vendor-bank-change case shows how a pinned profile, two synthetic evidence sources, and a pinned verifier produce a portable record. The record is bound to one exact action digest. It can inform a later Gate decision, but it cannot authorize the action.
          </p>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <span style={{
              padding: '6px 11px', borderRadius: radius.sm, background: color.greenDark,
              color: color.card, fontFamily: font.mono, fontSize: 11, fontWeight: 700,
            }}>{record.verdict}</span>
            <span style={{
              padding: '6px 11px', borderRadius: radius.sm, border: `1px solid ${color.border}`,
              color: color.t2, fontFamily: font.mono, fontSize: 11, fontWeight: 700,
            }}>AUTHORIZES ACTION: FALSE</span>
          </div>
        </section>

        <section style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: 14, margin: '16px 0 56px',
        }}>
          <Fact label="Record digest" value={record.record_digest} />
          <Fact label="Pinned profile" value={`${record.profile_id}\n${record.profile_hash}`} />
          <Fact label="Claim Case digest" value={record.claim_case_digest} />
          <Fact label="Exact action digest" value={record.action_digest ?? 'No action binding'} />
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))', gap: 18, marginBottom: 56 }}>
          <div style={styles.card}>
            <div style={{ ...styles.eyebrow, color: color.greenDark }}>What VERIFIED means here</div>
            <h2 style={styles.h3}>The pinned synthetic profile was satisfied.</h2>
            <ul style={{ ...styles.list, fontSize: 14, marginBottom: 0 }}>
              <li>Two distinct fictional source IDs supported the same claim.</li>
              <li>Every artifact digest and binding matched.</li>
              <li>The verifier source and profile were pinned by digest.</li>
              <li>The record can be reproduced at its fixed evaluation time.</li>
            </ul>
          </div>
          <div style={{ ...styles.card, borderColor: color.gold }}>
            <div style={{ ...styles.eyebrow, color: color.goldDark }}>What it does not mean</div>
            <h2 style={styles.h3}>Verification is not authority.</h2>
            <ul style={{ ...styles.list, fontSize: 14, marginBottom: 0 }}>
              <li>No real organization, vendor, bank account, or customer was assessed.</li>
              <li>No certification, accreditation, deployment, or outcome is claimed.</li>
              <li>No money moved and no provider accepted an instruction.</li>
              <li>Gate still evaluates authority, policy, exact-action binding, freshness, and replay separately.</li>
            </ul>
          </div>
        </section>

        <section style={{ marginBottom: 56 }}>
          <div style={styles.eyebrow}>Evidence results</div>
          <h2 style={styles.h2}>Two synthetic observations, preserved separately</h2>
          <div style={{ display: 'grid', gap: 12 }}>
            {record.evidence_results.map((evidence) => (
              <div key={evidence.evidence_id} style={{ ...styles.card, padding: '18px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                  <strong style={{ fontFamily: font.mono, fontSize: 13 }}>{evidence.source_id}</strong>
                  <span style={{ color: color.greenDark, fontFamily: font.mono, fontSize: 11, fontWeight: 700 }}>
                    {evidence.disposition} · {evidence.relationship}
                  </span>
                </div>
                <div style={{ marginTop: 8, fontFamily: font.mono, fontSize: 11, color: color.t3, overflowWrap: 'anywhere' }}>
                  {evidence.artifact_digest}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section style={{ ...styles.card, background: color.t1, color: color.card }}>
          <div style={{ ...styles.eyebrow, color: color.goldDark }}>Re-perform, do not trust this page</div>
          <h2 style={{ ...styles.h2, color: color.card }}>Replay the exact case offline.</h2>
          <p style={{ color: color.border, lineHeight: 1.7, maxWidth: 760 }}>
            The committed generator hashes the verifier source, recomputes every artifact and profile digest, evaluates the Claim Case, checks the final record digest, and compares the generated bytes with this public record.
          </p>
          <pre style={{
            padding: 18, borderRadius: radius.base, overflowX: 'auto',
            background: '#1C1917', color: '#E7E5E4', fontFamily: font.mono,
            fontSize: 12, lineHeight: 1.8,
          }}>{replayCommand}</pre>
          <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', marginTop: 20 }}>
            <a href={CLAIM_ASSURANCE_REFERENCE_API_PATH} style={{ color: color.goldDark, fontFamily: font.mono, fontSize: 13 }}>
              Resolve exact JSON
            </a>
            <a
              href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/claim-assurance-reference"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: color.goldDark, fontFamily: font.mono, fontSize: 13 }}
            >
              Inspect generator and verifier
            </a>
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
