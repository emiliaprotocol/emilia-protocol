// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import {
  GATE_IMPLEMENTATION,
  PRODUCTION_GATE,
  PROTECTED_WORKFLOW_PILOT,
} from '@/lib/commercial-offer';

export const metadata: Metadata = {
  alternates: { canonical: '/cloud' },
};

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 920, margin: '0 auto', padding: '64px 24px 80px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#F59E0B', marginBottom: 12 },
  h1: { fontSize: 38, fontWeight: 700, letterSpacing: -0.7, lineHeight: 1.16, marginBottom: 16 },
  sub: { fontSize: 16, color: '#94A3B8', lineHeight: 1.7, marginBottom: 36, maxWidth: 760 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 48 },
  card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 8, padding: 24 },
  cardTitle: { fontSize: 16, fontWeight: 650, color: '#F8FAFC', marginBottom: 8 },
  cardBody: { fontSize: 13, color: '#94A3B8', lineHeight: 1.65, margin: 0 },
  label: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 1.7, textTransform: 'uppercase', color: '#60A5FA', marginBottom: 8 },
  section: { marginBottom: 48 },
  h2: { fontSize: 25, fontWeight: 700, marginBottom: 12 },
  body: { fontSize: 15, color: '#94A3B8', lineHeight: 1.72, maxWidth: 760 },
  cta: { display: 'inline-block', padding: '12px 22px', borderRadius: 8, fontSize: 14, fontWeight: 650, textDecoration: 'none' },
  divider: { height: 1, background: 'rgba(255,255,255,0.07)', margin: '48px 0' },
} satisfies Record<string, React.CSSProperties>;

const SURFACES = [
  ['Implemented reference UI', 'Policy, signoff, event, evidence, tenant-isolation, alert, and settings screens are present in the repository.'],
  ['Developer-configured test paths', 'Some screens can call repository API handlers when a developer supplies local or sandbox test configuration. That is not hosted-service availability.'],
  ['Evidence-bound status', 'The interfaces keep requests, decisions, consumption, provider entry, outcome, and reconciliation distinct when the backing evidence supports them.'],
  ['Designed operating shape', 'Production identity, customer-held credentials, trust roots, retention, isolation, and service levels must be scoped and accepted for a specific deployment.'],
] as const;

export default function CloudPage(): React.ReactElement {
  return (
    <main style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Deindexed implementation prototype</div>
        <h1 style={s.h1}>A reference view of the operations a Gate deployment would need.</h1>
        <p style={s.sub}>
          These screens make the intended operating surface inspectable. EMILIA does not
          currently offer this route as a managed Cloud product, and this prototype is not
          evidence of a customer deployment, production coverage, availability, or adoption.
        </p>

        <div style={s.grid}>
          {SURFACES.map(([title, body]) => (
            <article key={title} style={s.card}>
              <div style={s.cardTitle}>{title}</div>
              <p style={s.cardBody}>{body}</p>
            </article>
          ))}
        </div>

        <div style={s.divider} />

        <section style={s.section}>
          <div style={s.label}>Commercial boundary</div>
          <h2 style={s.h2}>One public pilot. Production is separate.</h2>
          <p style={s.body}>
            The public offer is the {PROTECTED_WORKFLOW_PILOT.priceLabel}, {' '}
            {PROTECTED_WORKFLOW_PILOT.durationLabel} Protected-workflow pilot for {' '}
            {PROTECTED_WORKFLOW_PILOT.workflowLabel}. It uses synthetic, read-only, sandbox,
            or shadow inputs only. It receives no provider credentials and cannot actuate a
            production system.
          </p>
          <p style={s.body}>
            After buyer acceptance, {GATE_IMPLEMENTATION.name} is separately scoped for one real
            executor boundary. {PRODUCTION_GATE.availabilityLabel}.
          </p>
        </section>

        <section style={s.section}>
          <div style={s.label}>Not established here</div>
          <h2 style={s.h2}>Interface coverage is not deployment assurance.</h2>
          <ul style={{ ...s.body, paddingLeft: 20 }}>
            <li>No currently operated or generally available hosted Gate Cloud service</li>
            <li>No customer, integration, production-isolation, residency, SSO, VPC, or SLA claim</li>
            <li>No certificate, audit conclusion, compliance determination, or successful-effect proof</li>
            <li>No production provider credentials, actuation authority, or complete-mediation claim</li>
          </ul>
        </section>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
          <a href="/pilot" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>
            Review the protected-workflow pilot
          </a>
          <a
            href="mailto:team@emiliaprotocol.ai?subject=Gate%20Implementation%20inquiry"
            style={{ ...s.cta, background: 'transparent', color: '#60A5FA', border: '1px solid rgba(96,165,250,0.32)' }}
          >
            Ask about Gate Implementation
          </a>
        </div>
      </div>
    </main>
  );
}
