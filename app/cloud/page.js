const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 800, margin: '0 auto', padding: '80px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 12 },
  h1: { fontSize: 36, fontWeight: 700, letterSpacing: -0.5, lineHeight: 1.2, marginBottom: 16 },
  sub: { fontSize: 16, color: '#94A3B8', lineHeight: 1.6, marginBottom: 40 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 48 },
  card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: 24 },
  cardTitle: { fontSize: 15, fontWeight: 600, color: '#F8FAFC', marginBottom: 8 },
  cardBody: { fontSize: 13, color: '#94A3B8', lineHeight: 1.6 },
  label: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: '#22C55E', marginBottom: 8 },
  section: { marginBottom: 48 },
  h2: { fontSize: 24, fontWeight: 700, marginBottom: 12 },
  body: { fontSize: 15, color: '#94A3B8', lineHeight: 1.7 },
  cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontSize: 14, fontWeight: 600, textDecoration: 'none', marginTop: 24 },
  divider: { height: 1, background: 'rgba(255,255,255,0.06)', margin: '48px 0' },
};

export const metadata = {
  title: 'EP Cloud — Managed Trust Control Plane',
  description: 'Managed policy registry, signoff orchestration, event explorer, audit exports, and tenant management above the open EP protocol.',
};

export default function CloudPage() {
  return (
    <div style={s.page}>
      <div style={s.container}>

        <div style={s.eyebrow}>EP Cloud</div>
        <h1 style={s.h1}>The managed control plane<br />above the open protocol</h1>
        <p style={s.sub}>
          The EP protocol is open. EP Cloud is the recurring revenue product layer that makes it operational:
          managed policy, verification, signoff orchestration, monitoring, evidence tooling, and tenant management.
        </p>

        <div style={s.grid}>
          <div style={s.card}>
            <div style={s.label}>Policy</div>
            <div style={s.cardTitle}>Managed policy registry</div>
            <div style={s.cardBody}>Version-controlled policies with hash snapshots. Rollout, rollback, and diff between versions. Policy simulation before deployment.</div>
          </div>
          <div style={s.card}>
            <div style={s.label}>Signoff</div>
            <div style={s.cardTitle}>Signoff orchestration</div>
            <div style={s.cardBody}>Challenge routing, notification delivery, approval queues, escalation timers, and SLA monitoring for accountable signoff workflows.</div>
          </div>
          <div style={s.card}>
            <div style={s.label}>Events</div>
            <div style={s.cardTitle}>Event explorer</div>
            <div style={s.cardBody}>Search, filter, and timeline every protocol event. Full-text search across handshakes, signoffs, and decisions with real-time streaming.</div>
          </div>
          <div style={s.card}>
            <div style={s.label}>Audit</div>
            <div style={s.cardTitle}>Audit exports</div>
            <div style={s.cardBody}>SOX-grade evidence packets. Per-action decision records, policy snapshots, signoff traces, and reconstruction-ready exports.</div>
          </div>
          <div style={s.card}>
            <div style={s.label}>Tenants</div>
            <div style={s.cardTitle}>Tenant management</div>
            <div style={s.cardBody}>Multi-tenant isolation with per-tenant policies, keys, quotas, and audit trails. Operator-level access controls.</div>
          </div>
          <div style={s.card}>
            <div style={s.label}>Alerts</div>
            <div style={s.cardTitle}>Alerting and webhooks</div>
            <div style={s.cardBody}>Configurable alerts on policy violations, signoff timeouts, consumption anomalies, and overload conditions. Webhook delivery with retry.</div>
          </div>
        </div>

        <div style={s.divider} />

        <div style={s.section}>
          <h2 style={s.h2}>Open protocol. Commercial control plane.</h2>
          <p style={s.body}>
            EP is a three-layer system. The protocol is open and forkable. The runtime is self-hostable.
            The cloud control plane is the managed product layer where recurring revenue lives.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginTop: 20 }}>
            <div style={{ padding: 16, border: '1px solid rgba(34,197,94,0.15)', borderRadius: 8, textAlign: 'center' }}>
              <div style={{ ...s.label, color: '#3B82F6' }}>Open</div>
              <div style={{ fontSize: 14, color: '#F8FAFC', fontWeight: 600 }}>Protocol + Runtime</div>
              <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 4 }}>Apache 2.0</div>
            </div>
            <div style={{ padding: 16, border: '1px solid rgba(34,197,94,0.3)', borderRadius: 8, textAlign: 'center', background: 'rgba(34,197,94,0.04)' }}>
              <div style={s.label}>Cloud</div>
              <div style={{ fontSize: 14, color: '#F8FAFC', fontWeight: 600 }}>Managed Control Plane</div>
              <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 4 }}>Per-tenant pricing</div>
            </div>
            <div style={{ padding: 16, border: '1px solid rgba(34,197,94,0.15)', borderRadius: 8, textAlign: 'center' }}>
              <div style={{ ...s.label, color: '#3B82F6' }}>Enterprise</div>
              <div style={{ fontSize: 14, color: '#F8FAFC', fontWeight: 600 }}>VPC + SSO + Residency</div>
              <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 4 }}>Custom deployment</div>
            </div>
          </div>
        </div>

        <div style={s.divider} />

        <div style={s.section}>
          <h2 style={s.h2}>Vertical packs</h2>
          <p style={s.body}>
            Sector-specific policy templates, compliance mappings, and audit formats for regulated industries.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginTop: 16 }}>
            <div style={{ padding: 12, border: '1px solid rgba(34,197,94,0.1)', borderRadius: 8 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#F8FAFC' }}>Government</div>
              <div style={{ fontSize: 12, color: '#94A3B8' }}>Payment integrity, benefit controls, GovGuard pre-execution gate</div>
            </div>
            <div style={{ padding: 12, border: '1px solid rgba(34,197,94,0.1)', borderRadius: 8 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#F8FAFC' }}>Financial</div>
              <div style={{ fontSize: 12, color: '#94A3B8' }}>Treasury controls, SOX evidence, wire fraud prevention</div>
            </div>
            <div style={{ padding: 12, border: '1px solid rgba(34,197,94,0.1)', borderRadius: 8 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#F8FAFC' }}>Agent Governance</div>
              <div style={{ fontSize: 12, color: '#94A3B8' }}>AI delegation authority, autonomous action control</div>
            </div>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: 48 }}>
          <a href="/partners" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>Request Cloud Access</a>
          <a href="/protocol" style={{ ...s.cta, background: 'transparent', color: '#22C55E', border: '1px solid rgba(34,197,94,0.3)', marginLeft: 12 }}>Read the Protocol</a>
        </div>

      </div>
    </div>
  );
}
