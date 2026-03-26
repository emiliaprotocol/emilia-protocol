'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 1120, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  topBar: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24, gap: 12 },
  searchInput: { flex: 1, maxWidth: 360, padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#020617', color: '#e8eaf0', fontSize: 13, fontFamily: "'IBM Plex Sans', sans-serif", outline: 'none' },
  btn: { padding: '10px 20px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: 'none', cursor: 'pointer', background: '#22C55E', color: '#020617' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340, 1fr))', gap: 20 },
  card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: 24 },
  cardHeader: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 },
  tenantName: { fontSize: 16, fontWeight: 600 },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  row: { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' },
  rowLabel: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#4a4f6a', letterSpacing: 0.5, textTransform: 'uppercase' },
  rowValue: { fontSize: 13 },
  badge: (bg, fg) => ({ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 0.5, padding: '3px 8px', borderRadius: 4, background: bg, color: fg }),
  dot: (color) => ({ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block', marginRight: 8 }),
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
};

const MOCK_TENANTS = [
  { id: 'ten_acme', name: 'Acme Corp', slug: 'acme-corp', plan: 'enterprise', status: 'active', region: 'us-east-1', handshakes: 6234, policies: 12, members: 24, created: '2025-08-15T00:00:00Z' },
  { id: 'ten_globex', name: 'Globex Financial', slug: 'globex-fin', plan: 'enterprise', status: 'active', region: 'eu-west-1', handshakes: 4102, policies: 8, members: 18, created: '2025-10-01T00:00:00Z' },
  { id: 'ten_initech', name: 'Initech EU', slug: 'initech-eu', plan: 'business', status: 'active', region: 'eu-central-1', handshakes: 2891, policies: 6, members: 11, created: '2025-11-20T00:00:00Z' },
  { id: 'ten_umbrella', name: 'Umbrella Health', slug: 'umbrella-health', plan: 'business', status: 'suspended', region: 'us-west-2', handshakes: 890, policies: 4, members: 7, created: '2026-01-10T00:00:00Z' },
  { id: 'ten_wayne', name: 'Wayne Industries', slug: 'wayne-ind', plan: 'enterprise', status: 'active', region: 'us-east-1', handshakes: 1456, policies: 9, members: 32, created: '2026-02-05T00:00:00Z' },
];

const statusColor = { active: '#22C55E', suspended: '#f87171', pending: '#22C55E' };
const planBadge = (plan) => {
  const map = { enterprise: ['rgba(34,197,94,0.1)', '#22C55E'], business: ['rgba(59,130,246,0.1)', '#3B82F6'] };
  const [bg, fg] = map[plan] || ['rgba(122,128,154,0.1)', '#7a809a'];
  return <span style={s.badge(bg, fg)}>{plan}</span>;
};

export default function TenantsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tenants, setTenants] = useState([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        await new Promise(r => setTimeout(r, 500));
        setTenants(MOCK_TENANTS);
      } catch (err) {
        setError('Failed to load tenants.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const filtered = tenants.filter(t =>
    t.name.toLowerCase().includes(search.toLowerCase()) ||
    t.slug.toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <div style={s.page}><div style={s.loading}>Loading tenants...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Tenants</div>
        <h1 style={s.h1}>Tenant Management</h1>
        <p style={s.subtitle}>View and manage organizations using your EP Cloud deployment.</p>

        {error && <div style={s.error}>{error}</div>}

        <div style={s.topBar}>
          <input
            style={s.searchInput}
            placeholder="Search tenants..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <button style={s.btn}>+ Add Tenant</button>
        </div>

        <div style={s.grid}>
          {filtered.map(t => (
            <div key={t.id} style={s.card}>
              <div style={s.cardHeader}>
                <div>
                  <div style={s.tenantName}>{t.name}</div>
                  <div style={{ ...s.mono, color: '#4a4f6a', marginTop: 4 }}>{t.slug}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={s.dot(statusColor[t.status])} />
                  {planBadge(t.plan)}
                </div>
              </div>
              <div style={s.row}>
                <span style={s.rowLabel}>Region</span>
                <span style={{ ...s.mono, color: '#7a809a' }}>{t.region}</span>
              </div>
              <div style={s.row}>
                <span style={s.rowLabel}>Handshakes</span>
                <span style={s.rowValue}>{t.handshakes.toLocaleString()}</span>
              </div>
              <div style={s.row}>
                <span style={s.rowLabel}>Policies</span>
                <span style={s.rowValue}>{t.policies}</span>
              </div>
              <div style={s.row}>
                <span style={s.rowLabel}>Members</span>
                <span style={s.rowValue}>{t.members}</span>
              </div>
              <div style={{ ...s.row, borderBottom: 'none' }}>
                <span style={s.rowLabel}>Created</span>
                <span style={{ ...s.mono, color: '#4a4f6a', fontSize: 11 }}>{new Date(t.created).toLocaleDateString()}</span>
              </div>
            </div>
          ))}
          {filtered.length === 0 && (
            <div style={{ ...s.card, textAlign: 'center', color: '#4a4f6a', padding: 40, gridColumn: '1 / -1' }}>No tenants match your search.</div>
          )}
        </div>
      </div>
    </div>
  );
}
