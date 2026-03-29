'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 1120, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: 24, marginBottom: 24 },
  filterBar: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, flexWrap: 'wrap' },
  searchInput: { flex: 1, minWidth: 200, padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#020617', color: '#e8eaf0', fontSize: 13, fontFamily: "'IBM Plex Sans', sans-serif", outline: 'none' },
  select: { padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#020617', color: '#e8eaf0', fontSize: 13, fontFamily: "'IBM Plex Sans', sans-serif", outline: 'none', appearance: 'none', minWidth: 140 },
  btn: { padding: '10px 20px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: 'none', cursor: 'pointer', background: '#3B82F6', color: '#fff' },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  th: { padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1.5, textTransform: 'uppercase', borderBottom: '1px solid rgba(255,255,255,0.06)' },
  td: { padding: '12px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' },
  dot: (color) => ({ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block', marginRight: 8 }),
  typeBadge: (type) => {
    const map = {
      'handshake.completed': '#22C55E', 'handshake.initiated': '#3B82F6', 'policy.violation': '#f87171',
      'signoff.requested': '#22C55E', 'alert.triggered': '#f87171', 'audit.export': '#7a809a',
    };
    return map[type] || '#4a4f6a';
  },
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
};

const EVENT_TYPES = ['All Types', 'handshake.completed', 'handshake.initiated', 'policy.violation', 'signoff.requested', 'alert.triggered', 'audit.export'];

const MOCK_EVENTS = [
  { id: 'evt_f1a2b3', type: 'handshake.completed', handshake: 'hs_9f2a1b3c', tenant: 'acme-corp', details: 'AML/KYC verification passed all checks', timestamp: '2026-03-22T14:32:18Z' },
  { id: 'evt_c4d5e6', type: 'signoff.requested', handshake: 'hs_7e4d2a8f', tenant: 'globex-fin', details: 'SOX 404 controls require manual attestation', timestamp: '2026-03-22T12:15:44Z' },
  { id: 'evt_g7h8i9', type: 'policy.violation', handshake: 'hs_3c1b9e7d', tenant: 'initech-eu', details: 'GDPR consent record missing for data subject', timestamp: '2026-03-22T11:48:02Z' },
  { id: 'evt_j1k2l3', type: 'handshake.initiated', handshake: 'hs_8b4e2f1a', tenant: 'acme-corp', details: 'New handshake initiated for vendor onboarding', timestamp: '2026-03-22T10:22:30Z' },
  { id: 'evt_m4n5o6', type: 'alert.triggered', handshake: 'hs_1d6e4b9a', tenant: 'globex-fin', details: 'Sanctions screening match flagged for review', timestamp: '2026-03-22T09:55:11Z' },
  { id: 'evt_p7q8r9', type: 'audit.export', handshake: null, tenant: 'acme-corp', details: 'Evidence package generated for Q1 2026 audit', timestamp: '2026-03-22T08:30:00Z' },
  { id: 'evt_s1t2u3', type: 'handshake.completed', handshake: 'hs_6c9a3d7e', tenant: 'initech-eu', details: 'AI Act compliance trail verified', timestamp: '2026-03-21T17:45:22Z' },
  { id: 'evt_v4w5x6', type: 'policy.violation', handshake: 'hs_2e8d1f4a', tenant: 'globex-fin', details: 'Data residency constraint violated - APAC region', timestamp: '2026-03-21T15:12:09Z' },
];

export default function EventsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [events, setEvents] = useState([]);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('All Types');

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        await new Promise(r => setTimeout(r, 500));
        setEvents(MOCK_EVENTS);
      } catch (err) {
        setError('Failed to load events.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const filtered = events.filter(e => {
    const matchesType = typeFilter === 'All Types' || e.type === typeFilter;
    const matchesSearch = !search || e.details.toLowerCase().includes(search.toLowerCase()) ||
      e.id.toLowerCase().includes(search.toLowerCase()) ||
      (e.handshake && e.handshake.toLowerCase().includes(search.toLowerCase()));
    return matchesType && matchesSearch;
  });

  if (loading) return <div style={s.page}><div style={s.loading}>Loading events...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Events</div>
        <h1 style={s.h1}>Event Explorer</h1>
        <p style={s.subtitle}>Search and filter protocol events across all tenants and handshakes.</p>

        {error && <div style={s.error}>{error}</div>}

        <div style={s.filterBar}>
          <input
            style={s.searchInput}
            placeholder="Search events by ID, handshake, or description..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <select style={s.select} value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <button style={s.btn} onClick={() => { setSearch(''); setTypeFilter('All Types'); }}>Clear</button>
        </div>

        <div style={s.card}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={s.th}>Event ID</th>
                  <th style={s.th}>Type</th>
                  <th style={s.th}>Handshake</th>
                  <th style={s.th}>Tenant</th>
                  <th style={s.th}>Details</th>
                  <th style={s.th}>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(e => (
                  <tr key={e.id}>
                    <td style={{ ...s.td, ...s.mono, color: '#3B82F6' }}>{e.id}</td>
                    <td style={s.td}>
                      <span style={{ ...s.mono, color: s.typeBadge(e.type), display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <span style={s.dot(s.typeBadge(e.type))} />
                        {e.type}
                      </span>
                    </td>
                    <td style={{ ...s.td, ...s.mono, color: '#7a809a' }}>{e.handshake || '\u2014'}</td>
                    <td style={{ ...s.td, fontSize: 12 }}>{e.tenant}</td>
                    <td style={{ ...s.td, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.details}</td>
                    <td style={{ ...s.td, ...s.mono, color: '#4a4f6a', fontSize: 11, whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr><td colSpan={6} style={{ ...s.td, textAlign: 'center', color: '#4a4f6a', padding: 40 }}>No events match your filters.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ ...s.mono, color: '#4a4f6a', textAlign: 'right' }}>
          Showing {filtered.length} of {events.length} events
        </div>
      </div>
    </div>
  );
}
