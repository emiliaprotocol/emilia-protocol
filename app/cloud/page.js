'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#0a0f1e', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 1120, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#d4af55', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 },
  statCard: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: '20px 24px' },
  statLabel: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: '#7a809a', marginBottom: 8 },
  statValue: { fontSize: 32, fontWeight: 700, letterSpacing: -1 },
  card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: 24, marginBottom: 24 },
  cardTitle: { fontSize: 15, fontWeight: 600, marginBottom: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  th: { padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1.5, textTransform: 'uppercase', borderBottom: '1px solid rgba(255,255,255,0.06)' },
  td: { padding: '10px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)' },
  dot: (color) => ({ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block', marginRight: 8 }),
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
};

const MOCK_STATS = { handshakes: 14832, policies: 47, tenants: 12, uptime: 99.97 };

const MOCK_ACTIVITY = [
  { id: 'hs_9f2a1b3c', event: 'Handshake completed', policy: 'aml-kyc-v3', tenant: 'acme-corp', time: '2 min ago', status: 'success' },
  { id: 'hs_7e4d2a8f', event: 'Signoff requested', policy: 'sox-404-controls', tenant: 'globex-fin', time: '8 min ago', status: 'pending' },
  { id: 'hs_3c1b9e7d', event: 'Policy violation detected', policy: 'gdpr-consent-v2', tenant: 'initech-eu', time: '14 min ago', status: 'alert' },
  { id: 'hs_5a8f3c2e', event: 'Audit export generated', policy: 'ai-act-trail', tenant: 'acme-corp', time: '22 min ago', status: 'success' },
  { id: 'hs_1d6e4b9a', event: 'Escalation triggered', policy: 'sanctions-screen', tenant: 'globex-fin', time: '31 min ago', status: 'alert' },
];

const MOCK_HEALTH = [
  { service: 'Policy Engine', status: 'operational', latency: '12ms', uptime: '99.99%' },
  { service: 'Signoff Pipeline', status: 'operational', latency: '45ms', uptime: '99.95%' },
  { service: 'Event Ingestion', status: 'operational', latency: '8ms', uptime: '99.98%' },
  { service: 'Audit Ledger', status: 'degraded', latency: '230ms', uptime: '99.82%' },
  { service: 'Alert Router', status: 'operational', latency: '18ms', uptime: '99.97%' },
];

const statusColor = { success: '#3b9b6e', pending: '#d4af55', alert: '#f87171' };
const healthColor = { operational: '#3b9b6e', degraded: '#d4af55', down: '#f87171' };

export default function CloudDashboardPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState(null);
  const [activity, setActivity] = useState([]);
  const [health, setHealth] = useState([]);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        // In production these would be API calls; using mock data for now
        await new Promise(r => setTimeout(r, 600));
        setStats(MOCK_STATS);
        setActivity(MOCK_ACTIVITY);
        setHealth(MOCK_HEALTH);
      } catch (err) {
        setError('Failed to load dashboard data. Check your connection and permissions.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  if (loading) return <div style={s.page}><div style={s.loading}>Loading dashboard...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Dashboard</div>
        <h1 style={s.h1}>Overview</h1>
        <p style={s.subtitle}>Real-time operational view of your Emilia Protocol Cloud deployment.</p>

        {error && <div style={s.error}>{error}</div>}

        {stats && (
          <div style={s.grid}>
            <div style={s.statCard}>
              <div style={s.statLabel}>Total Handshakes</div>
              <div style={{ ...s.statValue, color: '#4a90d9' }}>{stats.handshakes.toLocaleString()}</div>
            </div>
            <div style={s.statCard}>
              <div style={s.statLabel}>Active Policies</div>
              <div style={{ ...s.statValue, color: '#d4af55' }}>{stats.policies}</div>
            </div>
            <div style={s.statCard}>
              <div style={s.statLabel}>Tenants</div>
              <div style={{ ...s.statValue, color: '#e8eaf0' }}>{stats.tenants}</div>
            </div>
            <div style={s.statCard}>
              <div style={s.statLabel}>Uptime</div>
              <div style={{ ...s.statValue, color: '#3b9b6e' }}>{stats.uptime}%</div>
            </div>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
          <div style={s.card}>
            <div style={s.cardTitle}>
              <span>Recent Activity</span>
              <a href="/cloud/events" style={{ ...s.mono, color: '#4a90d9', textDecoration: 'none' }}>View all</a>
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={s.th}>ID</th>
                  <th style={s.th}>Event</th>
                  <th style={s.th}>Policy</th>
                  <th style={s.th}>Time</th>
                </tr>
              </thead>
              <tbody>
                {activity.map(a => (
                  <tr key={a.id}>
                    <td style={{ ...s.td, ...s.mono, color: '#4a90d9' }}>{a.id}</td>
                    <td style={s.td}>
                      <span style={s.dot(statusColor[a.status])} />
                      {a.event}
                    </td>
                    <td style={{ ...s.td, ...s.mono, color: '#7a809a' }}>{a.policy}</td>
                    <td style={{ ...s.td, ...s.mono, color: '#4a4f6a', fontSize: 11 }}>{a.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={s.card}>
            <div style={s.cardTitle}>Service Health</div>
            {health.map(h => (
              <div key={h.service} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={s.dot(healthColor[h.status])} />
                  <span style={{ fontSize: 13 }}>{h.service}</span>
                </div>
                <span style={{ ...s.mono, color: '#4a4f6a' }}>{h.latency}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
