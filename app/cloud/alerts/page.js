'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 1120, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 },
  statCard: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '20px 24px' },
  statLabel: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: '#7a809a', marginBottom: 8 },
  statValue: { fontSize: 28, fontWeight: 700, letterSpacing: -1 },
  tabs: { display: 'flex', gap: 0, marginBottom: 24, borderBottom: '1px solid rgba(255,255,255,0.06)' },
  tab: (active) => ({ padding: '10px 20px', fontSize: 13, fontWeight: 500, color: active ? '#e8eaf0' : '#4a4f6a', background: 'none', border: 'none', borderBottom: active ? '2px solid #22C55E' : '2px solid transparent', cursor: 'pointer', fontFamily: "'IBM Plex Sans', sans-serif" }),
  card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: 24, marginBottom: 16 },
  alertCard: (severity) => {
    const borderMap = { critical: 'rgba(248,113,113,0.3)', high: 'rgba(248,113,113,0.15)', medium: 'rgba(34,197,94,0.15)', low: 'rgba(59,130,246,0.1)' };
    return { ...{ background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: 20, marginBottom: 12 }, borderLeft: `3px solid ${borderMap[severity] || 'rgba(255,255,255,0.06)'}` };
  },
  alertHeader: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 },
  alertTitle: { fontSize: 14, fontWeight: 600 },
  alertMeta: { display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 8 },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  badge: (bg, fg) => ({ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, letterSpacing: 0.5, padding: '3px 8px', borderRadius: 4, background: bg, color: fg }),
  btnSmall: { padding: '6px 14px', borderRadius: 6, fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: '1px solid rgba(59,130,246,0.3)', cursor: 'pointer', background: 'transparent', color: '#3B82F6' },
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
};

const MOCK_ALERTS = [
  { id: 'alrt_01', title: 'Sanctions screening match detected', severity: 'critical', status: 'active', tenant: 'globex-fin', handshake: 'hs_1d6e4b9a', policy: 'sanctions-screen', message: 'Entity match found against OFAC SDN list during vendor onboarding handshake.', triggered: '2026-03-22T09:55:11Z' },
  { id: 'alrt_02', title: 'GDPR consent record missing', severity: 'high', status: 'active', tenant: 'initech-eu', handshake: 'hs_3c1b9e7d', policy: 'gdpr-consent-v2', message: 'Data subject consent not recorded before processing. Policy violation flagged.', triggered: '2026-03-22T11:48:02Z' },
  { id: 'alrt_03', title: 'Audit ledger latency elevated', severity: 'medium', status: 'active', tenant: null, handshake: null, policy: null, message: 'Audit ledger write latency exceeding 200ms threshold for 15 minutes.', triggered: '2026-03-22T13:20:00Z' },
  { id: 'alrt_04', title: 'Signoff challenge expired', severity: 'low', status: 'acknowledged', tenant: 'globex-fin', handshake: 'hs_1d6e4b9a', policy: 'sanctions-screen', message: 'Signoff challenge sig_e2f9a6 expired without attestation.', triggered: '2026-03-19T10:00:00Z' },
  { id: 'alrt_05', title: 'Data residency constraint violated', severity: 'high', status: 'resolved', tenant: 'globex-fin', handshake: 'hs_2e8d1f4a', policy: 'data-residency', message: 'Handshake data routed through APAC region, violating EU residency constraint.', triggered: '2026-03-21T15:12:09Z' },
];

const sevColor = { critical: '#f87171', high: '#fb923c', medium: '#22C55E', low: '#3B82F6' };
const sevBadge = (sev) => <span style={s.badge(`${sevColor[sev]}18`, sevColor[sev])}>{sev}</span>;
const statusBadge = (st) => {
  const map = { active: ['rgba(248,113,113,0.1)', '#f87171'], acknowledged: ['rgba(34,197,94,0.1)', '#22C55E'], resolved: ['rgba(0,255,136,0.1)', '#22C55E'] };
  const [bg, fg] = map[st] || ['rgba(122,128,154,0.1)', '#7a809a'];
  return <span style={s.badge(bg, fg)}>{st}</span>;
};

export default function AlertsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [activeTab, setActiveTab] = useState('active');

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        await new Promise(r => setTimeout(r, 500));
        setAlerts(MOCK_ALERTS);
      } catch (err) {
        setError('Failed to load alerts.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const counts = {
    active: alerts.filter(a => a.status === 'active').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved: alerts.filter(a => a.status === 'resolved').length,
  };

  const filtered = activeTab === 'all' ? alerts : alerts.filter(a => a.status === activeTab);

  if (loading) return <div style={s.page}><div style={s.loading}>Loading alerts...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Alerts</div>
        <h1 style={s.h1}>Alert Center</h1>
        <p style={s.subtitle}>Monitor policy violations, system alerts, and escalations.</p>

        {error && <div style={s.error}>{error}</div>}

        <div style={s.grid}>
          <div style={s.statCard}>
            <div style={s.statLabel}>Active</div>
            <div style={{ ...s.statValue, color: '#f87171' }}>{counts.active}</div>
          </div>
          <div style={s.statCard}>
            <div style={s.statLabel}>Acknowledged</div>
            <div style={{ ...s.statValue, color: '#22C55E' }}>{counts.acknowledged}</div>
          </div>
          <div style={s.statCard}>
            <div style={s.statLabel}>Resolved (7d)</div>
            <div style={{ ...s.statValue, color: '#22C55E' }}>{counts.resolved}</div>
          </div>
          <div style={s.statCard}>
            <div style={s.statLabel}>Total</div>
            <div style={{ ...s.statValue, color: '#e8eaf0' }}>{alerts.length}</div>
          </div>
        </div>

        <div style={s.tabs}>
          {['active', 'acknowledged', 'resolved', 'all'].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} style={s.tab(activeTab === tab)}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {filtered.map(a => (
          <div key={a.id} style={s.alertCard(a.severity)}>
            <div style={s.alertHeader}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={s.alertTitle}>{a.title}</span>
                {sevBadge(a.severity)}
                {statusBadge(a.status)}
              </div>
              <span style={{ ...s.mono, color: '#4a4f6a', fontSize: 11 }}>{new Date(a.triggered).toLocaleString()}</span>
            </div>
            <p style={{ fontSize: 13, color: '#9ca3af', margin: '8px 0 0', lineHeight: 1.5 }}>{a.message}</p>
            <div style={s.alertMeta}>
              {a.tenant && <span style={{ ...s.mono, color: '#7a809a' }}>Tenant: {a.tenant}</span>}
              {a.handshake && <span style={{ ...s.mono, color: '#3B82F6' }}>HS: {a.handshake}</span>}
              {a.policy && <span style={{ ...s.mono, color: '#22C55E' }}>Policy: {a.policy}</span>}
            </div>
            {a.status === 'active' && (
              <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                <button style={s.btnSmall}>Acknowledge</button>
                <button style={{ ...s.btnSmall, borderColor: 'rgba(0,255,136,0.3)', color: '#22C55E' }}>Resolve</button>
              </div>
            )}
          </div>
        ))}

        {filtered.length === 0 && (
          <div style={{ ...s.card, textAlign: 'center', color: '#4a4f6a', padding: 40 }}>No alerts in this category.</div>
        )}
      </div>
    </div>
  );
}
