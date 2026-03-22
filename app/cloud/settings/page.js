'use client';

import { useState, useEffect } from 'react';

const s = {
  page: { minHeight: '100vh', background: '#0a0f1e', color: '#e8eaf0', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  container: { maxWidth: 900, margin: '0 auto', padding: '40px 24px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#d4af55', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.5, marginBottom: 8, color: '#e8eaf0' },
  subtitle: { fontSize: 14, color: '#7a809a', marginBottom: 32 },
  card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: 24, marginBottom: 24 },
  cardTitle: { fontSize: 16, fontWeight: 600, marginBottom: 4 },
  cardDesc: { fontSize: 13, color: '#7a809a', marginBottom: 20 },
  fieldGroup: { marginBottom: 20 },
  label: { display: 'block', fontSize: 11, fontWeight: 600, color: '#7a809a', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1, textTransform: 'uppercase' },
  input: { width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0a0f1e', color: '#e8eaf0', fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif", outline: 'none', boxSizing: 'border-box' },
  select: { width: '100%', padding: '10px 14px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0a0f1e', color: '#e8eaf0', fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif", outline: 'none', boxSizing: 'border-box', appearance: 'none' },
  toggle: (on) => ({ width: 44, height: 24, borderRadius: 12, background: on ? '#4a90d9' : '#1f2937', border: 'none', cursor: 'pointer', position: 'relative', transition: 'background 0.2s', flexShrink: 0 }),
  toggleDot: (on) => ({ width: 18, height: 18, borderRadius: '50%', background: '#e8eaf0', position: 'absolute', top: 3, left: on ? 23 : 3, transition: 'left 0.2s' }),
  row: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' },
  rowLabel: { fontSize: 14 },
  rowDesc: { fontSize: 12, color: '#7a809a', marginTop: 2 },
  btn: { padding: '10px 24px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: 'none', cursor: 'pointer', background: '#d4af55', color: '#0a0f1e' },
  btnDanger: { padding: '10px 24px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', border: '1px solid rgba(248,113,113,0.3)', cursor: 'pointer', background: 'transparent', color: '#f87171' },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  loading: { textAlign: 'center', padding: 60, color: '#4a4f6a', fontFamily: "'IBM Plex Mono', monospace", fontSize: 13 },
  error: { background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', borderRadius: 8, padding: '12px 16px', color: '#f87171', fontSize: 13, marginBottom: 24 },
  success: { background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.15)', borderRadius: 8, padding: '12px 16px', color: '#00ff88', fontSize: 13, marginBottom: 24 },
};

export default function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);

  const [config, setConfig] = useState({
    orgName: '',
    contactEmail: '',
    defaultRegion: 'us-east-1',
    retentionDays: '365',
    webhookUrl: '',
    emailAlerts: true,
    slackAlerts: false,
    autoEscalate: true,
    enforceSignoffs: true,
    auditLogging: true,
    mfaRequired: true,
  });

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        await new Promise(r => setTimeout(r, 500));
        setConfig(prev => ({
          ...prev,
          orgName: 'Acme Corp',
          contactEmail: 'admin@acme-corp.com',
          webhookUrl: 'https://hooks.acme-corp.com/ep-alerts',
        }));
      } catch (err) {
        setError('Failed to load settings.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const handleSave = async () => {
    setSaved(false);
    setError(null);
    await new Promise(r => setTimeout(r, 800));
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const update = (key, value) => setConfig(prev => ({ ...prev, [key]: value }));

  const Toggle = ({ value, onToggle }) => (
    <button style={s.toggle(value)} onClick={onToggle} type="button">
      <span style={s.toggleDot(value)} />
    </button>
  );

  if (loading) return <div style={s.page}><div style={s.loading}>Loading settings...</div></div>;

  return (
    <div style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>Cloud / Settings</div>
        <h1 style={s.h1}>Configuration</h1>
        <p style={s.subtitle}>Manage your EP Cloud deployment settings and preferences.</p>

        {error && <div style={s.error}>{error}</div>}
        {saved && <div style={s.success}>Settings saved successfully.</div>}

        <div style={s.card}>
          <div style={s.cardTitle}>Organization</div>
          <div style={s.cardDesc}>Basic organization and deployment configuration.</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={s.fieldGroup}>
              <label style={s.label}>Organization Name</label>
              <input style={s.input} value={config.orgName} onChange={e => update('orgName', e.target.value)} />
            </div>
            <div style={s.fieldGroup}>
              <label style={s.label}>Contact Email</label>
              <input style={s.input} type="email" value={config.contactEmail} onChange={e => update('contactEmail', e.target.value)} />
            </div>
            <div style={s.fieldGroup}>
              <label style={s.label}>Default Region</label>
              <select style={s.select} value={config.defaultRegion} onChange={e => update('defaultRegion', e.target.value)}>
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU West (Ireland)</option>
                <option value="eu-central-1">EU Central (Frankfurt)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
              </select>
            </div>
            <div style={s.fieldGroup}>
              <label style={s.label}>Data Retention (Days)</label>
              <input style={s.input} type="number" value={config.retentionDays} onChange={e => update('retentionDays', e.target.value)} />
            </div>
          </div>
        </div>

        <div style={s.card}>
          <div style={s.cardTitle}>Notifications</div>
          <div style={s.cardDesc}>Configure alert delivery channels and webhook integrations.</div>
          <div style={s.fieldGroup}>
            <label style={s.label}>Webhook URL</label>
            <input style={s.input} placeholder="https://hooks.example.com/ep-alerts" value={config.webhookUrl} onChange={e => update('webhookUrl', e.target.value)} />
          </div>
          <div style={s.row}>
            <div>
              <div style={s.rowLabel}>Email alerts</div>
              <div style={s.rowDesc}>Send alert notifications via email</div>
            </div>
            <Toggle value={config.emailAlerts} onToggle={() => update('emailAlerts', !config.emailAlerts)} />
          </div>
          <div style={s.row}>
            <div>
              <div style={s.rowLabel}>Slack integration</div>
              <div style={s.rowDesc}>Push alerts to a Slack channel</div>
            </div>
            <Toggle value={config.slackAlerts} onToggle={() => update('slackAlerts', !config.slackAlerts)} />
          </div>
          <div style={{ ...s.row, borderBottom: 'none' }}>
            <div>
              <div style={s.rowLabel}>Auto-escalate critical alerts</div>
              <div style={s.rowDesc}>Automatically escalate unacknowledged critical alerts after 30 minutes</div>
            </div>
            <Toggle value={config.autoEscalate} onToggle={() => update('autoEscalate', !config.autoEscalate)} />
          </div>
        </div>

        <div style={s.card}>
          <div style={s.cardTitle}>Security &amp; Compliance</div>
          <div style={s.cardDesc}>Enforcement and audit settings for your deployment.</div>
          <div style={s.row}>
            <div>
              <div style={s.rowLabel}>Require signoffs on all handshakes</div>
              <div style={s.rowDesc}>Enforce manual attestation before handshake completion</div>
            </div>
            <Toggle value={config.enforceSignoffs} onToggle={() => update('enforceSignoffs', !config.enforceSignoffs)} />
          </div>
          <div style={s.row}>
            <div>
              <div style={s.rowLabel}>Audit logging</div>
              <div style={s.rowDesc}>Write all operations to tamper-evident audit ledger</div>
            </div>
            <Toggle value={config.auditLogging} onToggle={() => update('auditLogging', !config.auditLogging)} />
          </div>
          <div style={{ ...s.row, borderBottom: 'none' }}>
            <div>
              <div style={s.rowLabel}>Require MFA for cloud access</div>
              <div style={s.rowDesc}>Enforce multi-factor authentication for all cloud dashboard users</div>
            </div>
            <Toggle value={config.mfaRequired} onToggle={() => update('mfaRequired', !config.mfaRequired)} />
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <button style={s.btnDanger}>Reset to Defaults</button>
          <button style={s.btn} onClick={handleSave}>Save Changes</button>
        </div>
      </div>
    </div>
  );
}
