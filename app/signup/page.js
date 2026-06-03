'use client';

import Link from 'next/link';
import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const TYPES = [
  ['agent', 'AI agent'],
  ['mcp_server', 'MCP server'],
  ['service_provider', 'Service / app'],
  ['npm_package', 'npm package'],
];

const slugify = (s) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 36);
const rand = () => Math.random().toString(36).slice(2, 6);

function Field({ label, children, hint }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={styles.label}>{label}</label>
      {children}
      {hint && <div style={{ fontSize: 12, color: color.t3, marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

function CopyRow({ label, value }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: color.t3, marginBottom: 6 }}>{label}</div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
        <code style={{ flex: 1, fontFamily: font.mono, fontSize: 12.5, background: '#1C1917', color: '#D6D3D1', padding: '12px 14px', borderRadius: radius.sm, overflowX: 'auto', whiteSpace: 'nowrap' }}>{value}</code>
        <button onClick={copy} className="ep-cta-secondary" style={{ ...cta.secondary, padding: '0 16px' }}>{copied ? 'Copied' : 'Copy'}</button>
      </div>
    </div>
  );
}

export default function SignupPage() {
  const [form, setForm] = useState({ display_name: '', description: '', entity_type: 'agent' });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const update = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  async function register(entityId) {
    const res = await fetch('/api/entities/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        entity_id: entityId,
        display_name: form.display_name.trim(),
        entity_type: form.entity_type,
        description: form.description.trim(),
      }),
    });
    return res;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const base = slugify(form.display_name) || 'agent';
      let res = await register(`${base}-${rand()}`);
      if (res.status === 400) {
        // Most likely a handle collision — retry once with a fresh suffix.
        res = await register(`${base}-${rand()}${rand()}`);
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || body.title || 'Registration failed. Try a different name.');
      }
      setResult(await res.json());
    } catch (err) {
      setError(err.message);
    }
    setSubmitting(false);
  }

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, maxWidth: 720, paddingTop: 110, paddingBottom: 80 }}>
        {!result ? (
          <>
            <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 20 }}>
              Start free
            </div>
            <h1 style={{ ...styles.h1, marginBottom: 12 }}>Get a sandbox API key in 30 seconds.</h1>
            <p style={{ ...styles.body, maxWidth: 560 }}>
              Register an entity on the live network and get a real EMILIA API key &mdash; no credit
              card, no sales call. Free sandbox tier. Use it to issue Trust Receipts, run handshakes,
              and call the gate from your agent.
            </p>

            <form onSubmit={handleSubmit} style={{ ...styles.card, marginTop: 28 }}>
              <Field label="Name" hint="Your agent, app, or service. Becomes your public entity handle.">
                <input className="ep-input" style={styles.input} value={form.display_name} onChange={(e) => update('display_name', e.target.value)} placeholder="Acme Invoice Agent" maxLength={200} />
              </Field>
              <Field label="What is it?" hint="One line — what it does. Required.">
                <input className="ep-input" style={styles.input} value={form.description} onChange={(e) => update('description', e.target.value)} placeholder="Pays vendor invoices from approved POs" />
              </Field>
              <Field label="Type">
                <select className="ep-input" style={styles.input} value={form.entity_type} onChange={(e) => update('entity_type', e.target.value)}>
                  {TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </Field>
              {error && <p style={{ color: color.red, fontSize: 13, margin: '4px 0 14px' }}>{error}</p>}
              <button
                type="submit"
                className="ep-cta"
                disabled={submitting || !form.display_name.trim() || !form.description.trim()}
                style={{ ...((!form.display_name.trim() || !form.description.trim()) ? cta.disabled : cta.primary), width: '100%', justifyContent: 'center' }}
              >
                {submitting ? 'Creating your key…' : 'Create my sandbox key →'}
              </button>
              <p style={{ fontSize: 12, color: color.t3, marginTop: 14, textAlign: 'center' }}>
                Free sandbox · rate-limited · no card. Need scale or SLAs? <Link href="/pricing" style={{ color: color.gold }}>See pricing</Link>.
              </p>
            </form>
          </>
        ) : (
          <>
            <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.green, marginBottom: 20 }}>
              You&rsquo;re on the network
            </div>
            <h1 style={{ ...styles.h1, marginBottom: 12 }}>Save your key &mdash; it&rsquo;s shown once.</h1>
            <p style={{ ...styles.body, maxWidth: 560 }}>
              <strong style={{ color: color.t1 }}>{result.entity?.display_name}</strong> is registered as{' '}
              <code style={{ fontFamily: font.mono, fontSize: 13, color: color.t1 }}>{result.entity?.entity_id}</code>. Copy these now and store them in your secret manager.
            </p>
            <div style={{ ...styles.card, marginTop: 24, borderColor: color.gold }}>
              <CopyRow label="API key (shown once)" value={result.api_key} />
              <CopyRow label="Owner ID" value={result.owner_id} />
              <p style={{ fontSize: 12.5, color: color.t2, lineHeight: 1.6, margin: '4px 0 0' }}>
                These won&rsquo;t be shown again. Treat the API key like a password. Establish durable
                ownership with <code style={{ fontFamily: font.mono, fontSize: 12 }}>POST /api/identity/bind</code>.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
              <Link href="/docs" className="ep-cta" style={cta.primary}>Read the quickstart →</Link>
              <Link href="/agent-guard" className="ep-cta-secondary" style={cta.secondary}>Guard an agent</Link>
              <Link href="/explorer" className="ep-cta-ghost" style={cta.ghost}>Find yourself on the network →</Link>
            </div>
          </>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
