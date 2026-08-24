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

const slugify = (s: string) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 36);
const rand = () => Math.random().toString(36).slice(2, 6);

interface FieldProps {
  id: string;
  label: React.ReactNode;
  children: React.ReactNode;
  hint?: React.ReactNode;
}

function Field({ id, label, children, hint }: FieldProps) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label htmlFor={id} style={styles.label}>{label}</label>
      {children}
      {hint && <div id={`${id}-hint`} style={{ fontSize: 12, color: color.t3, marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

interface CopyRowProps {
  label: string;
  value: string;
}

function CopyRow({ label, value }: CopyRowProps) {
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

interface RegisteredEntity {
  id: string;
  entity_id: string;
  display_name: string;
  entity_type: string;
  confidence: string;
  status: string;
  created_at: string;
}

interface RegisterResult {
  entity: RegisteredEntity;
  api_key: string;
  owner_id: string;
  message: string;
  _note: string;
}

export default function SignupPage() {
  const [form, setForm] = useState({ display_name: '', description: '', entity_type: 'agent' });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RegisterResult | null>(null);
  const update = (k: string, v: string) => setForm((f) => ({ ...f, [k]: v }));

  async function register(entityId: string) {
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

  async function handleSubmit(e: React.FormEvent) {
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
        throw new Error((body as any).detail || (body as any).title || 'Registration failed. Try a different name.');
      }
      setResult(await res.json());
    } catch (err) {
      setError((err as Error).message);
    }
    setSubmitting(false);
  }

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main style={{ ...styles.section, maxWidth: 720, paddingTop: 110, paddingBottom: 80 }}>
        {!result ? (
          <>
            <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.goldDark, marginBottom: 20 }}>
              Experimental public registry sandbox
            </div>
            <h1 style={{ ...styles.h1, marginBottom: 12 }}>Create a nonproduction sandbox credential.</h1>
            <p style={{ ...styles.body, maxWidth: 560 }}>
              Register a test entity in the experimental public registry and receive a reference API
              credential. Use it to exercise development paths for authorization receipts, handshakes,
              and Gate calls. This is a rate-limited sandbox, not a production service, customer
              deployment, service-level commitment, or global authority network.
            </p>

            <form onSubmit={handleSubmit} style={{ ...styles.card, marginTop: 28 }}>
              <Field id="signup-name" label="Name" hint="Your test agent, app, or service. Becomes an experimental public registry handle.">
                <input id="signup-name" aria-describedby="signup-name-hint" className="ep-input" style={styles.input} value={form.display_name} onChange={(e) => update('display_name', e.target.value)} placeholder="Acme Invoice Agent" maxLength={200} />
              </Field>
              <Field id="signup-description" label="What is it?" hint="One line describing the test entity. Required.">
                <input id="signup-description" aria-describedby="signup-description-hint" className="ep-input" style={styles.input} value={form.description} onChange={(e) => update('description', e.target.value)} placeholder="Tests invoice actions against approved POs" />
              </Field>
              <Field id="signup-type" label="Type">
                <select id="signup-type" className="ep-input" style={styles.input} value={form.entity_type} onChange={(e) => update('entity_type', e.target.value)}>
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
                Experimental sandbox · rate-limited · no card · no production SLA. <Link href="/pricing" style={{ color: color.goldDark }}>See the current commercial boundary</Link>.
              </p>
            </form>
          </>
        ) : (
          <>
            <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.green, marginBottom: 20 }}>
              Experimental registration created
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
              <Link href="/explorer" className="ep-cta-ghost" style={cta.ghost}>Inspect the experimental registry →</Link>
            </div>
          </>
        )}
      </main>

      <SiteFooter />
    </div>
  );
}
