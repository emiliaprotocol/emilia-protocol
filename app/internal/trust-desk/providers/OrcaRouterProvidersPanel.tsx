'use client';

// SPDX-License-Identifier: Apache-2.0
//
// OrcaRouter Cyber Inference provider settings.
//
// Two explicit authentication choices, one credential seam:
//   * API key  — paste an existing sk-orca-… key;
//   * Connect  — OAuth 2.0 + PKCE, out-of-band code (Flow B).
//
// The model control is a selector built only from the server-side catalogue;
// there is no free-text model field. Every async login response carries the
// attempt generation it started under, so a late response from an abandoned
// attempt can never overwrite a newer credential or hint. `pagehide` clears
// busy/hint synchronously and sends a keepalive cancellation, because a
// bfcache restore would otherwise come back permanently busy.

import { useCallback, useEffect, useRef, useState } from 'react';
import { requestOrcaCancellation } from './orcarouter-cancellation';

type Credential = {
  configured: boolean;
  source: 'env' | 'api_key' | 'pkce' | null;
  masked: string | null;
  needs_reauth: boolean;
  scope: string | null;
  updated_at: string | null;
  generation: string | null;
  error: string | null;
};

type Model = {
  id: string;
  name: string;
  context_length: number | null;
  input_modalities: string[];
  endpoint_types: string[];
  verified_seed?: boolean;
};

type Status = {
  provider: string;
  display_name: string;
  credential: Credential;
  origins: { auth: string; api: string };
  models: { default: string; cyber: string[]; fallback: string; selected: string; selections?: Record<string, string | null> };
  catalog_source: string;
  docs: { provider_page: string; cyber_models: string };
};

type Catalog = {
  capability: string;
  modality: string;
  source: 'live' | 'seed' | 'last-known-good';
  degraded: boolean;
  error: string | null;
  catalog_source: string;
  count: number;
  models: Model[];
};

type Connect = {
  attempt_id: string;
  authorize_url: string;
  expires_at: string;
};

const sourceLabel: Record<string, string> = {
  env: 'Environment (ORCAROUTER_API_KEY)',
  api_key: 'Saved API key',
  pkce: 'OrcaRouter account (OAuth 2.0 + PKCE)',
};

const s: Record<string, any> = {
  page: { minHeight: '100vh', background: '#fafaf9', color: '#1c1917' },
  container: { maxWidth: 1040, margin: '0 auto', padding: '40px 24px 64px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#78716c', marginBottom: 8 },
  h1: { fontSize: 28, fontWeight: 700, letterSpacing: -0.4, margin: '0 0 8px' },
  subtitle: { fontSize: 14, color: '#57534e', margin: '0 0 28px', maxWidth: 760, lineHeight: 1.6 },
  card: { background: '#ffffff', border: '1px solid #e7e5e4', borderRadius: 10, padding: 24, marginBottom: 20, boxShadow: '0 1px 2px rgba(28,25,23,0.04)' },
  cardTitle: { fontSize: 16, fontWeight: 650, margin: '0 0 4px', display: 'flex', alignItems: 'center', gap: 10 },
  cardDesc: { fontSize: 13, color: '#78716c', margin: '0 0 18px', lineHeight: 1.55 },
  row: { display: 'flex', flexWrap: 'wrap', gap: 16 },
  half: { flex: '1 1 320px', border: '1px solid #e7e5e4', borderRadius: 8, padding: 18, background: '#fcfcfb' },
  halfTitle: { fontSize: 13, fontWeight: 700, margin: '0 0 4px' },
  halfDesc: { fontSize: 12, color: '#78716c', margin: '0 0 12px', lineHeight: 1.5 },
  label: { display: 'block', fontSize: 11, fontWeight: 650, color: '#78716c', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 1, textTransform: 'uppercase' },
  input: { width: '100%', boxSizing: 'border-box', padding: '10px 12px', borderRadius: 6, border: '1px solid #d6d3d1', background: '#fff', color: '#1c1917', fontSize: 14, fontFamily: "'IBM Plex Mono', monospace" },
  select: { width: '100%', boxSizing: 'border-box', padding: '10px 12px', borderRadius: 6, border: '1px solid #d6d3d1', background: '#fff', color: '#1c1917', fontSize: 14 },
  btn: { padding: '9px 16px', borderRadius: 6, border: '1px solid #1c1917', background: '#1c1917', color: '#fff', fontSize: 13, fontWeight: 650, cursor: 'pointer' },
  btnGhost: { padding: '9px 16px', borderRadius: 6, border: '1px solid #d6d3d1', background: '#fff', color: '#1c1917', fontSize: 13, fontWeight: 650, cursor: 'pointer' },
  btnDanger: { padding: '9px 16px', borderRadius: 6, border: '1px solid #fca5a5', background: '#fff', color: '#b91c1c', fontSize: 13, fontWeight: 650, cursor: 'pointer' },
  btnDisabled: { opacity: 0.55, cursor: 'not-allowed' },
  statusLine: { display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', fontSize: 13, margin: '0 0 16px' },
  badge: { display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 9px', borderRadius: 999, fontSize: 11, fontWeight: 700, letterSpacing: 0.4, textTransform: 'uppercase' },
  mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 },
  alert: { background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', borderRadius: 8, padding: '10px 14px', fontSize: 13, margin: '0 0 16px' },
  notice: { background: '#eff6ff', border: '1px solid #bfdbfe', color: '#1e3a8a', borderRadius: 8, padding: '10px 14px', fontSize: 13, margin: '0 0 16px', lineHeight: 1.5 },
  success: { background: '#f0fdf4', border: '1px solid #bbf7d0', color: '#166534', borderRadius: 8, padding: '10px 14px', fontSize: 13, margin: '0 0 16px' },
  urlBox: { wordBreak: 'break-all', background: '#f5f5f4', border: '1px solid #e7e5e4', borderRadius: 6, padding: '10px 12px', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, lineHeight: 1.5, margin: '0 0 12px' },
  dropdownWrap: { position: 'relative', marginTop: 6 },
  trigger: { width: '100%', boxSizing: 'border-box', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '10px 12px', borderRadius: 6, border: '1px solid #d6d3d1', background: '#fff', color: '#1c1917', fontSize: 14, cursor: 'pointer', textAlign: 'left' },
  panel: { position: 'absolute', top: 'calc(100% + 4px)', left: 0, right: 0, zIndex: 40, background: '#ffffff', border: '1px solid #d6d3d1', borderRadius: 8, boxShadow: '0 12px 30px rgba(28,25,23,0.14)', maxHeight: 320, overflowY: 'auto', padding: 6 },
  option: { display: 'block', width: '100%', boxSizing: 'border-box', textAlign: 'left', padding: '8px 10px', borderRadius: 5, border: '1px solid transparent', background: '#fff', cursor: 'pointer', fontSize: 13 },
  optionMeta: { display: 'block', fontSize: 11, color: '#78716c', marginTop: 2, fontFamily: "'IBM Plex Mono', monospace" },
  metaGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, marginTop: 16 },
  metaCell: { border: '1px solid #e7e5e4', borderRadius: 6, padding: '10px 12px', background: '#fcfcfb' },
  metaLabel: { fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', color: '#78716c', fontFamily: "'IBM Plex Mono', monospace" },
  metaValue: { fontSize: 13, marginTop: 4, wordBreak: 'break-all' },
};

const badge = (tone: 'ok' | 'warn' | 'bad' | 'info') => ({
  ...s.badge,
  background: tone === 'ok' ? '#dcfce7' : tone === 'warn' ? '#fef3c7' : tone === 'bad' ? '#fee2e2' : '#e0e7ff',
  color: tone === 'ok' ? '#166534' : tone === 'warn' ? '#92400e' : tone === 'bad' ? '#991b1b' : '#3730a3',
});

export default function OrcaRouterProvidersPanel(): React.ReactElement {
  const [status, setStatus] = useState<Status | null>(null);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [capability, setCapability] = useState<'chat' | 'embedding'>('chat');
  const [requiresImage, setRequiresImage] = useState(false);
  const [selectedModel, setSelectedModel] = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [busy, setBusy] = useState<'save' | 'clear' | 'start' | 'complete' | 'cancel' | 'model' | null>(null);
  const [connect, setConnect] = useState<Connect | null>(null);
  const [code, setCode] = useState('');
  const attemptRef = useRef(0);
  const catalogSeenRef = useRef(false);

  const clearLoginState = useCallback(() => {
    attemptRef.current += 1;
    setBusy(null);
    setConnect(null);
    setCode('');
  }, []);

  const loadStatus = useCallback(async () => {
    const res = await fetch('/api/orcarouter/status', { cache: 'no-store' });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `status ${res.status}`);
    const body: Status = await res.json();
    setStatus(body);
    setSelectedModel(body.models.selected || body.models.default);
    return body;
  }, []);

  const loadCatalog = useCallback(async (nextCapability: string, image: boolean, refresh = false) => {
    setCatalogLoading(true);
    try {
      const query = new URLSearchParams({ capability: nextCapability });
      if (nextCapability === 'chat' && image) query.set('modality', 'image');
      if (refresh) query.set('refresh', '1');
      const res = await fetch(`/api/orcarouter/models?${query.toString()}`, { cache: 'no-store' });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setCatalog(null);
        setError(body.detail || body.title || `Catalogue request failed (${res.status})`);
        return;
      }
      const next: Catalog = body;
      setCatalog(next);
      setError(null);
      // A selection that no longer satisfies the active filters is cleared,
      // never silently kept. Only announce it when the operator changed a
      // filter; the first load may legitimately drop a default the account
      // cannot route.
      const hadCatalog = catalogSeenRef.current;
      catalogSeenRef.current = true;
      setSelectedModel((current) => {
        if (current && next.models.some((model) => model.id === current)) return current;
        if (current && hadCatalog) setNotice('The previously selected model is not compatible with these filters. Choose another model.');
        return '';
      });
    } catch {
      setCatalog(null);
      setError('Could not reach the model catalogue.');
    } finally {
      setCatalogLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const body = await loadStatus();
        if (cancelled) return;
        if (body.credential.configured) await loadCatalog('chat', false);
      } catch (err: any) {
        if (!cancelled) setError(err?.message || 'Could not load provider status.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [loadStatus, loadCatalog]);

  // A pending authorization expires after ten minutes. Release the panel then,
  // and release it on pagehide, where a generation-guarded `finally` cannot
  // help a back-forward-cache restore.
  useEffect(() => {
    if (!connect) return undefined;
    const remaining = Date.parse(connect.expires_at) - Date.now();
    const timer = setTimeout(() => {
      clearLoginState();
      setNotice('The authorization window closed. Check OrcaRouter for any key already issued.');
      fetch('/api/orcarouter/connect/cancel', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ attempt_id: connect.attempt_id }),
        keepalive: true,
      }).catch(() => {});
    }, Math.max(0, remaining));
    return () => clearTimeout(timer);
  }, [connect, clearLoginState]);

  useEffect(() => {
    const onHide = () => {
      attemptRef.current += 1;
      setBusy(null);
      setConnect((pending) => {
        if (pending) {
          try {
            fetch('/api/orcarouter/connect/cancel', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ attempt_id: pending.attempt_id }),
              keepalive: true,
            }).catch(() => {});
          } catch {
            /* best effort during teardown */
          }
        }
        return null;
      });
      setCode('');
    };
    window.addEventListener('pagehide', onHide);
    return () => {
      window.removeEventListener('pagehide', onHide);
      attemptRef.current += 1;
    };
  }, []);

  const refresh = async () => {
    setNotice(null);
    await loadStatus().catch(() => {});
    await loadCatalog(capability, requiresImage, true);
  };

  const saveApiKey = async () => {
    let priorAuthorizationNotice: string | null = null;
    // Do not switch methods while cancellation of a pending attempt is uncertain.
    if (connect) {
      const generation = ++attemptRef.current;
      setBusy('cancel');
      setError(null);
      setNotice(null);
      const result = await requestOrcaCancellation(connect.attempt_id);
      if (attemptRef.current !== generation) return;
      if (result.outcome === 'unconfirmed') {
        setBusy(null);
        setError(result.message);
        await loadStatus().catch(() => {});
        return;
      }
      priorAuthorizationNotice = result.message;
      clearLoginState();
      setBusy('save');
      const saveGeneration = attemptRef.current;
      await loadStatus().catch(() => {});
      if (attemptRef.current !== saveGeneration) return;
    }
    setBusy('save');
    setError(null);
    setNotice(priorAuthorizationNotice);
    try {
      const res = await fetch('/api/orcarouter/credential', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail || 'Could not save the API key.');
      setApiKey('');
      setNotice(priorAuthorizationNotice
        ? `API key saved. ${priorAuthorizationNotice}`
        : 'API key saved. It is sealed at rest and never shown again.');
      await loadStatus();
      await loadCatalog(capability, requiresImage, true);
    } catch (err: any) {
      setError(err?.message || 'Could not save the API key.');
    } finally {
      setBusy(null);
    }
  };

  const clearCredential = async () => {
    setBusy('clear');
    setError(null);
    setNotice(null);
    try {
      const res = await fetch('/api/orcarouter/credential', { method: 'DELETE' });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail || 'Could not clear the credential.');
      setNotice('Stored credential cleared.');
      await loadStatus();
      setCatalog(null);
      setSelectedModel('');
    } catch (err: any) {
      setError(err?.message || 'Could not clear the credential.');
    } finally {
      setBusy(null);
    }
  };

  const startConnect = async () => {
    const generation = attemptRef.current + 1;
    attemptRef.current = generation;
    setBusy('start');
    setError(null);
    setNotice(null);
    try {
      const res = await fetch('/api/orcarouter/connect/start', { method: 'POST' });
      const body = await res.json().catch(() => ({}));
      if (attemptRef.current !== generation) return;
      if (!res.ok) throw new Error(body.detail || 'Could not start the connection.');
      setConnect(body);
    } catch (err: any) {
      if (attemptRef.current === generation) setError(err?.message || 'Could not start the connection.');
    } finally {
      if (attemptRef.current === generation) setBusy(null);
    }
  };

  const completeConnect = async () => {
    if (!connect) return;
    const generation = attemptRef.current;
    const attemptId = connect.attempt_id;
    setBusy('complete');
    setError(null);
    setNotice(null);
    try {
      const res = await fetch('/api/orcarouter/connect/complete', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ attempt_id: attemptId, code }),
      });
      const body = await res.json().catch(() => ({}));
      if (attemptRef.current !== generation) return;
      if (!res.ok) {
        setConnect(null);
        throw new Error(body.detail || 'The authorization code was not accepted.');
      }
      setConnect(null);
      setCode('');
      setNotice('Connected. The OrcaRouter key is stored sealed and is reused until revoked.');
      await loadStatus();
      await loadCatalog('chat', false, true);
    } catch (err: any) {
      if (attemptRef.current === generation) setError(err?.message || 'The connection could not be completed.');
    } finally {
      if (attemptRef.current === generation) setBusy(null);
    }
  };

  const cancelConnect = async () => {
    const pending = connect;
    if (!pending) return;
    // Ignore a late completion response while cancellation is being resolved.
    const generation = ++attemptRef.current;
    setBusy('cancel');
    setNotice(null);
    setError(null);
    const result = await requestOrcaCancellation(pending.attempt_id);
    if (attemptRef.current !== generation) return;
    if (result.outcome === 'unconfirmed') {
      setBusy(null);
      setError(result.message);
      await loadStatus().catch(() => {});
      return;
    }
    clearLoginState();
    setNotice(result.message);
    await loadStatus().catch(() => {});
  };

  const chooseModel = async (model: Model) => {
    setDropdownOpen(false);
    const previous = selectedModel;
    setSelectedModel(model.id);
    setBusy('model');
    setError(null);
    try {
      const res = await fetch('/api/orcarouter/preferences', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ capability, model: model.id }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail || 'Could not save the model selection.');
      setStatus((current) => current ? {
        ...current,
        models: {
          ...current.models,
          selections: { ...(current.models.selections || {}), [capability]: model.id },
        },
      } : current);
      setNotice(`Model set to ${model.id}.`);
    } catch (err: any) {
      setSelectedModel(previous);
      setError(err?.message || 'Could not save the model selection.');
    } finally {
      setBusy(null);
    }
  };

  if (loading) {
    return <main style={s.page}><div style={s.container}><p style={{ color: '#78716c' }}>Loading provider settings…</p></div></main>;
  }

  const credential = status?.credential;
  const disabled = busy !== null;
  const options = catalog?.models || [];

  return (
    <main style={s.page}>
      <div style={s.container}>
        <div style={s.eyebrow}>AI Trust Desk · Internal</div>
        <h1 style={s.h1}>Model providers</h1>
        <p style={s.subtitle}>
          OrcaRouter Cyber Inference is the named provider for authorized security-team inference.
          Configure exactly one credential below: paste an existing API key, or connect your
          OrcaRouter account with OAuth 2.0 + PKCE. Both paths produce the same ordinary
          OrcaRouter API key, and inference always goes to <span style={s.mono}>{status?.origins.api || 'https://api.orcarouter.ai/v1'}</span>.
        </p>

        {error && <div style={s.alert} role="alert">{error}</div>}
        {notice && <div style={s.success} role="status">{notice}</div>}

        <section style={s.card} aria-label="OrcaRouter Cyber Inference settings">
          <h2 style={s.cardTitle}>
            OrcaRouter Cyber Inference
            <span style={badge(credential?.needs_reauth ? 'bad' : credential?.configured ? 'ok' : 'warn')} data-testid="orca-credential-state">
              {credential?.needs_reauth ? 'Reconnect required' : credential?.configured ? 'Configured' : 'Not configured'}
            </span>
          </h2>
          <p style={s.cardDesc}>
            Purpose-built for security teams doing authorized work: red-team and blue-team
            inference that general-purpose gateways often refuse or silently downgrade.
          </p>

          <div style={s.statusLine}>
            <span style={s.metaLabel}>Credential</span>
            <strong style={s.mono} data-testid="orca-credential-masked">
              {credential?.configured ? credential.masked : 'none'}
            </strong>
            {credential?.source && <span style={{ color: '#78716c' }}>· {sourceLabel[credential.source]}</span>}
          </div>

          {credential?.needs_reauth && (
            <div style={s.alert}>
              This credential was revoked or rejected. Reconnect below; no refresh is attempted for a durable key.
            </div>
          )}

          <div style={s.row}>
            <div style={s.half}>
              <h3 style={s.halfTitle}>API key</h3>
              <p style={s.halfDesc}>
                Use an existing <span style={s.mono}>sk-orca-…</span> key from your OrcaRouter console.
              </p>
              <label style={s.label} htmlFor="orca-api-key">OrcaRouter API key</label>
              <input
                id="orca-api-key"
                data-testid="orca-auth-api-key"
                type="password"
                autoComplete="off"
                spellCheck={false}
                placeholder="sk-orca-…"
                value={apiKey}
                disabled={disabled}
                onChange={(event) => setApiKey(event.target.value)}
                style={s.input}
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                <button type="button" style={{ ...s.btn, ...(disabled ? s.btnDisabled : {}) }} disabled={disabled} onClick={saveApiKey}>
                  {busy === 'save' ? 'Saving…' : 'Save key'}
                </button>
                <button type="button" style={{ ...s.btnDanger, ...(disabled ? s.btnDisabled : {}) }} disabled={disabled} onClick={clearCredential}>
                  {busy === 'clear' ? 'Clearing…' : 'Clear stored key'}
                </button>
              </div>
            </div>

            <div style={s.half}>
              <h3 style={s.halfTitle}>Connect with OrcaRouter</h3>
              <p style={s.halfDesc}>
                Approve in your browser and paste the code shown. No client secret is used, and the
                verifier never leaves this server.
              </p>
              {!connect && (
                <button
                  type="button"
                  data-testid="orca-auth-pkce"
                  style={{ ...s.btnGhost, ...(disabled ? s.btnDisabled : {}) }}
                  disabled={disabled}
                  onClick={startConnect}
                >
                  {busy === 'start' ? 'Opening…' : 'Connect with OrcaRouter'}
                </button>
              )}
              {connect && (
                <div>
                  <div style={s.urlBox} data-testid="orca-authorize-url">
                    <a href={connect.authorize_url} target="_blank" rel="noreferrer">{connect.authorize_url}</a>
                  </div>
                  <label style={s.label} htmlFor="orca-code">Code shown after approval</label>
                  <input
                    id="orca-code"
                    type="text"
                    autoComplete="one-time-code"
                    value={code}
                    disabled={disabled}
                    onChange={(event) => setCode(event.target.value)}
                    style={s.input}
                  />
                  <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                    <button type="button" style={{ ...s.btn, ...(disabled ? s.btnDisabled : {}) }} disabled={disabled || !code} onClick={completeConnect}>
                      {busy === 'complete' ? 'Finishing…' : 'Finish connection'}
                    </button>
                    <button type="button" style={s.btnGhost} disabled={busy === 'cancel'} onClick={cancelConnect}>Cancel</button>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div style={s.metaGrid}>
            <div style={s.metaCell}>
              <div style={s.metaLabel}>Authorization origin</div>
              <div style={s.metaValue}>{status?.origins.auth || 'https://www.orcarouter.ai'}</div>
            </div>
            <div style={s.metaCell}>
              <div style={s.metaLabel}>Inference origin</div>
              <div style={s.metaValue}>{status?.origins.api || 'https://api.orcarouter.ai/v1'}</div>
            </div>
            <div style={s.metaCell}>
              <div style={s.metaLabel}>Default / fallback</div>
              <div style={s.metaValue}>{status?.models.default} · {status?.models.fallback}</div>
            </div>
            <div style={s.metaCell}>
              <div style={s.metaLabel}>Cyber models</div>
              <div style={s.metaValue}>{status?.models.cyber.join(' · ')}</div>
            </div>
          </div>
        </section>

        <section style={s.card} aria-label="Model selection">
          <h2 style={s.cardTitle}>Model</h2>
          <p style={s.cardDesc}>
            Options come from the live catalogue at <span style={s.mono}>{status?.catalog_source}</span>.
            {catalog?.degraded && ' Live discovery is unavailable, so a verified fallback catalogue is shown.'}
          </p>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
            <div style={{ flex: '1 1 220px' }}>
              <label style={s.label} htmlFor="orca-capability">Capability</label>
              <select
                id="orca-capability"
                style={s.select}
                value={capability}
                disabled={disabled || catalogLoading}
                onChange={(event) => {
                  const next = event.target.value as 'chat' | 'embedding';
                  setCapability(next);
                  // Each capability keeps its own saved selection; never carry a
                  // chat model into the embedding selector or vice versa.
                  setSelectedModel(status?.models.selections?.[next] || '');
                  if (next !== 'chat') setRequiresImage(false);
                  loadCatalog(next, next === 'chat' ? requiresImage : false, true);
                }}
              >
                <option value="chat">Chat</option>
                <option value="embedding">Embeddings</option>
              </select>
            </div>
            {capability === 'chat' && (
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, paddingTop: 22 }}>
                <input
                  type="checkbox"
                  checked={requiresImage}
                  disabled={disabled || catalogLoading}
                  onChange={(event) => {
                    setRequiresImage(event.target.checked);
                    loadCatalog('chat', event.target.checked, true);
                  }}
                />
                Requires image input
              </label>
            )}
            <button
              type="button"
              style={{ ...s.btnGhost, marginTop: 22, ...(disabled ? s.btnDisabled : {}) }}
              disabled={disabled || catalogLoading}
              onClick={refresh}
            >
              {catalogLoading ? 'Refreshing…' : 'Refresh catalogue'}
            </button>
          </div>

          {catalogLoading && <p style={{ color: '#78716c', fontSize: 13 }}>Loading models…</p>}
          {!catalogLoading && catalog && options.length === 0 && (
            <div style={s.notice}>No compatible models were returned for this capability.</div>
          )}
          {!catalogLoading && options.length > 0 && (
            <div style={s.dropdownWrap}>
              <button
                type="button"
                data-testid="orca-model-trigger"
                aria-haspopup="listbox"
                aria-expanded={dropdownOpen}
                style={s.trigger}
                disabled={disabled}
                onClick={() => setDropdownOpen((open) => !open)}
              >
                <span style={s.mono}>{selectedModel || 'Select a model'}</span>
                <span aria-hidden="true">▾</span>
              </button>
              {dropdownOpen && (
                <div style={s.panel} role="listbox" data-testid="orca-model-panel">
                  {options.map((model) => (
                    <button
                      key={model.id}
                      type="button"
                      role="option"
                      aria-selected={model.id === selectedModel}
                      data-testid="orca-model-option"
                      style={{ ...s.option, background: model.id === selectedModel ? '#f5f5f4' : '#fff' }}
                      onClick={() => chooseModel(model)}
                    >
                      <span>{model.name}</span>
                      <span style={s.optionMeta}>
                        {model.id}
                        {model.context_length ? ` · ${model.context_length.toLocaleString()} ctx` : ''}
                        {model.input_modalities?.length ? ` · ${model.input_modalities.join('+')}` : ''}
                        {model.verified_seed ? ' · verified fallback' : ''}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {catalog && (
            <div style={s.statusLine}>
              <span style={badge(catalog.degraded ? 'warn' : 'ok')}>
                {catalog.source === 'live' ? 'Live catalogue' : catalog.source === 'last-known-good' ? 'Last known good' : 'Verified fallback'}
              </span>
              <span style={{ color: '#78716c' }}>{catalog.count} compatible model{catalog.count === 1 ? '' : 's'}</span>
              {catalog.error && <span style={{ color: '#b45309' }}>· {catalog.error}</span>}
            </div>
          )}
        </section>

        <p style={{ fontSize: 12, color: '#78716c', lineHeight: 1.6 }}>
          <a href="https://www.orcarouter.ai/cyber" target="_blank" rel="noreferrer">OrcaRouter Cyber Inference</a>
          {' '}·{' '}
          <a href="https://www.orcarouter.ai/models?tier=cyber" target="_blank" rel="noreferrer">Cyber model catalogue</a>
          {' '}· keys are revocable at any time from the OrcaRouter console.
        </p>
      </div>
    </main>
  );
}
