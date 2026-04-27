'use client';

import { useState, useCallback } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

/**
 * /playground — EP Trust Playground
 *
 * Interactive sandbox where developers can:
 *   - Create test entities
 *   - Submit receipts between them
 *   - Run handshake ceremonies step-by-step
 *   - See trust profiles update in real-time
 *   - Verify receipts offline
 *
 * All in-browser, hitting the local/live API. Learning by doing, not reading.
 *
 * @license Apache-2.0
 */

const mono = { fontFamily: font.mono, fontSize: 12, lineHeight: 1.6 };
const badge = (bg, fg, border) => ({
  ...mono, fontSize: 10, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase',
  padding: '3px 10px', borderRadius: 100, display: 'inline-block',
  background: bg, color: fg, border: `1px solid ${border}`,
});

function ResultPanel({ title, data, status }) {
  if (!data) return null;
  const isOk = status === 'success';
  return (
    <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, marginTop: 12, overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: `1px solid ${color.border}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ ...mono, fontWeight: 600, color: color.t1 }}>{title}</span>
        <span style={badge(
          isOk ? 'rgba(22,163,74,0.08)' : 'rgba(220,38,38,0.08)',
          isOk ? '#16A34A' : '#DC2626',
          isOk ? 'rgba(22,163,74,0.2)' : 'rgba(220,38,38,0.2)',
        )}>{isOk ? 'SUCCESS' : 'ERROR'}</span>
      </div>
      <pre style={{ ...mono, padding: 16, margin: 0, color: color.t2, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 300, overflow: 'auto' }}>
        {typeof data === 'string' ? data : JSON.stringify(data, null, 2)}
      </pre>
    </div>
  );
}

export default function PlaygroundPage() {
  const [entities, setEntities] = useState([]);
  const [receipts, setReceipts] = useState([]);
  const [handshakes, setHandshakes] = useState([]);
  const [profiles, setProfiles] = useState({});
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);

  const apiCall = useCallback(async (method, path, body) => {
    setLoading(true);
    try {
      const opts = { method, headers: { 'Content-Type': 'application/json' } };
      if (body) opts.body = JSON.stringify(body);
      const res = await fetch(path, opts);
      const data = await res.json();
      setResult({ data, status: res.ok ? 'success' : 'error', title: `${method} ${path}` });
      setLoading(false);
      return { ok: res.ok, data };
    } catch (err) {
      setResult({ data: err.message, status: 'error', title: `${method} ${path}` });
      setLoading(false);
      return { ok: false, data: null };
    }
  }, []);

  async function createEntity(name) {
    const { ok, data } = await apiCall('POST', '/api/entity', { name });
    if (ok && data?.entity_id) {
      setEntities(prev => [...prev, { id: data.entity_id, name, api_key: data.api_key }]);
      setStep(s => Math.max(s, 1));
    }
  }

  async function submitReceipt() {
    if (entities.length < 2) return;
    const { ok, data } = await apiCall('POST', '/api/receipt', {
      issuer: entities[0].id,
      subject: entities[1].id,
      action_type: 'playground_test',
      outcome: 'positive',
      context: { source: 'playground', timestamp: new Date().toISOString() },
    });
    if (ok && data) {
      setReceipts(prev => [...prev, data]);
      setStep(s => Math.max(s, 2));
    }
  }

  async function getProfile(entityId) {
    const { ok, data } = await apiCall('GET', `/api/trust?entity_id=${encodeURIComponent(entityId)}`);
    if (ok && data) {
      setProfiles(prev => ({ ...prev, [entityId]: data }));
      setStep(s => Math.max(s, 3));
    }
  }

  async function runHandshake() {
    if (entities.length < 1) return;
    const { ok, data } = await apiCall('POST', '/api/handshake', {
      initiator: entities[0].id,
      action_type: 'playground_action',
      resource_ref: 'playground/test-resource',
    });
    if (ok && data?.handshake_id) {
      setHandshakes(prev => [...prev, data]);
      setStep(s => Math.max(s, 4));
    }
  }

  async function consumeHandshake(hsId) {
    await apiCall('POST', '/api/handshake/verify', { handshake_id: hsId });
    setStep(s => Math.max(s, 5));
  }

  async function verifyReceipt() {
    if (receipts.length < 1) return;
    const receiptId = receipts[0]?.payload?.receipt_id || receipts[0]?.receipt_id;
    if (receiptId) {
      await apiCall('GET', `/api/verify/${encodeURIComponent(receiptId)}`);
    }
  }

  const STEPS = [
    { num: '01', title: 'Register Entities', desc: 'Create two test entities with Ed25519 key pairs.', action: 'Create Entities', enabled: true },
    { num: '02', title: 'Submit Receipt', desc: 'Entity A issues a trust receipt about Entity B.', action: 'Submit Receipt', enabled: entities.length >= 2 },
    { num: '03', title: 'View Profile', desc: 'See how the trust profile updates from receipt evidence.', action: 'Get Profile', enabled: entities.length >= 1 },
    { num: '04', title: 'Run Handshake', desc: 'Initiate a pre-action authorization ceremony.', action: 'Start Handshake', enabled: entities.length >= 1 },
    { num: '05', title: 'Consume Handshake', desc: 'Verify and consume — replay is structurally impossible.', action: 'Consume', enabled: handshakes.length >= 1 },
    { num: '06', title: 'Verify Receipt', desc: 'Verify the receipt signature — no EP server required.', action: 'Verify', enabled: receipts.length >= 1 },
  ];

  const actions = [
    () => { createEntity('Playground Agent A'); setTimeout(() => createEntity('Playground Agent B'), 500); },
    () => submitReceipt(),
    () => getProfile(entities[0]?.id),
    () => runHandshake(),
    () => consumeHandshake(handshakes[handshakes.length - 1]?.handshake_id),
    () => verifyReceipt(),
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 40 }}>
        <div style={styles.eyebrow}>Trust Playground</div>
        <h1 style={styles.h1}>Learn by doing.</h1>
        <p style={{ ...styles.body, maxWidth: 560 }}>
          Walk through the complete EP trust lifecycle interactively. Create entities, issue receipts, run handshake ceremonies, and verify everything — all from this page.
        </p>
      </section>

      <section style={{ ...styles.sectionWide, paddingTop: 0 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
          {/* Left: Steps */}
          <div>
            <h2 style={{ ...styles.h2, fontSize: 18 }}>Lifecycle Steps</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {STEPS.map((s, i) => (
                <div key={i} style={{
                  ...styles.card,
                  padding: '16px 20px',
                  opacity: s.enabled ? 1 : 0.4,
                  borderColor: step === i ? color.gold : color.border,
                  transition: 'border-color 0.2s',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ ...mono, fontSize: 10, color: i < step ? '#16A34A' : color.gold, letterSpacing: 1 }}>
                        {i < step ? '\u2713' : s.num}
                      </span>
                      <span style={{ fontWeight: 600, fontSize: 14, color: color.t1 }}>{s.title}</span>
                    </div>
                    <button
                      onClick={actions[i]}
                      disabled={!s.enabled || loading}
                      style={{
                        ...cta.primary,
                        padding: '6px 14px', fontSize: 11,
                        opacity: s.enabled && !loading ? 1 : 0.4,
                      }}
                    >{loading ? '...' : s.action}</button>
                  </div>
                  <p style={{ fontSize: 12, color: color.t2, margin: 0, lineHeight: 1.5 }}>{s.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Result + State */}
          <div>
            <h2 style={{ ...styles.h2, fontSize: 18 }}>API Response</h2>
            {result && <ResultPanel title={result.title} data={result.data} status={result.status} />}

            {entities.length > 0 && (
              <div style={{ marginTop: 20 }}>
                <h3 style={{ ...mono, fontSize: 11, color: color.t3, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 8 }}>Live State</h3>
                <div style={{ ...styles.card, padding: '12px 16px' }}>
                  <div style={{ ...mono, color: color.t2, marginBottom: 4 }}>Entities: {entities.length}</div>
                  <div style={{ ...mono, color: color.t2, marginBottom: 4 }}>Receipts: {receipts.length}</div>
                  <div style={{ ...mono, color: color.t2, marginBottom: 4 }}>Handshakes: {handshakes.length}</div>
                  {Object.entries(profiles).map(([eid, p]) => (
                    <div key={eid} style={{ ...mono, color: color.t2, marginTop: 8, paddingTop: 8, borderTop: `1px solid ${color.border}` }}>
                      <div style={{ fontWeight: 600, marginBottom: 2 }}>{eid.slice(0, 20)}...</div>
                      <div>Score: {p.score?.toFixed(2)} | Confidence: {p.confidence} | Depth: {p.evidence_depth}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!result && (
              <div style={{ ...styles.card, marginTop: 12, textAlign: 'center', padding: 40 }}>
                <div style={{ ...mono, color: color.t3, fontSize: 13 }}>
                  Click a step on the left to begin.
                  <br /><br />
                  Each step calls the real EP API.
                  <br />
                  Watch the response appear here.
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
