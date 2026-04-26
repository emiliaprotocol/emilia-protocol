'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

/**
 * /explorer — Trust Receipt Explorer
 *
 * The "Etherscan for trust." Anyone can:
 *   - Look up a receipt by receipt_id
 *   - Look up a commitment proof by proof_id
 *   - Verify a receipt's signature in-browser
 *   - Check a commitment proof's validity
 *   - See an entity's public trust profile
 *
 * No authentication required. Transparency as a protocol property.
 */

const TABS = ['receipt', 'proof', 'entity'];

export default function ExplorerPage() {
  const [activeTab, setActiveTab] = useState('receipt');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleLookup(e) {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let res;
      if (activeTab === 'receipt') {
        res = await fetch(`/api/verify/${encodeURIComponent(query.trim())}`);
      } else if (activeTab === 'proof') {
        res = await fetch(`/api/trust/zk-proof?proof_id=${encodeURIComponent(query.trim())}`);
      } else {
        res = await fetch(`/api/trust/profile/${encodeURIComponent(query.trim())}`);
      }

      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || data.error || `Not found (${res.status})`);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError('Network error — could not reach the API.');
    }
    setLoading(false);
  }

  const placeholders = {
    receipt: 'ep_r_abc123...',
    proof: 'ep_zkp_abc123...',
    entity: 'ep_entity_abc123...',
  };

  const labels = {
    receipt: 'Verify Receipt',
    proof: 'Verify Proof',
    entity: 'Trust Profile',
  };

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 40 }}>
        <div style={styles.eyebrow}>Trust Explorer</div>
        <h1 style={styles.h1}>Verify anything. Trust nothing.</h1>
        <p style={{ ...styles.body, maxWidth: 560 }}>
          Look up any receipt, commitment proof, or entity. Verification is public — no account, no API key. Just the truth.
        </p>
      </section>

      <section style={styles.section}>
        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 24, borderBottom: `1px solid ${color.border}` }}>
          {TABS.map(tab => (
            <button
              key={tab}
              onClick={() => { setActiveTab(tab); setResult(null); setError(null); setQuery(''); }}
              style={{
                fontFamily: font.mono, fontSize: 12, fontWeight: 500,
                letterSpacing: 1, textTransform: 'uppercase',
                padding: '12px 24px',
                border: 'none', background: 'none', cursor: 'pointer',
                color: activeTab === tab ? color.gold : color.t3,
                borderBottom: activeTab === tab ? `2px solid ${color.gold}` : '2px solid transparent',
              }}
            >{labels[tab]}</button>
          ))}
        </div>

        {/* Search form */}
        <form onSubmit={handleLookup} style={{ display: 'flex', gap: 12, marginBottom: 32 }}>
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={placeholders[activeTab]}
            style={{
              flex: 1, padding: '14px 18px',
              fontFamily: font.mono, fontSize: 14,
              border: `1px solid ${color.border}`, borderRadius: radius.base,
              outline: 'none', background: '#FAFAF9',
            }}
          />
          <button
            type="submit"
            disabled={loading}
            style={{ ...cta.primary, opacity: loading ? 0.6 : 1, minWidth: 140 }}
          >{loading ? 'Verifying...' : 'Look Up'}</button>
        </form>

        {/* Error */}
        {error && (
          <div style={{
            padding: '16px 20px', borderRadius: radius.base,
            background: 'rgba(220,38,38,0.06)', border: '1px solid rgba(220,38,38,0.2)',
            color: '#DC2626', fontFamily: font.mono, fontSize: 13, marginBottom: 24,
          }}>{error}</div>
        )}

        {/* Result */}
        {result && (
          <div style={{
            background: color.card, border: `1px solid ${color.border}`,
            borderRadius: radius.base, overflow: 'hidden',
          }}>
            {/* Header */}
            <div style={{
              padding: '16px 20px',
              borderBottom: `1px solid ${color.border}`,
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <span style={{
                fontFamily: font.mono, fontSize: 12, fontWeight: 600,
                color: color.t1, letterSpacing: 0.5,
              }}>
                {activeTab === 'receipt' ? 'Receipt Verification' :
                 activeTab === 'proof' ? 'Commitment Proof' : 'Trust Profile'}
              </span>
              {result.valid !== undefined && (
                <span style={{
                  fontFamily: font.mono, fontSize: 10, fontWeight: 600,
                  letterSpacing: 1.5, textTransform: 'uppercase',
                  padding: '4px 12px', borderRadius: 100,
                  ...(result.valid
                    ? { background: 'rgba(22,163,74,0.1)', color: '#16A34A', border: '1px solid rgba(22,163,74,0.2)' }
                    : { background: 'rgba(220,38,38,0.1)', color: '#DC2626', border: '1px solid rgba(220,38,38,0.2)' }
                  ),
                }}>{result.valid ? 'VERIFIED' : 'INVALID'}</span>
              )}
            </div>

            {/* Body */}
            <div style={{ padding: '20px' }}>
              <pre style={{
                fontFamily: font.mono, fontSize: 12, lineHeight: 1.6,
                color: color.t2, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                margin: 0,
              }}>{JSON.stringify(result, null, 2)}</pre>
            </div>

            {/* Anchor link */}
            {result.anchor_block && (
              <div style={{
                padding: '12px 20px',
                borderTop: `1px solid ${color.border}`,
                background: '#F5F5F4',
              }}>
                <a
                  href={`https://basescan.org/tx/${result.transaction_hash || ''}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ fontFamily: font.mono, fontSize: 12, color: color.blue }}
                >View on-chain anchor on Basescan</a>
              </div>
            )}
          </div>
        )}

        {/* Explainer */}
        {!result && !error && (
          <div style={{ marginTop: 40 }}>
            <h2 style={styles.h2}>How verification works</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginTop: 16 }}>
              {[
                { step: '01', title: 'Signature check', body: 'Every receipt is Ed25519-signed by the issuer. Verification uses the signer\'s public key — discoverable at /.well-known/ep-keys.json.' },
                { step: '02', title: 'Merkle proof', body: 'Receipts are batched into Merkle trees and the root is anchored on Base L2. The proof verifies inclusion without revealing other receipts.' },
                { step: '03', title: 'On-chain anchor', body: 'The Merkle root is published to Base L2 as calldata. Anyone can verify the root exists on-chain at the stated block number via Basescan.' },
              ].map((s, i) => (
                <div key={i} style={{
                  background: color.card, border: `1px solid ${color.border}`,
                  borderRadius: radius.base, padding: '20px',
                }}>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1, marginBottom: 10 }}>{s.step}</div>
                  <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, marginBottom: 6, color: color.t1 }}>{s.title}</h3>
                  <p style={{ fontSize: 12, color: color.t2, lineHeight: 1.55 }}>{s.body}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
