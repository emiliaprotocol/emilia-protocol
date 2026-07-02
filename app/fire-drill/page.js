'use client';
// SPDX-License-Identifier: Apache-2.0
// /fire-drill — the Agent Action Firewall Test, on the web. Paste an MCP
// manifest, OpenAPI spec, or tool list; see which dangerous actions can run
// without an accountable human receipt.

import { useState } from 'react';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
// The scanner is pure (zero imports, no node APIs), so it runs entirely in the
// browser — instant, and the pasted manifest never leaves the page. Same source
// of truth as `npx @emilia-protocol/fire-drill`.
import { scan } from '../../packages/fire-drill/index.js';

const EXAMPLE_VULNERABLE = JSON.stringify({
  tools: [
    { name: 'read_status', description: 'read-only health check' },
    { name: 'delete_customer_data', description: 'hard delete a customer and all records' },
    { name: 'release_payment', description: 'wire funds to a destination account' },
    { name: 'deploy_production', description: 'roll out a new release to prod' },
  ],
}, null, 2);

const EXAMPLE_SAFE = JSON.stringify({
  tools: [
    { name: 'read_status', description: 'read-only health check' },
    {
      name: 'release_payment',
      description: 'wire funds to a destination account',
      inputSchema: { type: 'object', properties: { amount: { type: 'number' }, emilia_receipt: { type: 'object' } } },
    },
  ],
}, null, 2);

export default function FireDrillPage() {
  const [text, setText] = useState(EXAMPLE_VULNERABLE);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  function run() {
    setBusy(true); setError(null); setReport(null);
    try {
      let input;
      try {
        input = JSON.parse(text);
      } catch {
        setError('Input must be valid JSON (an MCP manifest, OpenAPI spec, or tool array).');
        return;
      }
      setReport(scan(input));
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }

  const scoreColor = (s) => (s === 100 ? color.green : s >= 50 ? color.gold : '#DC2626');

  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 40 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>THE AGENT ACTION FIREWALL TEST</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Can your agent take a dangerous action without a receipt?</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Paste an MCP server manifest, an OpenAPI spec, or a tool list. The fire drill flags every
              dangerous operation — money movement, data destruction, production deploy, permission
              change, bulk export, regulated override — that can run <b>without an accountable human
              receipt</b>.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12, fontSize: 15, color: color.t2 }}>
              Runs the same scanner as <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code>.
              Static assessment — verify the fix at runtime with CF-1 / EG-1 conformance.
            </p>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
              <button onClick={() => setText(EXAMPLE_VULNERABLE)} style={{ ...cta.secondary, cursor: 'pointer' }}>Example: vulnerable MCP</button>
              <button onClick={() => setText(EXAMPLE_SAFE)} style={{ ...cta.secondary, cursor: 'pointer' }}>Example: gated MCP</button>
            </div>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              style={{
                width: '100%', minHeight: 260, fontFamily: font.mono, fontSize: 13, lineHeight: 1.6,
                color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`,
                borderRadius: 8, padding: 18, resize: 'vertical', boxSizing: 'border-box',
              }}
            />
            <div style={{ display: 'flex', gap: 12, marginTop: 16, alignItems: 'center' }}>
              <button onClick={run} disabled={busy} style={{ ...cta.primary, cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.7 : 1 }}>
                {busy ? 'Running…' : 'Run the fire drill'}
              </button>
              {error && <span style={{ color: '#DC2626', fontFamily: font.mono, fontSize: 13 }}>{error}</span>}
            </div>
          </div>
        </section>

        {report && (
          <section style={{ ...styles.section, paddingTop: 8 }}>
            <div style={styles.container}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 20, flexWrap: 'wrap', borderTop: `1px solid ${color.border}`, paddingTop: 28 }}>
                <div style={{ fontFamily: font.mono, fontSize: 44, fontWeight: 700, color: scoreColor(report.score) }}>{report.score}<span style={{ fontSize: 20, color: color.t3 }}>/100</span></div>
                <div>
                  <div style={{ fontFamily: font.mono, fontSize: 12, letterSpacing: 1, color: color.t2, textTransform: 'uppercase' }}>Agent Action Firewall score</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 4 }}>
                    {report.summary.dangerous} dangerous · {report.summary.gated} gated · {report.summary.ungated} unguarded
                  </div>
                </div>
                <div style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 10, padding: '10px 16px', border: `1px solid ${report.eg1 === 'pass' ? color.green : '#DC2626'}`, borderRadius: 999 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 999, background: report.eg1 === 'pass' ? color.green : '#DC2626', display: 'inline-block' }} />
                  <span style={{ fontFamily: font.mono, fontSize: 12, color: report.eg1 === 'pass' ? color.green : '#DC2626', letterSpacing: 1, textTransform: 'uppercase' }}>
                    {report.eg1 === 'pass' ? 'EG-1 Enforced' : 'EG-1 Failed'}
                  </span>
                </div>
              </div>

              {report.findings.length === 0 ? (
                <p style={{ ...styles.body, marginTop: 24, color: color.green }}>
                  ✓ No dangerous action can run without a receipt. Eligible for the <b>EG-1 Enforced</b> badge.
                </p>
              ) : (
                <div style={{ marginTop: 24 }}>
                  {report.findings.map((f) => (
                    <div key={f.operation} style={{ borderTop: `1px solid ${color.border}`, padding: '16px 0' }}>
                      <div style={{ fontFamily: font.mono, fontSize: 14, color: '#DC2626' }}>✗ {f.message}</div>
                      <div style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 6 }}><b style={{ color: color.t1 }}>Fix:</b> {f.fix}</div>
                      <div style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 2 }}><b style={{ color: color.t1 }}>Earn:</b> {f.earn}</div>
                    </div>
                  ))}
                </div>
              )}
              <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 20 }}>{report.note}</p>
            </div>
          </section>
        )}

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={{ ...styles.h2, maxWidth: 760 }}>
              If your agent can take an irreversible action without a receipt, you do not have control.
              You have hope.
            </h2>
            <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
              <a href="/gate" style={cta.primary}>Add EMILIA Gate</a>
              <a href="/fire-drill/cf-1" style={cta.secondary}>What is CF-1?</a>
              <a href="/gate#eg1" style={cta.secondary}>Earn EG-1</a>
              <a href="/fire-drill/gallery" style={cta.secondary}>Safety Index</a>
              <Link href="/fire-drill/report" style={cta.secondary}>The Report</Link>
            </div>
            <div style={{ marginTop: 28 }}>
              <div style={{ ...styles.eyebrow, color: color.t3 }}>EARNED CF-1 / EG-1? EMBED THE BADGE</div>
              <pre style={{ fontFamily: font.mono, fontSize: 12, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: 8, padding: 16, marginTop: 10, overflowX: 'auto', whiteSpace: 'pre-wrap' }}>{'![EG-1 Enforced](https://www.emiliaprotocol.ai/badge/eg1?eg1=pass)'}</pre>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
