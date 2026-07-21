'use client';
// SPDX-License-Identifier: Apache-2.0
// /fire-drill — static receipt-declaration review. Runtime enforcement is a
// separate conformance question.

import { useState } from 'react';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
// The scanner is pure (zero imports, no node APIs), so it runs entirely in the
// browser — instant, and the pasted manifest never leaves the page. Same source
// of truth as `npx @emilia-protocol/fire-drill`.
import { scan } from '../../packages/fire-drill/index.js';
import { strictJsonGate } from '../../packages/verify/strict-json.js';

const MAX_INPUT_BYTES = 8 * 1024 * 1024;

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
      inputSchema: {
        type: 'object',
        properties: { amount: { type: 'number' }, emilia_receipt: { type: 'object' } },
        required: ['amount', 'emilia_receipt'],
      },
    },
  ],
}, null, 2);

export default function FireDrillPage() {
  const [text, setText] = useState(EXAMPLE_VULNERABLE);
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function run() {
    setBusy(true); setError(null); setReport(null);
    try {
      if (new TextEncoder().encode(text).length > MAX_INPUT_BYTES) {
        setError(`Input exceeds ${MAX_INPUT_BYTES} bytes.`);
        return;
      }
      const gate = strictJsonGate(text);
      if (!gate.ok) {
        setError(`Input refused: ${gate.reason}.`);
        return;
      }
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

  const scoreColor = (s) => (s >= 50 ? color.gold : '#DC2626');

  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 40 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>STATIC RECEIPT DECLARATION REVIEW</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Do your dangerous tools declare required evidence?</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Paste an MCP server manifest, OpenAPI spec, or tool list. The scanner identifies detected
              high-risk operations that omit a structurally required receipt input.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12, fontSize: 15, color: color.t2 }}>
              Runs the same scanner as <code style={{ fontFamily: font.mono }}>npx @emilia-protocol/fire-drill</code>.
              Static metadata cannot establish runtime verification or consumption. EG-1 remains unassessed
              until the deployed gate passes the separate runtime conformance suite.
            </p>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
              <button onClick={() => setText(EXAMPLE_VULNERABLE)} style={{ ...cta.secondary, cursor: 'pointer' }}>Example: vulnerable MCP</button>
              <button onClick={() => setText(EXAMPLE_SAFE)} style={{ ...cta.secondary, cursor: 'pointer' }}>Example: declared evidence</button>
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
                  <div style={{ fontFamily: font.mono, fontSize: 12, letterSpacing: 1, color: color.t2, textTransform: 'uppercase' }}>Static declaration coverage</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 4 }}>
                    {report.summary.dangerous} dangerous · {report.summary.declared} declared · {report.summary.missing_declaration} missing
                  </div>
                </div>
                <div style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 10, padding: '10px 16px', border: `1px solid ${report.static_result === 'complete' ? color.gold : '#DC2626'}`, borderRadius: 999 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 999, background: report.static_result === 'complete' ? color.gold : '#DC2626', display: 'inline-block' }} />
                  <span style={{ fontFamily: font.mono, fontSize: 12, color: report.static_result === 'complete' ? color.gold : '#DC2626', letterSpacing: 1, textTransform: 'uppercase' }}>
                    Static {report.static_result} · EG-1 not assessed
                  </span>
                </div>
              </div>

              {report.findings.length === 0 ? (
                <p style={{ ...styles.body, marginTop: 24, color: color.gold }}>
                  Every detected dangerous action declares a required receipt input. This is ready for
                  runtime review; it is not proof that any handler enforces the declaration.
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
              A declaration tells reviewers where evidence belongs. Runtime conformance determines whether the control is real.
            </h2>
            <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
              <a href="/gate" style={cta.primary}>Add EMILIA Gate</a>
              <a href="/fire-drill/cf-1" style={cta.secondary}>What is CF-1?</a>
              <a href="/gate#eg1" style={cta.secondary}>Run EG-1</a>
              <a href="/fire-drill/gallery" style={cta.secondary}>Declaration index</a>
              <Link href="/fire-drill/report" style={cta.secondary}>The Report</Link>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
