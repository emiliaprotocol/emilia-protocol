'use client';

/**
 * /demo — "The Agent That Tried To" live crash test.
 * @license Apache-2.0
 *
 * An autonomous AI agent is manipulated (prompt injection) into a catastrophic
 * action. EMILIA evaluates it at the pre-execution moment and blocks it with a
 * signed refusal — the agent cannot self-authorize. Two independent humans then
 * sign off, and the action commits with a cryptographic receipt.
 *
 * ENFORCED scenarios are decided by the real production policy engine
 * (/api/demo/crash → evaluateGuardPolicy). ILLUSTRATIVE scenarios are labeled.
 */

import { useState } from 'react';
import Link from 'next/link';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { CRASH_SCENARIOS } from '@/lib/crash-scenarios';
import { styles, color, font, radius, cta } from '@/lib/tokens';

const EASE = [0.23, 1, 0.32, 1] as const;
const fmtUsd = (n) => (typeof n === 'number' ? `$${n.toLocaleString()}` : null);

export default function DemoPage(): React.JSX.Element {
  const [activeId, setActiveId] = useState(CRASH_SCENARIOS[0].id);
  const [phase, setPhase] = useState('idle'); // idle | blocked | committed
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  // activeId is always seeded from CRASH_SCENARIOS (initial state + selectScenario,
  // which only ever receives an id from CRASH_SCENARIOS.map), so this lookup always hits.
  const s = CRASH_SCENARIOS.find((x) => x.id === activeId)!;

  function selectScenario(id) {
    setActiveId(id);
    setPhase('idle');
    setResult(null);
  }

  async function execute() {
    setLoading(true);
    try {
      const res = await fetch(`/api/demo/crash/${activeId}`);
      const data = await res.json();
      setResult(data);
      setPhase(data.signoff_required ? 'blocked' : 'committed');
    } catch {
      setResult({ error: 'Request failed — try again.' });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <SiteNav activePage="Demo" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 96, paddingBottom: 40 }}>
        <div style={{ ...styles.eyebrow, color: color.red }}>● Live crash test</div>
        <h1 style={{ ...styles.h1Large }}>
          The agent that <span style={{ color: color.gold }}>tried to.</span>
        </h1>
        <p style={{ ...styles.body, maxWidth: 640, fontSize: 18, color: color.t2 }}>
          Watch an autonomous AI agent get manipulated into a catastrophic action — and watch
          EMILIA stop it at the pre-execution moment, with a <strong style={{ color: color.t1 }}>signed
          refusal</strong>. Nothing irreversible without a signed human yes.
        </p>
      </section>

      {/* Scenario tabs */}
      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 12 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {CRASH_SCENARIOS.map((sc) => {
            const on = sc.id === activeId;
            return (
              <button
                key={sc.id}
                onClick={() => selectScenario(sc.id)}
                style={{
                  fontFamily: font.mono,
                  fontSize: 12,
                  letterSpacing: 0.5,
                  padding: '10px 14px',
                  borderRadius: radius.sm,
                  cursor: 'pointer',
                  border: `1px solid ${on ? color.t1 : color.border}`,
                  background: on ? color.t1 : color.card,
                  color: on ? color.bg : color.t2,
                  whiteSpace: 'nowrap',
                }}
              >
                {sc.actor}
              </button>
            );
          })}
        </div>
      </section>

      {/* Two-column: setup + console */}
      <section style={{ ...styles.section, paddingTop: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, alignItems: 'start' }} className="ep-demo-grid">
          {/* Left — the setup */}
          <div>
            <ModeBadge mode={s.mode} />
            <h2 style={{ ...styles.h2, marginTop: 12 }}>{s.title}</h2>
            <Field label="The agent's job">{s.agentTask}</Field>
            <Field label="The manipulation" tone="red">
              {s.injection}
            </Field>
            <Field label="What the agent is about to do" tone="red">
              {s.riskyAction}
            </Field>
            {s.costUsd != null && (
              <div style={{ marginTop: 16, fontFamily: font.mono, fontSize: 13, color: color.t3 }}>
                AT RISK: <span style={{ color: color.red, fontWeight: 700 }}>{fmtUsd(s.costUsd)}</span> {s.costLabel}
              </div>
            )}
          </div>

          {/* Right — the console */}
          <div
            style={{
              border: `1px solid ${color.border}`,
              borderRadius: radius.base,
              background: '#0F172A',
              padding: 20,
              minHeight: 320,
            }}
          >
            <div style={{ fontFamily: font.mono, fontSize: 11, color: '#94A3B8', letterSpacing: 1, marginBottom: 14 }}>
              AGENT CONSOLE · pre-execution gate
            </div>

            {phase === 'idle' && (
              <div>
                <pre style={consolePre}>
{`agent> intent: ${s.actionType}
agent> about to execute…
EMILIA> evaluating action before it runs`}
                </pre>
                <button onClick={execute} disabled={loading} style={execBtn}>
                  {loading ? 'Evaluating…' : '▶ Let the agent execute'}
                </button>
              </div>
            )}

            {phase === 'blocked' && result?.blocked_response && (
              <BlockedCard result={result} onSignoff={() => setPhase('committed')} />
            )}

            {phase === 'committed' && result && (
              <CommittedCard result={result} />
            )}
          </div>
        </div>
      </section>

      {/* Closing */}
      <section style={{ ...styles.sectionAlt }}>
        <div style={{ ...styles.section, textAlign: 'center', paddingTop: 56, paddingBottom: 64 }}>
          <h2 style={{ ...styles.h2, fontSize: 28 }}>This is the whole point of EMILIA.</h2>
          <p style={{ ...styles.body, maxWidth: 560, margin: '0 auto 24px' }}>
            Every high-risk action an AI agent takes is evaluated before it runs. If it’s
            irreversible, a real human has to sign off — and there’s a cryptographic receipt either
            way. Formally verified. Open protocol.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link href="/r/example" className="ep-cta" style={cta.primary}>See a real signed receipt →</Link>
            <Link href="/spec" className="ep-cta-secondary" style={cta.secondary}>Read the spec</Link>
          </div>
        </div>
      </section>

      <SiteFooter />
      <style>{`@media (max-width: 760px){ .ep-demo-grid{ grid-template-columns:1fr !important; } }`}</style>
    </div>
  );
}

// ── Blocked card ──────────────────────────────────────────────────────────
function BlockedCard({ result, onSignoff }) {
  const b = result.blocked_response;
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: EASE }}
    >
      <div
        style={{
          border: `2px solid ${color.red}`,
          borderRadius: radius.base,
          background: 'rgba(220,38,38,0.08)',
          padding: 16,
          marginBottom: 14,
        }}
      >
        <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 700, color: '#F87171', letterSpacing: 1 }}>
          ⛔ BLOCKED — 403 SIGNOFF_REQUIRED
        </div>
        <div style={{ fontFamily: font.sans, fontSize: 14, color: '#FCA5A5', marginTop: 8, lineHeight: 1.5 }}>
          {b.detail}
        </div>
      </div>
      <div style={{ fontFamily: font.mono, fontSize: 11, color: '#94A3B8', marginBottom: 6 }}>
        WHY — policy reasons
      </div>
      <ul style={{ margin: '0 0 12px', paddingLeft: 18, color: '#CBD5E1', fontSize: 13, lineHeight: 1.6 }}>
        {(b.reasons || []).map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
        {(result.scenario?.gateCitation ? [result.scenario.gateCitation] : []).map((c, i) => (
          <span key={i} style={{ fontFamily: font.mono, fontSize: 10, color: '#94A3B8' }}>{c}</span>
        ))}
      </div>
      <pre style={consolePre}>{JSON.stringify(b, null, 2)}</pre>
      <button onClick={onSignoff} style={{ ...execBtn, background: color.gold }}>
        ✓ Run the human signoff →
      </button>
    </motion.div>
  );
}

// ── Committed card ────────────────────────────────────────────────────────
function CommittedCard({ result }) {
  const c = result.committed;
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }}>
      {c && (
        <>
          <div
            style={{
              border: `2px solid ${color.green}`,
              borderRadius: radius.base,
              background: 'rgba(22,163,74,0.10)',
              padding: 16,
              marginBottom: 14,
            }}
          >
            <div style={{ fontFamily: font.mono, fontSize: 13, fontWeight: 700, color: '#4ADE80', letterSpacing: 1 }}>
              ✓ COMMITTED — after two independent approvals
            </div>
          </div>
          <div style={{ fontFamily: font.mono, fontSize: 11, color: '#94A3B8', marginBottom: 6 }}>SIGNOFF</div>
          <div style={{ marginBottom: 6, fontSize: 12, color: '#F87171', fontFamily: font.mono }}>
            ✗ self-approval rejected — {c.self_approval_rejected.error}
          </div>
          {c.approvers.map((a) => (
            <div key={a.id} style={{ fontSize: 13, color: '#CBD5E1', fontFamily: font.mono }}>
              ✓ {a.role} — {a.id}
            </div>
          ))}
        </>
      )}
      <div style={{ fontFamily: font.mono, fontSize: 11, color: '#94A3B8', margin: '14px 0 6px' }}>
        SIGNED RECEIPT (Ed25519) — verify it yourself
      </div>
      <pre style={consolePre}>{JSON.stringify(result.receipt, null, 2)}</pre>
      <div style={{ fontFamily: font.mono, fontSize: 10, color: '#64748B', marginTop: 8, wordBreak: 'break-all' }}>
        public_key: {result.public_key}
      </div>
    </motion.div>
  );
}

// ── small helpers ─────────────────────────────────────────────────────────
function ModeBadge({ mode }) {
  const enforced = mode === 'enforced';
  return (
    <span
      style={{
        fontFamily: font.mono,
        fontSize: 10,
        letterSpacing: 1.5,
        padding: '3px 8px',
        borderRadius: radius.sm,
        border: `1px solid ${enforced ? color.green : color.gold}`,
        color: enforced ? color.green : color.gold,
        textTransform: 'uppercase',
      }}
    >
      {enforced ? 'Enforced · live policy engine' : 'Illustrative pattern'}
    </span>
  );
}

function Field({ label, children, tone }: { label: any; children: any; tone?: any }) {
  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, color: color.t3, textTransform: 'uppercase', marginBottom: 6 }}>
        {label}
      </div>
      <div
        style={{
          fontFamily: font.sans,
          fontSize: 14,
          lineHeight: 1.6,
          color: tone === 'red' ? color.t1 : color.t2,
          padding: tone === 'red' ? '10px 12px' : 0,
          background: tone === 'red' ? 'rgba(220,38,38,0.05)' : 'transparent',
          borderLeft: tone === 'red' ? `2px solid ${color.red}` : 'none',
          borderRadius: tone === 'red' ? radius.sm : 0,
        }}
      >
        {children}
      </div>
    </div>
  );
}

const consolePre: React.CSSProperties = {
  fontFamily: font.mono,
  fontSize: 11.5,
  lineHeight: 1.6,
  color: '#CBD5E1',
  background: 'rgba(2,6,23,0.6)',
  border: '1px solid rgba(148,163,184,0.18)',
  borderRadius: 6,
  padding: 12,
  margin: '0 0 14px',
  overflowX: 'auto',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
};

const execBtn: React.CSSProperties = {
  fontFamily: font.sans,
  fontSize: 14,
  fontWeight: 600,
  color: '#FFFFFF',
  background: color.red,
  border: 'none',
  borderRadius: radius.sm,
  padding: '12px 18px',
  cursor: 'pointer',
  width: '100%',
};
