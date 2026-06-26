// SPDX-License-Identifier: Apache-2.0
// EMILIA Gate — the Consequence Firewall. Deny-by-default enforcement for
// consequential machine actions at the actuator boundary. Product landing page.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const GATED = [
  { type: 'finance.wire_transfer', label: 'Move money', sample: 'Wire release, beneficiary or bank-detail change' },
  { type: 'devops.deploy', label: 'Change production', sample: 'Deploy, migration, secret rotation, permission grant' },
  { type: 'data.export', label: 'Move or delete data', sample: 'Bulk export, destructive query, record deletion' },
  { type: 'grid.curtailment', label: 'Change energy posture', sample: 'Curtailment / dispatch posture change (GRACE)' },
  { type: 'physical.actuation', label: 'Actuate the physical world', sample: 'Robot motion, tool use, vehicle maneuver' },
  { type: 'agent.tool_call', label: 'Any irreversible agent tool', sample: 'Dangerous MCP / framework tool call' },
];

const LOOP = [
  { n: '1', title: 'Request', body: 'An agent or system requests a consequential action at the actuator boundary.' },
  { n: '2', title: 'Challenge', body: 'If the action is guarded and no valid receipt is present, the gate returns 428 Receipt Required and tells the agent exactly what to bring.' },
  { n: '3', title: 'Authorize', body: 'A named human — or a quorum, for hard cuts — signs the exact action on a device-bound authenticator.' },
  { n: '4', title: 'Verify', body: 'Offline, fail-closed: authority (pinned key), action-binding, assurance tier, freshness, one-time consumption — no trust in the operator.' },
  { n: '5', title: 'Execute', body: 'Only a passing check reaches the actuator. Deny by default; absence of a receipt is the anomaly, not the default.' },
  { n: '6', title: 'Execution receipt', body: 'On execution the gate emits proof bound to the exact authorization decision — the artifact an auditor, regulator, or incident review replays.' },
];

const SURFACES = [
  { type: 'MCP', label: 'Agent tools', body: 'Wrap MCP servers; a dangerous tool call without a receipt returns 428.', status: 'Shipped' },
  { type: 'API', label: 'HTTP middleware', body: 'Express / Connect / Next / Go — protect POST / PUT / PATCH / DELETE.', status: 'Shipped' },
  { type: 'FRAMEWORKS', label: 'Agent runtimes', body: 'OpenAI, LangChain, CrewAI, AutoGen — guard tool calls in one wrap().', status: 'Shipped' },
  { type: 'CLOUD', label: 'Infra & platforms', body: 'GitHub, AWS/IAM, Kubernetes, Terraform, Supabase, Stripe.', status: 'Roadmap' },
  { type: 'ROBOTS', label: 'Actuator sidecar', body: 'A local daemon before motion/tool commands. Pre-authorize a bounded envelope; verify each act offline.', status: 'Reference' },
  { type: 'ATTESTED', label: 'Attested gate', body: 'Prove the gate is actually installed and running via device/workload attestation. Crucial for robots.', status: 'Roadmap' },
];

const TIERS = [
  { tier: 'software', body: 'A valid receipt — a software-held key.' },
  { tier: 'class_a', body: 'A device-bound human signoff (WebAuthn / passkey).' },
  { tier: 'quorum', body: 'm-of-n distinct humans — the cryptographic two-person rule.' },
];

export default function GatePage() {
  return (
    <>
      <SiteNav activePage="Gate" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA GATE · THE CONSEQUENCE FIREWALL</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>The firewall for machine action.</h1>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              Antivirus scanned files. Firewalls filtered packets. EMILIA Gate verifies actions
              before machines change the world. It sits at the actuator boundary and refuses any
              consequential action unless it carries a valid, non-replayed authorization receipt —
              proof a named human approved that exact action.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12, fontSize: 15, color: color.t2 }}>
              Not authentication, not permissions, not anomaly detection. A policy-enforcement point
              that requires portable proof of human authorization before the world is mutated. Deny
              by default. Fail closed.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="#loop" style={cta.primary}>How it works</a>
              <a href="#surfaces" style={cta.secondary}>Where it runs</a>
              <a href="/pilot?v=gate" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>

        {/* The one line */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE INVARIANT</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 820 }}>
              If an agent cannot produce a valid receipt, it cannot change money, code, permissions,
              data, infrastructure, energy, or physical state.
            </h2>
            <p style={{ ...styles.body, maxWidth: 680, marginTop: 16 }}>
              The gate is deployed by the resource owner — the bank, the cloud API, the database, the
              robot controller, the grid. An agent that wants to act must bring a receipt the gate
              verifies. There is no central authority to trust; verification is offline.
            </p>
          </div>
        </section>

        {/* What it gates */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHAT IT GATES</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Consequences, not prompts.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {GATED.map((a) => (
                <div key={a.type} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase' }}>{a.type}</div>
                  <div style={{ ...styles.h3, fontSize: 18, marginTop: 8 }}>{a.label}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 12, color: color.t2 }}>{a.sample}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* The loop */}
        <section id="loop" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE LOOP</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Request → challenge → sign → verify → execute → proof.</h2>
            <div style={{ marginTop: 32 }}>
              {LOOP.map((s) => (
                <div key={s.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.brd}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{s.n}</div>
                  <div>
                    <div style={{ ...styles.h3, fontSize: 18 }}>{s.title}</div>
                    <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 680 }}>{s.body}</div>
                  </div>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, maxWidth: 680, marginTop: 24, fontSize: 14, color: color.t2 }}>
              Assurance tiers set the floor per action: <b style={{ color: color.t1 }}>software</b> — {TIERS[0].body} {' '}
              <b style={{ color: color.t1 }}>class_a</b> — {TIERS[1].body} {' '}
              <b style={{ color: color.t1 }}>quorum</b> — {TIERS[2].body}
            </p>
          </div>
        </section>

        {/* Surfaces */}
        <section id="surfaces" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHERE IT RUNS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>One gate, every actuator boundary.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {SURFACES.map((s) => (
                <div key={s.type} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1 }}>{s.type}</div>
                    <div style={{ fontFamily: font.mono, fontSize: 10, color: s.status === 'Shipped' ? color.green : color.t2, letterSpacing: 1, textTransform: 'uppercase' }}>{s.status}</div>
                  </div>
                  <div style={{ ...styles.h3, fontSize: 17, marginTop: 8 }}>{s.label}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{s.body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Honest boundary */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE HONEST LIMIT</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>It does not stop every bad actor. It makes unreceipted systems untrusted.</h2>
            <p style={{ ...styles.body, maxWidth: 680, marginTop: 16 }}>
              A bad actor can build an unguarded machine. EMILIA Gate makes legitimate
              infrastructure refuse unreceipted consequential actions by default — so the parties
              with leverage (clouds, payment rails, regulators, insurers) can require a receipt.
              That is how TLS, code signing, and SOC 2 won: not by stopping every bad actor, but by
              making serious buyers reject systems that lack the control. Necessary, not sufficient.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/verify" style={cta.primary}>Verify a receipt</a>
              <a href="/agent-guard" style={cta.secondary}>Agent guard</a>
              <a href="/pilot?v=gate" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
