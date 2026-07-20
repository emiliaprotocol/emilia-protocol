// SPDX-License-Identifier: Apache-2.0
// EMILIA Gate — the Consequence Firewall. Deny-by-default enforcement for
// consequential machine actions at the actuator boundary. Product landing page.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const GATED = [
  { type: 'payment.release', label: 'Money movement', sample: 'Release payment, wire transfer, treasury disbursement', tier: 'Class A' },
  { type: 'payment.bank_details.change', label: 'Bank-detail change', sample: 'Vendor, beneficiary, payroll, or payout destination update', tier: 'Class A' },
  { type: 'deploy.production', label: 'Production deploy', sample: 'Deploy, migration, secret rotation, production config', tier: 'Quorum' },
  { type: 'permission.admin.change', label: 'Permission change', sample: 'Admin grant, role expansion, privileged scope change', tier: 'Quorum' },
  { type: 'data.export', label: 'Sensitive data export', sample: 'Bulk customer, claims, patient, citizen, or employee data export', tier: 'Class A' },
  { type: 'record.delete', label: 'Record deletion', sample: 'Delete or destroy system-of-record state', tier: 'Class A' },
  { type: 'regulated.decision.override', label: 'Regulated override', sample: 'Benefit, credit, clinical, compliance, or safety decision override', tier: 'Quorum' },
];

const LOOP = [
  { n: '1', title: 'Request', body: 'An agent or system requests a consequential action at the actuator boundary.' },
  { n: '2', title: 'Challenge', body: 'If the action is guarded and no valid receipt is present, the gate returns 428 Receipt Required and tells the agent exactly what to bring.' },
  { n: '3', title: 'Authorize', body: 'A directory-bound approver — or a quorum, for hard cuts — signs the exact action on an enrolled device-bound authenticator.' },
  { n: '4', title: 'Verify', body: 'Offline, fail-closed: authority (pinned key), action-binding, assurance tier, freshness, one-time consumption — no trust in the operator.' },
  { n: '5', title: 'Execute', body: 'Only a passing check reaches the actuator. Deny by default; absence of a receipt is the anomaly, not the default.' },
  { n: '6', title: 'Execution receipt', body: 'On execution the gate emits proof bound to the exact authorization decision — the artifact an auditor, regulator, or incident review replays.' },
];

const SURFACES = [
  { type: 'MCP', label: 'Agent tools', body: 'Wrap any MCP tool in one line (gateMcpTool); a dangerous call without a receipt returns 428.', status: 'Shipped' },
  { type: 'API', label: 'HTTP middleware', body: 'Express / Connect / Next / Go — protect POST / PUT / PATCH / DELETE.', status: 'Shipped' },
  { type: 'FRAMEWORKS', label: 'Agent runtimes', body: 'OpenAI, LangChain, CrewAI, AutoGen — guard tool calls in one wrap().', status: 'Shipped' },
  { type: 'CLOUD', label: 'Infra & platforms', body: 'System-of-record adapters shipped for GitHub, Stripe, Supabase/Postgres, AWS, Kubernetes, Terraform, GCP, Vercel, Cloudflare, Linear, Jira, and Salesforce.', status: 'Shipped' },
  { type: 'ROBOTS', label: 'Actuator sidecar', body: 'A local daemon before motion/tool commands. Pre-authorize a bounded envelope; verify each act offline.', status: 'Reference' },
];

const TIERS = [
  { tier: 'software', body: 'A valid receipt — a software-held key.' },
  { tier: 'class_a', body: 'A device-bound human signoff (WebAuthn / passkey).' },
  { tier: 'quorum', body: 'm-of-n distinct humans — the cryptographic two-person rule.' },
];

const DEMO = [
  ['read_status', 'passes through'],
  ['release_payment, no receipt', '428 Receipt Required'],
  ['software receipt', 'refused; needs Class A'],
  ['valid receipt, observed drift', 'refused; field binding failed'],
  ['Class A + bound fields', 'runs'],
  ['same receipt again', 'replay refused'],
  ['tampered amount', 'signature rejected'],
];

const RUN = `node packages/gate/demo.mjs

# output:
# release_payment, no receipt       -> REFUSE 428 (receipt_required)
# release_payment, observed drift   -> REFUSE 428 (execution_binding_failed)
# release_payment, class_a + bound  -> ALLOW
# same receipt again                -> REFUSE 428 (replay_refused)
# reliance packet                   -> RELY`;

const EG1 = [
  'missing receipt → 428',
  'software receipt on a Class-A action → refused',
  'observed execution drift → refused',
  'valid Class-A / quorum receipt → runs',
  'same receipt replay → refused',
  'tampered receipt → refused',
  'execution proof binds to the authorization decision',
  'reliance packet returns verdict: rely',
];

const EG1_RUN = `node packages/gate/eg1.mjs

# EG-1 Conformance — does this integration ENFORCE EMILIA Gate?
#   PASS  missing receipt -> 428
#   PASS  software receipt on Class-A action -> refused
#   PASS  observed execution drift -> refused
#   PASS  valid Class-A/quorum receipt -> runs
#   PASS  same receipt replay -> refused
#   PASS  tampered receipt -> refused
#   PASS  execution proof binds to authorization decision
#   PASS  reliance packet returns verdict "rely"
#   ✓ EG-1 Enforced  (8/8)`;

const CODE = `import { createTrustedActionFirewall } from '@emilia-protocol/gate';

const gate = createTrustedActionFirewall({
  trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY],
  store: sharedConsumptionStore,
});

const observedAction = await paymentSystem.describeRelease('pi_123');

const out = await gate.run({
  selector: { protocol: 'mcp', tool: 'release_payment' },
  receipt,
  observedAction,
}, () => paymentSystem.release(observedAction));

if (!out.ok) return out.body; // 428 Receipt Required
return out.packet;            // auditor-ready reliance artifact`;

const RECEIPT_PROGRAM_RUN = `npm run demo:receipt-program

# Parent capability: 1000 USD -> delegated 100 USD
# CAID: recomputed from the exact payment action
# RECEIPT -> MATCH -> RESERVE -> EXECUTE -> COMMIT -> CERTIFY
# Child capability remaining: 50 USD
# Certificate: context-bound and present in the evidence log`;

export default function GatePage() {
  return (
    <>
      <SiteNav activePage="Gate" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA GATE · THE CONSEQUENCE FIREWALL</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Stop consequential machine action before it becomes irreversible.</h1>
            <p style={{ fontFamily: font.mono, color: color.gold, fontSize: 14, fontWeight: 600, marginTop: 18 }}>
              Protocol proves. Gate prevents.
            </p>
            <p style={{ ...styles.lead, maxWidth: 760, marginTop: 16 }}>
              EMILIA Gate sits immediately before protected execution. Before money moves,
              infrastructure changes, regulated records update, or irreversible state changes, Gate
              verifies the exact authority and evidence the resource owner requires, consumes
              accepted authorization once, and records the result.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12, fontSize: 15, color: color.t2 }}>
              On a fully mediated path, missing, stale, mismatched, or replayed evidence never
              reaches mutation. The open Protocol lets the relying party reproduce why the exact
              action passed or failed under its own pinned trust inputs.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/gate/live" style={cta.primary}>Open live Gate</a>
              <a href="/gate/control-plane" style={cta.secondary}>Open control plane</a>
              <a href="#loop" style={cta.secondary}>How it works</a>
              <a href="#surfaces" style={cta.secondary}>Where it runs</a>
              <a href="/try/receipt-required" style={cta.secondary}>Try to break it</a>
              <a href="/fire-drill/cf-1" style={cta.secondary}>CF-1 conformance</a>
              <a href="/pilot?v=gate" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>

        {/* The one line */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE INVARIANT</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 820 }}>
              If the required evidence does not verify, the protected system does not mutate.
            </h2>
            <p style={{ ...styles.body, maxWidth: 680, marginTop: 16 }}>
              The gate is deployed by the resource owner — the bank, the cloud API, the database, the
              robot controller, the grid. An agent that wants to act must bring a receipt the gate
              verifies. The guarantee is only as strong as that mediation: every protected path must
              reach Gate at the actual system of record or actuator. Verification itself is open and
              can run offline without an EMILIA service.
            </p>
          </div>
        </section>

        {/* Run it */}
        <section style={{ ...styles.section, background: '#1C1917', color: '#FAFAF9', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>PROOF IN ONE COMMAND</div>
            <h2 style={{ ...styles.h2, marginTop: 12, color: '#FAFAF9', maxWidth: 760 }}>The product is the refusal sequence.</h2>
            <p style={{ ...styles.body, maxWidth: 700, marginTop: 16, color: 'rgba(250,250,249,0.72)' }}>
              A dangerous action is not argued with. It is challenged, verified, bound to real
              execution fields, consumed once, and turned into a reliance packet. The demo runs
              locally with generated keys; no EMILIA server is trusted.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24, marginTop: 32, alignItems: 'start' }}>
              <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.8, color: '#D6D3D1', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 8, padding: 22, margin: 0, overflowX: 'auto', whiteSpace: 'pre' }}>{RUN}</pre>
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.14)' }}>
                {DEMO.map(([a, b]) => (
                  <div key={a} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 16, padding: '13px 0', borderBottom: '1px solid rgba(255,255,255,0.14)' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 12, color: 'rgba(250,250,249,0.72)' }}>{a}</div>
                    <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, textAlign: 'right' }}>{b}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* What it gates */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHAT IT GATES</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Default packs for high-risk action families.</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              This is not just an amount threshold. EMILIA Gate treats entire action categories as
              high risk and binds the material system-of-record fields for each category.
            </p>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {GATED.map((a) => (
                <div key={a.type} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'baseline' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase' }}>{a.type}</div>
                    <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1, textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{a.tier}</div>
                  </div>
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
                <div key={s.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.border}` }}>
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

        {/* Product architecture */}
        <section style={{ ...styles.section, background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE COMPLETE SYSTEM</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 760 }}>
              Gate enforces. The surrounding layers keep it human, open, and reproducible.
            </h2>
            <div style={{ marginTop: 32, borderTop: `1px solid ${color.border}` }}>
              {[
                ['/product/accountable-signoff', 'Approver Apps', 'Lock the human decision to the exact CAID, show material revisions, and track the consequence without blind replay.'],
                ['/action-escrow', 'Action Escrow', 'Keep document execution, exact release approval, custodian state, and one-time consequence control as separate verifiable rows.'],
                ['/protocol', 'EMILIA Protocol', 'Define the portable evidence and open verification rules beneath Gate.'],
                ['/assurance', 'Assurance Plane', 'Re-perform exact-action evidence, conformance results, and stated formal-model scope; record drift and prepare the technical handoff.'],
              ].map(([href, title, body]) => (
                <a key={title} href={href} className="ep-gate-stack-row" style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 0.7fr) minmax(280px, 1.3fr) auto', gap: 24, alignItems: 'center', padding: '20px 0', borderBottom: `1px solid ${color.border}`, textDecoration: 'none' }}>
                  <strong style={{ ...styles.h3, fontSize: 16 }}>{title}</strong>
                  <span style={{ ...styles.body, fontSize: 14, color: color.t2 }}>{body}</span>
                  <span aria-hidden style={{ color: color.gold }}>&rarr;</span>
                </a>
              ))}
            </div>
          </div>
        </section>

        {/* Standards composition */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>COMPOSE, DON&apos;T REPLACE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 800 }}>
              A distinct job at each authorization layer.
            </h2>
            <p style={{ ...styles.lead, maxWidth: 820, marginTop: 18 }}>
              AgentROA governs calls. ORPRG proves policy permitted the effect. EMILIA proves
              exact authorization by an enrolled approver under the relying party&rsquo;s pinned
              directory, then safely controls consequential outcomes.
            </p>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 16 }}>
              {[
                ['Call governance', 'AgentROA', 'Does the call remain inside the agent’s verified delegated scope?'],
                ['Policy permit', 'ORPRG', 'Does the native policy evidence prove this effect was permitted?'],
                ['Approver authorization + control', 'EMILIA', 'Did the directory-bound approver authorize this exact action, and may the protected executor mutate now?'],
              ].map(([label, title, body]) => (
                <div key={title} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.2, textTransform: 'uppercase' }}>{label}</div>
                  <div style={{ ...styles.h3, fontSize: 18, marginTop: 9 }}>{title}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{body}</div>
                </div>
              ))}
            </div>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 24, fontSize: 14, color: color.t2 }}>
              EMILIA does not collapse machine delegation, machine policy, and human authorization
              into one verdict. CAID can correlate their native action descriptions only under the
              exact mapping profiles the relying party pins. A match is not authorization, and a
              missing or lossy mapping returns <code>INDETERMINATE</code> instead of guessing.
            </p>
          </div>
        </section>

        {/* API */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>THE PRODUCT API</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 780 }}>One ordered path: reserve, execute, commit, prove.</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16 }}>
              `gate.run()` makes the ordering hard to get wrong. It reserves the receipt while the
              action is in flight, commits one-time consumption only after success, releases on
              pre-mutation failure, and returns the reliance packet.
            </p>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 12 }}>
              When an action carries a bounded capability, Gate reserves exact-action or
              CAID-scoped spend before provider entry, refuses overspend and replay, and commits
              after success. If provider entry occurred but the result cannot be established, Gate
              consumes the reservation as indeterminate: no blind retry or refund, and
              reconciliation only from authenticated evidence bound to the same provider,
              operation, and action.
            </p>
            <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.75, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: 8, padding: 22, margin: '28px 0 0', overflowX: 'auto', whiteSpace: 'pre' }}>{CODE}</pre>
            <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
              {[
                ['428 challenge', 'Missing or bad receipt never reaches the mutation.'],
                ['Observed fields', 'Executor binds facts from the real system, not the request body.'],
                ['Execution proof', 'The post-action record commits to the authorization decision hash.'],
                ['Reliance packet', 'Reproducible technical record with checks, evidence head, and limitations.'],
              ].map(([title, body]) => (
                <div key={title} style={{ borderTop: `1px solid ${color.border}`, paddingTop: 14 }}>
                  <div style={{ ...styles.h3, fontSize: 16 }}>{title}</div>
                  <div style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 6 }}>{body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Receipt programs */}
        <section style={{ ...styles.section, background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>RECEIPT PROGRAMS</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 800 }}>
              The instruction, delegated budget, effect, and terminal evidence stay bound.
            </h2>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
              The receipt-program kernel freezes one CAID-bound action and stable operation ID,
              executes it through Gate&apos;s real bounded-capability path, and signs and records a
              content-addressed certificate over the bounded result and Gate evidence. It is a
              developer surface behind the Consequence Firewall, not a second policy engine or
              ledger.
            </p>
            <p style={{ ...styles.body, maxWidth: 760, marginTop: 12 }}>
              Provider deadline expiry, response loss, or invalid output becomes <code>INDETERMINATE</code>.
              The budget and operation remain closed to blind replay. Production requires durable
              capability state, an atomic evidence log, KMS/HSM signing, a pinned certificate
              context, and a pinned result projection. Signing or logging failure preserves the
              Gate outcome without claiming complete proof.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24, marginTop: 28, alignItems: 'start' }}>
              <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.75, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: 8, padding: 22, margin: 0, overflowX: 'auto', whiteSpace: 'pre' }}>{RECEIPT_PROGRAM_RUN}</pre>
              <div style={{ ...styles.card, padding: 24 }}>
                <div style={{ ...styles.h3, fontSize: 17 }}>What the certificate proves</div>
                <p style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 10 }}>
                  Integrity and exact internal binding under a relying-party-pinned operator key
                  and context, including CAID re-performance, action and operation identity,
                  result digest, opcode sequence, authorization-to-execution linkage, and the
                  complete certificate evidence record.
                </p>
                <div style={{ ...styles.h3, fontSize: 17, marginTop: 22 }}>What it does not prove</div>
                <p style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 10 }}>
                  It is not a ZK proof, consensus result, provider attestation, or proof of legal,
                  physical, or commercial correctness. Full re-performance still verifies the
                  referenced authorization, capability, and evidence records under independent
                  trust inputs.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Surfaces */}
        <section id="surfaces" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHERE IT RUNS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>One Gate pattern, several actuator boundaries.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {SURFACES.map((s) => (
                <div key={s.type} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1 }}>{s.type}</div>
                    <div style={{ fontFamily: font.mono, fontSize: 10, color: ['Shipped', 'Built'].includes(s.status) ? color.green : color.t2, letterSpacing: 1, textTransform: 'uppercase' }}>{s.status}</div>
                  </div>
                  <div style={{ ...styles.h3, fontSize: 17, marginTop: 8 }}>{s.label}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{s.body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CF-1 / EG-1 conformance */}
        <section id="eg1" style={{ ...styles.section, background: '#1C1917', color: '#FAFAF9', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>CF-1 / EG-1 CONFORMANCE</div>
            <h2 style={{ ...styles.h2, marginTop: 12, color: '#FAFAF9', maxWidth: 820 }}>
              Does your integration actually enforce the gate — or are you just claiming it?
            </h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 16, color: 'rgba(250,250,249,0.72)' }}>
              CF-1 is a public self-description, not a certification. EG-1 is the runnable Gate
              harness behind it: point the harness at your dangerous action; if it passes all eight
              checks, you have a reproducible conformance record instead of a claim. It makes an open PR crisp:
              <i>“this makes <code>delete_row</code> earn EG-1 / CF-1.”</i>
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24, marginTop: 32, alignItems: 'start' }}>
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.14)' }}>
                {EG1.map((c, i) => (
                  <div key={c} style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 14, padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.14)' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold }}>{String(i + 1).padStart(2, '0')}</div>
                    <div style={{ fontFamily: font.mono, fontSize: 12.5, color: 'rgba(250,250,249,0.82)' }}>{c}</div>
                  </div>
                ))}
              </div>
              <div>
                <pre style={{ fontFamily: font.mono, fontSize: 12, lineHeight: 1.7, color: '#D6D3D1', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 8, padding: 22, margin: 0, overflowX: 'auto', whiteSpace: 'pre' }}>{EG1_RUN}</pre>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 10, marginTop: 20, padding: '10px 16px', border: `1px solid ${color.gold}`, borderRadius: 999 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 999, background: color.green, display: 'inline-block' }} />
                  <span style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 1, textTransform: 'uppercase' }}>EG-1 Enforced</span>
                </div>
                <div style={{ marginTop: 14 }}>
                  {/* eslint-disable-next-line @next/next/no-img-element -- static SVG badge, next/image is overkill */}
                  <img src="/badges/cf-1.svg" alt="Consequence Firewall: CF-1" width={212} height={20} />
                </div>
                <p style={{ ...styles.body, fontSize: 13, color: 'rgba(250,250,249,0.58)', marginTop: 12 }}>
                  Public definition: <a href="/fire-drill/cf-1" style={{ color: color.gold }}>CF-1 Consequence Firewall conformance</a>.
                </p>
              </div>
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
              It cannot constrain a path that bypasses Gate. Complete mediation requires the resource
              owner to place the verifier immediately before every protected mutation and to remove
              alternate execution paths. Necessary, not sufficient.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="/verify" style={cta.primary}>Verify a receipt</a>
              <a href="/assurance" style={cta.secondary}>Re-perform the evidence</a>
              <a href="/pilot?v=gate" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
