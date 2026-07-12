// SPDX-License-Identifier: Apache-2.0
// Model-to-Matter - a verifiable clearance boundary between frontier models
// and physical execution. Content traced to docs/verticals/MODEL-TO-MATTER.md.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';

// The six questions existing controls already answer, and the one the executor
// still needs answered before it acts.
const EXISTING_CONTROLS = [
  'Was this model artifact signed?',
  'Did a safety evaluation run?',
  'Is this researcher or institution authorized?',
  'Did a biosafety reviewer approve the protocol?',
  'Did a domain-specific screening service pass the material request?',
  'Did a responsible human approve execution?',
];

// The live sequence a visitor should see: clear once, then refuse under
// mutation and replay. Traced to the demo's exercised properties.
const SEQUENCE = [
  {
    tag: 'CLEAR ONCE',
    accent: 'green',
    line: 'All six pinned authorities agree on this exact action. The executor consumes the single-use clearance and runs the step, one time.',
    verdict: 'clear_to_execute',
  },
  {
    tag: 'REFUSE - MUTATION',
    accent: 'red',
    line: 'One parameter changes after clearance (a facility, a destination, a materials commitment). The action digest changes, so the clearance no longer matches.',
    verdict: 'do_not_execute_action_mismatch',
  },
  {
    tag: 'REFUSE - REPLAY',
    accent: 'red',
    line: 'The same cleared action is presented again, or through a second independently issued challenge. The action digest is already consumed. Only one execution ever wins.',
    verdict: 'do_not_execute_already_consumed',
  },
];

const PROVES = [
  'A named, accountable human authorized this exact action, under a device-bound ceremony.',
  'Every evidence leg the executor pinned was present, fresh, and bound to the same action digest.',
  'The clearance was consumed exactly once. Two challenges cannot each clear the same action.',
  'The whole record is verifiable offline, later, by a replicating lab, an auditor, or a regulator, without trusting the executor’s own logs.',
];

const DOES_NOT_PROVE = [
  'That the experiment is scientifically safe. If every pinned authority approves something dangerous, the gate cannot independently discover that.',
  'That a sequence was screened. A screening leg reports only what a pinned external screening service signed. Model-to-Matter does no screening itself.',
  'That an authority judged correctly. An accepted signature proves what a pinned issuer stated, not that the statement was right.',
  'Physical truth. An effect statement proves what the executor signed, not that its sensors were honest.',
];

// The six evidence legs. Traced to the adapter schema table in the spec.
const LEGS = [
  ['model_attestation', 'Provider, model, manifest, harness, safeguards.'],
  ['safety_case_attestation', 'Model commitments, safety-case digest, assessment.'],
  ['institutional_authority', 'Organization, principal, action family, purpose, decision.'],
  ['biosafety_review', 'Protocol, material commitment, facility, decision.'],
  ['domain_screening', 'Material commitment, destination, screening-profile digest, decision.'],
  ['human_authorization', 'Approver, decision, assurance class.'],
];

// The attack table. Traced to "Properties exercised in code."
const ATTACKS = [
  ['Missing evidence', 'The graph is short a required leg (no screening, no biosafety sign-off). Refuse, and return a machine-readable follow-up naming only what is missing.'],
  ['Action mutation', 'A field changes after clearance. The server-computed action digest changes, so the clearance stops matching. Refuse.'],
  ['Issuer substitution', 'An evidence artifact is signed by a key the executor never pinned, or an issuer identity is swapped. Refuse.'],
  ['Revocation / expiry', 'An evidence leg is revoked or expired, or revocation state is simply absent. Absence fails closed. Refuse.'],
  ['Concurrent replay', 'The same action is presented twice at once, or across two independently issued challenges. Exactly one wins; the rest refuse.'],
];

export default function ModelToMatterPage() {
  return (
    <>
      <SiteNav activePage="Model-to-Matter" />
      <main style={styles.page}>

        {/* Hero */}
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 48 }}>
          <div style={styles.eyebrow}>MODEL-TO-MATTER</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 940 }}>
            A verifiable clearance boundary between frontier models and physical execution.
          </h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 20, fontSize: 18 }}>
            Frontier models now propose experiments and drive automated labs. Before a
            proposed step becomes matter, the executor should require one thing: proof
            that every authority it trusts agreed on this exact model, protocol, material,
            facility, and human approver, and that the step runs exactly once. Model-to-Matter
            is that gate. It composes with screening and safety review; it does not replace them.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href="mailto:team@emiliaprotocol.ai?subject=Pilot%20the%20Model-to-Matter%20gate" style={cta.primary}>Pilot the gate</a>
            <a href={`${REPO}/blob/main/docs/verticals/MODEL-TO-MATTER.md`} style={cta.secondary}>Read the spec</a>
          </div>
          <p style={{ fontSize: 13, color: color.t3, marginTop: 18, maxWidth: 760, lineHeight: 1.7 }}>
            Status: reference profile and adversarial demonstration, July 2026. Open, Apache-2.0,
            with running code and a public threat model. This profile has not been deployed in a
            wet lab and claims no commercial or research partnership.
          </p>
        </section>

        {/* The missing boundary */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE MISSING BOUNDARY</div>
          <h2 style={{ ...styles.h2, maxWidth: 780 }}>
            Existing controls answer six questions. The executor still needs the seventh.
          </h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Each of these is real, and each is answered by a different party at a different time:
          </p>
          <div style={{ marginTop: 12 }}>
            {EXISTING_CONTROLS.map((q, i) => (
              <div key={i} style={{ display: 'flex', gap: 20, padding: '12px 0', borderTop: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 13, color: color.t3, fontWeight: 600, minWidth: 24 }}>{i + 1}</div>
                <div style={{ ...styles.body, fontSize: 15, margin: 0, maxWidth: 700 }}>{q}</div>
              </div>
            ))}
          </div>
          <div style={{ ...styles.card, marginTop: 28, borderLeft: `3px solid ${color.gold}`, maxWidth: 820 }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>
              The question the executor must answer before it acts
            </div>
            <div style={{ ...styles.body, fontSize: 17, marginTop: 12, marginBottom: 0, color: color.t1 }}>
              Do all required authorities agree about this exact model, harness, protocol,
              material commitment, destination, facility, purpose, and one-time execution?
            </div>
          </div>
        </section>

        {/* Live demo sequence */}
        <section style={{ ...styles.sectionWide, ...styles.sectionAlt }}>
          <div style={styles.eyebrow}>SEE IT: EXECUTE, REFUSE, REPLAY</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>
            A structurally valid proposal is not permission to execute.
          </h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            The demonstration runs three outcomes against a synthetic, benign executor.
            Legitimate evidence clears the exact action once; mutation and replay refuse.
          </p>
          <div style={{ marginTop: 24, display: 'grid', gap: 14 }}>
            {SEQUENCE.map((s) => (
              <div key={s.tag} style={{ ...styles.card, padding: 22, borderLeft: `3px solid ${color[s.accent]}`, display: 'flex', gap: 20, alignItems: 'flex-start', flexWrap: 'wrap' }}>
                <div style={{ minWidth: 150 }}>
                  <span style={{ fontFamily: font.mono, fontWeight: 700, fontSize: 11.5, letterSpacing: 1, textTransform: 'uppercase', color: '#fff', background: color[s.accent], padding: '5px 10px', borderRadius: radius.sm }}>{s.tag}</span>
                </div>
                <div style={{ flex: 1, minWidth: 260 }}>
                  <div style={{ ...styles.cardBody, fontSize: 15, lineHeight: 1.7, color: color.t2 }}>{s.line}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 12.5, color: s.accent === 'green' ? color.green : color.red, marginTop: 10 }}>&rarr; {s.verdict}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 24, padding: 20, background: color.t1, borderRadius: radius.base, fontFamily: font.mono, fontSize: 13.5, color: '#E7E5E4', overflowX: 'auto' }}>
            <div style={{ color: color.t3, fontSize: 11, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 10 }}>Run the real demo locally</div>
            <div>git clone {REPO}</div>
            <div>node examples/model-to-matter/demo.mjs</div>
            <div style={{ color: '#78716C' }}>npx vitest run tests/model-to-matter.test.js</div>
          </div>
        </section>

        {/* What it proves / does not prove */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE PRECISE CLAIM</div>
          <h2 style={{ ...styles.h2, maxWidth: 820 }}>
            Model-to-Matter is safety-process enforcement, not scientific safety expertise.
          </h2>
          <p style={{ ...styles.body, maxWidth: 780 }}>
            It proves that an executor applied its pinned clearance process to one exact action,
            once. It does not prove the process was scientifically correct, or that no physical
            path bypassed the gate.
          </p>
          <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
            <div style={{ ...styles.card, padding: 26, borderTop: `3px solid ${color.green}` }}>
              <div style={{ fontFamily: font.mono, fontSize: 12, color: color.green, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>What it proves</div>
              <ul style={{ ...styles.list, marginTop: 14, fontSize: 14.5 }}>
                {PROVES.map((p, i) => <li key={i} style={{ marginBottom: 10 }}>{p}</li>)}
              </ul>
            </div>
            <div style={{ ...styles.card, padding: 26, borderTop: `3px solid ${color.t3}` }}>
              <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>What it does not prove</div>
              <ul style={{ ...styles.list, marginTop: 14, fontSize: 14.5 }}>
                {DOES_NOT_PROVE.map((p, i) => <li key={i} style={{ marginBottom: 10 }}>{p}</li>)}
              </ul>
            </div>
          </div>
        </section>

        {/* Complete mediation assumption */}
        <section style={styles.section}>
          <div style={styles.eyebrow}>DEPLOYMENT ASSUMPTION</div>
          <h2 style={styles.h2}>Complete mediation.</h2>
          <p style={styles.body}>
            The guarantee holds only under one condition: every protected execution path must
            traverse the gate. If the executor is the sole route to physical action, as a cloud
            lab or a synthesis provider is for its own instruments, then the clearance is
            authoritative. If a step can execute around the gate, the guarantee narrows to the
            paths that went through it.
          </p>
          <p style={styles.body}>
            This is the standard reference-monitor requirement, stated plainly: the gate is
            useful exactly to the degree that it mediates completely. Model-to-Matter makes the
            mediated decision portable and offline-verifiable. It does not, by itself, prove that
            no unmediated path existed.
          </p>
        </section>

        {/* Six evidence legs */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>SIX EVIDENCE LEGS</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>An AND over six signed facts, joined by one action digest.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            The executor pins each issuer key and requires all six. Each artifact is
            domain-separated, Ed25519-signed, bound to the exact action digest, and time-bounded.
            The executor owns the acceptance profile and cannot be talked into weakening it.
          </p>
          <div style={{ marginTop: 24, ...grid.auto(300) }}>
            {LEGS.map(([id, desc]) => (
              <div key={id} style={{ ...styles.card, padding: 22 }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 0.5 }}>{id}</div>
                <div style={{ ...styles.cardBody, marginTop: 10 }}>{desc}</div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 20, maxWidth: 760, lineHeight: 1.7 }}>
            The adapters carry no raw material. Sequences, FASTA, protocol text, prompts, and
            reasoning traces are forbidden; an evidence leg carries a signed commitment, not the
            payload. The server computes the action digest, so a presenter cannot choose it.
          </p>
        </section>

        {/* Attack table */}
        <section style={{ ...styles.sectionWide, ...styles.sectionAlt }}>
          <div style={styles.eyebrow}>WHAT THE GATE REFUSES</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>The refuse side is the security claim.</h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            Every refusal below is exercised in the public test contract, not asserted.
          </p>
          <div style={{ marginTop: 20, overflowX: 'auto' }}>
            <table style={{ borderCollapse: 'collapse', width: '100%', minWidth: 640 }}>
              <thead>
                <tr>
                  <th style={{ ...styles.tableHead, width: '26%' }}>Attack</th>
                  <th style={styles.tableHead}>What the gate does</th>
                </tr>
              </thead>
              <tbody>
                {ATTACKS.map(([a, d]) => (
                  <tr key={a}>
                    <td style={{ ...styles.tableCell, fontFamily: font.mono, fontSize: 13, color: color.t1, verticalAlign: 'top' }}>{a}</td>
                    <td style={{ ...styles.tableCell }}>{d}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Run it / spec / code + CTA */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>OPEN AND RUNNABLE</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Read it, run it, break it.</h2>
          <div style={{ marginTop: 24, ...grid.auto(240) }}>
            <a href={`${REPO}/blob/main/docs/verticals/MODEL-TO-MATTER.md`} style={{ ...styles.card, padding: 22, textDecoration: 'none' }}>
              <div style={{ ...styles.h3, fontSize: 17 }}>Public spec</div>
              <div style={{ ...styles.cardBody, marginTop: 6 }}>The reference profile, portable objects, and threat model.</div>
            </a>
            <a href={`${REPO}/blob/main/examples/model-to-matter/demo.mjs`} style={{ ...styles.card, padding: 22, textDecoration: 'none' }}>
              <div style={{ ...styles.h3, fontSize: 17 }}>Runnable demo</div>
              <div style={{ ...styles.cardBody, marginTop: 6 }}>One command. Watch clear, then refuse under mutation and replay.</div>
            </a>
            <a href={`${REPO}/blob/main/tests/model-to-matter.test.js`} style={{ ...styles.card, padding: 22, textDecoration: 'none' }}>
              <div style={{ ...styles.h3, fontSize: 17 }}>Adversarial tests</div>
              <div style={{ ...styles.cardBody, marginTop: 6 }}>The refuse cases, exercised in CI on every change.</div>
            </a>
            <a href={REPO} style={{ ...styles.card, padding: 22, textDecoration: 'none' }}>
              <div style={{ ...styles.h3, fontSize: 17 }}>Apache-2.0 code</div>
              <div style={{ ...styles.cardBody, marginTop: 6 }}>Open standard. The verifier is free forever.</div>
            </a>
          </div>
          <div style={{ ...styles.card, marginTop: 36, padding: 32, textAlign: 'center', borderTop: `3px solid ${color.gold}` }}>
            <div style={{ ...styles.h2, maxWidth: 640, margin: '0 auto 12px' }}>
              If you run an executor, pilot the gate.
            </div>
            <p style={{ ...styles.body, maxWidth: 620, margin: '0 auto 22px', fontSize: 15 }}>
              For cloud labs, synthesis providers, and lab-automation platforms: return the
              challenge before your instruments act, and refuse anything that has not cleared.
              A pilot needs adapters, not replacement systems.
            </p>
            <a href="mailto:team@emiliaprotocol.ai?subject=Pilot%20the%20Model-to-Matter%20gate" style={cta.primary}>Pilot the gate</a>
          </div>
        </section>

      </main>
      <SiteFooter />
    </>
  );
}
