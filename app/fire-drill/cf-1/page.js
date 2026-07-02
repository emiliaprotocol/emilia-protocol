// SPDX-License-Identifier: Apache-2.0
// /fire-drill/cf-1 - the category-level Consequence Firewall conformance page.
// CF-1 sits above RR-1/GG-1/EG-1: a public, earned definition for "this is a
// real firewall for consequential machine action, not just a logo."

import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

export const metadata = {
  title: 'CF-1 — Consequence Firewall conformance for AI agents | EMILIA',
  description:
    'CF-1 is the earned conformance badge for a consequence firewall: missing receipt refused, wrong authority refused, weak assurance refused, execution mismatch refused, replay and tamper refused, evidence verifiable offline.',
  alternates: { canonical: '/fire-drill/cf-1' },
};

const BADGE = 'https://www.emiliaprotocol.ai/badges/cf-1.svg';
const BADGE_MD = `[![Consequence Firewall: CF-1](${BADGE})](https://www.emiliaprotocol.ai/fire-drill/cf-1)`;

const CHECKS = [
  ['consequential_action_declared', 'The action is explicitly classified as consequential / high risk.'],
  ['missing_receipt_refused', 'No receipt means no mutation; the gate challenges before execution.'],
  ['wrong_authority_refused', 'Untrusted, revoked, or out-of-scope authorities cannot authorize the action.'],
  ['weak_assurance_refused', 'A software receipt cannot satisfy a Class-A or quorum action.'],
  ['execution_mismatch_refused', 'Executor-observed fields must match the signed action.'],
  ['valid_receipt_runs_once', 'A valid receipt lets the exact action run exactly once.'],
  ['replay_refused', 'The same receipt cannot be reused.'],
  ['tamper_refused', 'Changing a signed material field invalidates the receipt.'],
  ['evidence_verifies_offline', 'The allowed run emits evidence a third party can verify without trusting the operator.'],
];

const PROFILES = [
  ['RR-1', 'Receipt Required for one MCP / HTTP tool', 'Entry rail: proves missing, valid, replay, and tamper behavior.'],
  ['EG-1', 'EMILIA Gate runtime harness', 'Reference CF-1 runtime profile: proves the firewall checks end to end.'],
  ['GG-1', 'GovGuard fraud-control profile', 'Government vertical profile: wrong org, wrong approver, Class-A, replay, tamper, execution mismatch, evidence export.'],
];

export default function CF1Page() {
  return (
    <>
      <SiteNav activePage="Fire Drill" />
      <main style={styles.page}>
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 32 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>CF-1 · CONSEQUENCE FIREWALL, LEVEL 1</div>
            <h1 style={{ ...styles.h1, marginTop: 14, maxWidth: 900 }}>
              A badge for the one thing that matters: the action cannot run without accountable proof.
            </h1>
            <p style={{ ...styles.lead, maxWidth: 780, marginTop: 16 }}>
              CF-1 is the minimum conformance bar for calling an integration a Consequence Firewall
              for AI agents or other machine actors. It is earned by a reproducible refusal sequence,
              not asserted in copy.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 28, flexWrap: 'wrap' }}>
              <Link href="/gate#eg1" style={cta.primary}>Run the reference harness</Link>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/CONSEQUENCE-FIREWALL-CONFORMANCE.md" target="_blank" rel="noopener noreferrer" style={cta.secondary}>Read the spec</a>
              <Link href="/try/receipt-required" style={cta.secondary}>Try to break it</Link>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 18 }}>
          <div style={styles.container}>
            <div style={{
              display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap',
              border: `1px solid ${color.border}`, borderRadius: 12, padding: '22px 24px', background: '#0b0e14',
            }}>
              {/* eslint-disable-next-line @next/next/no-img-element -- static SVG badge, next/image is overkill */}
              <img src="/badges/cf-1.svg" alt="Consequence Firewall: CF-1" width={212} height={20} />
              <p style={{ ...styles.body, fontSize: 14, color: 'rgba(250,250,249,0.72)', margin: 0, flex: 1, minWidth: 280 }}>
                The narrow claim: a consequential action cannot mutate the world unless a valid,
                in-scope, sufficiently assured, non-replayed authorization receipt passes before
                execution, and the evidence can be verified offline.
              </p>
            </div>
            <p style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 12 }}>
              Earn it, then add the badge to your README:
            </p>
            <pre style={{
              fontFamily: font.mono, fontSize: 12.5, color: '#D6D3D1', background: '#0b0e14',
              border: `1px solid ${color.border}`, borderRadius: 8, padding: '12px 14px', overflowX: 'auto', marginTop: 6,
            }}>{BADGE_MD}</pre>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.container}>
            <h2 style={{ ...styles.h2 }}>What CF-1 certifies</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 12 }}>
              Nine behaviors on a real guarded action. Passing means the integration enforces the
              gate. Failing any one means the badge is not earned.
            </p>
            <div style={{ marginTop: 18, borderTop: `1px solid ${color.border}` }}>
              {CHECKS.map(([id, claim], i) => (
                <div key={id} style={{ display: 'grid', gridTemplateColumns: '40px minmax(0, 1fr)', gap: 18, padding: '14px 0', borderBottom: `1px solid ${color.border}`, alignItems: 'baseline' }}>
                  <span style={{ fontFamily: font.mono, fontSize: 13, color: color.gold }}>{String(i + 1).padStart(2, '0')}</span>
                  <span>
                    <span style={{ fontFamily: font.mono, fontSize: 12.5, color: color.t1, display: 'block', overflowWrap: 'anywhere' }}>{id}</span>
                    <span style={{ ...styles.body, fontSize: 14, color: color.t2, margin: '6px 0 0', display: 'block' }}>{claim}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 0 }}>
          <div style={styles.container}>
            <h2 style={{ ...styles.h2 }}>How it relates to RR-1, EG-1, and GG-1</h2>
            <p style={{ ...styles.body, maxWidth: 720, marginTop: 12 }}>
              CF-1 is the category-level standard. The existing badges are profile-specific ways to
              prove part or all of the same invariant.
            </p>
            <div style={{ marginTop: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 14 }}>
              {PROFILES.map(([name, scope, relationship]) => (
                <div key={name} style={{ ...styles.card, padding: 22 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 1 }}>{name}</div>
                  <h3 style={{ ...styles.h3, marginTop: 8, fontSize: 17 }}>{scope}</h3>
                  <p style={{ ...styles.body, fontSize: 14, color: color.t2, marginTop: 10 }}>{relationship}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, background: '#1C1917', color: '#FAFAF9', borderTop: `1px solid ${color.border}` }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>REFERENCE PROOF</div>
            <h2 style={{ ...styles.h2, color: '#FAFAF9', marginTop: 12, maxWidth: 760 }}>
              The reference Gate earns CF-1 by passing EG-1 plus the wrong-authority negative test.
            </h2>
            <pre style={{
              fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.8, color: '#D6D3D1',
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 8, padding: 22, margin: '28px 0 0', overflowX: 'auto', whiteSpace: 'pre',
            }}>{`node packages/gate/eg1.mjs   # prints "EG-1 Enforced" — the eight runtime checks`}</pre>
            <p style={{ ...styles.body, fontSize: 14, color: 'rgba(250,250,249,0.68)', maxWidth: 720, marginTop: 18 }}>
              The dedicated wrong-authority and allow-all / deny-all negative checks are part of the
              EMILIA Gate conformance suite. CF-1 is not a fraud score or a guarantee that the human
              made a good decision. It proves the enforcement point exists, fails closed, and leaves
              portable evidence.
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
