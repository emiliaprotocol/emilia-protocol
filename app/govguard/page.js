// SPDX-License-Identifier: Apache-2.0
// EP GovGuard — pre-execution control for government benefit/payment changes.
// Landing page for the GovGuard product wrapper around EP primitives.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'EMILIA GovGuard — Pre-Execution Trust for Government Programs',
  description:
    'Pre-execution control for government benefit/payment changes. Bind actor, authority, policy, and exact action context before the change executes. Observe-only, warn, or enforce mode.',
};

const PROTECTED_ACTIONS = [
  { type: 'benefit_bank_account_change', label: 'Benefit bank-account change', sample: 'Caseworker changes a claimant\'s benefit destination' },
  { type: 'benefit_address_change', label: 'Benefit mailing-address change', sample: 'Address tied to physical-check delivery' },
  { type: 'caseworker_override', label: 'Caseworker override', sample: 'Operator overrides automatic disqualification' },
];

const STAGES = [
  { n: '1', title: 'Precheck', body: 'Caseworker submits the change. GovGuard receives a canonical action object with before/after state.' },
  { n: '2', title: 'Policy decision', body: 'Money-destination changes, impossible travel, compromised devices — evaluated in one deterministic pass.' },
  { n: '3', title: 'Accountable signoff', body: 'When required, a named supervisor approves the exact action hash. Self-approval is forbidden.' },
  { n: '4', title: 'Trust receipt', body: 'Receipt binds actor, authority, action hash, policy hash, nonce, expiry, signoff state.' },
  { n: '5', title: 'One-time consume', body: 'Benefits core system consumes the receipt. Replay attempts log and fail. Expired receipts log and fail.' },
  { n: '6', title: 'Evidence packet', body: 'Full event timeline, IG/GAO-ready, exportable to JSON. Tamper-evident via append-only audit log.' },
];

const MODES = [
  { mode: 'observe', body: 'Evaluate every protected action. Log decisions. Never block. Generate the report that shows what would have been blocked.' },
  { mode: 'warn', body: 'Return decision to the caller. Caller chooses whether to honor. Used for staged rollouts.' },
  { mode: 'enforce', body: 'Fail closed. Block actions that violate policy or lack required signoff.' },
];

export default function GovGuardPage() {
  return (
    <>
      <SiteNav activePage="GovGuard" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA GOVGUARD · GOV-00X</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Pre-execution trust for government programs.</h1>
            <p style={{ ...styles.lead, maxWidth: 720, marginTop: 16 }}>
              GovGuard sits between the caseworker action and the benefits core system. Every benefit
              redirect, address change tied to payment, and caseworker override is bound to an
              authenticated actor, an exact policy hash, and an evidence trail before it executes.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="#how-it-works" style={cta.primary}>How it works</a>
              <a href="#api" style={cta.secondary}>API reference</a>
              <a href="mailto:team@emiliaprotocol.ai?subject=GovGuard%20pilot" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>

        {/* Why authentication is not enough */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHY AUTHENTICATION IS NOT ENOUGH</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 720 }}>
              Most fraud happens inside approved-looking workflows.
            </h2>
            <p style={{ ...styles.body, maxWidth: 640, marginTop: 16 }}>
              The caseworker is logged in. The session is valid. The form submits. Nothing in the
              authentication layer flags that the new bank account doesn&apos;t belong to the
              claimant. GovGuard is the layer that asks the question authentication doesn&apos;t:
              <em style={{ color: color.t1, fontStyle: 'normal' }}> &ldquo;before this executes, is the change itself permitted under policy, and who owns the outcome?&rdquo;</em>
            </p>
          </div>
        </section>

        {/* Protected actions */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>PROTECTED ACTIONS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Initial GovGuard policy pack.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {PROTECTED_ACTIONS.map((a) => (
                <div key={a.type} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase' }}>{a.type}</div>
                  <div style={{ ...styles.h3, fontSize: 18, marginTop: 8 }}>{a.label}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 12, color: color.t2 }}>{a.sample}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* How it works */}
        <section id="how-it-works" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>HOW IT WORKS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Six stages. Six audit points.</h2>
            <div style={{ marginTop: 32 }}>
              {STAGES.map((s) => (
                <div key={s.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.brd}` }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{s.n}</div>
                  <div>
                    <div style={{ ...styles.h3, fontSize: 18 }}>{s.title}</div>
                    <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 640 }}>{s.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Modes */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>ENFORCEMENT MODES</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Roll out without breaking anything.</h2>
            <p style={{ ...styles.body, maxWidth: 640, marginTop: 16 }}>
              Government programs cannot move from zero to blocking overnight. GovGuard supports
              three modes per organization, configurable per protected action type.
            </p>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
              {MODES.map((m) => (
                <div key={m.mode} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, letterSpacing: 2, textTransform: 'uppercase', fontWeight: 600 }}>{m.mode}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 12, color: color.t2 }}>{m.body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* API */}
        <section id="api" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>API</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>One v1 surface. Six endpoints.</h2>
            <div style={{ marginTop: 24, padding: 24, background: color.bgCard, border: `1px solid ${color.brd}`, borderRadius: radius.md, fontFamily: font.mono, fontSize: 13, lineHeight: 1.9 }}>
              <div><span style={{ color: color.gold }}>POST</span>   /api/v1/trust-receipts</div>
              <div><span style={{ color: color.gold }}>GET</span>    /api/v1/trust-receipts/&#123;receiptId&#125;</div>
              <div><span style={{ color: color.gold }}>POST</span>   /api/v1/trust-receipts/&#123;receiptId&#125;/consume</div>
              <div><span style={{ color: color.gold }}>GET</span>    /api/v1/trust-receipts/&#123;receiptId&#125;/evidence</div>
              <div><span style={{ color: color.gold }}>POST</span>   /api/v1/signoffs/request</div>
              <div><span style={{ color: color.gold }}>POST</span>   /api/v1/signoffs/&#123;signoffId&#125;/approve</div>
              <div><span style={{ color: color.gold }}>POST</span>   /api/v1/signoffs/&#123;signoffId&#125;/reject</div>
            </div>
            <p style={{ ...styles.body, fontSize: 14, marginTop: 16, color: color.t2 }}>
              Every endpoint is rate-limited and authenticated. Actor identity is derived from the
              authenticated session, never from the request body. Full OpenAPI spec ships in the
              v1.1 release.
            </p>
          </div>
        </section>

        {/* Pilot CTA */}
        <section style={{ ...styles.section, paddingBottom: 96 }}>
          <div style={styles.container}>
            <div style={{ ...styles.card, padding: 40, textAlign: 'center' }}>
              <h2 style={{ ...styles.h2, fontSize: 28 }}>Pilot in 30 days.</h2>
              <p style={{ ...styles.body, maxWidth: 540, margin: '16px auto 24px' }}>
                We&apos;ll wire one workflow (your choice: bank-account change, address change,
                or operator override) into observe mode. You get the audit trail of what would
                have been blocked. Then you decide if you want to flip to enforce.
              </p>
              <a href="mailto:team@emiliaprotocol.ai?subject=GovGuard%20pilot" style={cta.primary}>
                Request pilot
              </a>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
