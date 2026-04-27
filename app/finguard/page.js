// SPDX-License-Identifier: Apache-2.0
// EP FinGuard — pre-execution trust layer for beneficiary/vendor/payment
// instruction changes before SWIFT, ACH, Fedwire, RTP, or internal
// treasury release. Landing page for the FinGuard product.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'EMILIA FinGuard — Pre-Execution Trust for Treasury & Payment Operations',
  description:
    'Pre-execution trust for beneficiary/vendor/payment-instruction changes before SWIFT, ACH, Fedwire, RTP, or internal release. One-time consumable receipts, dual signoff, complete evidence packets.',
};

const PROTECTED_ACTIONS = [
  { type: 'vendor_bank_account_change', label: 'Vendor bank-account change', sample: 'AP user updates routing before $250K release' },
  { type: 'beneficiary_creation', label: 'Beneficiary creation', sample: 'New SWIFT-eligible counterparty added' },
  { type: 'large_payment_release', label: 'Large payment release', sample: 'Treasury releases wire above $50K threshold' },
  { type: 'ai_agent_payment_action', label: 'AI-agent initiated payment action', sample: 'Autonomous agent triggers a transfer' },
];

const STAGES = [
  { n: '1', title: 'Precheck', body: 'Treasury system POSTs the proposed change to FinGuard with before/after state and risk flags.' },
  { n: '2', title: 'Policy decision', body: 'Money-destination changes, large amounts, AI-initiated actions — all routed through deterministic rules.' },
  { n: '3', title: 'Accountable signoff', body: 'Treasury approver must be different from initiator. Approval binds to exact action hash.' },
  { n: '4', title: 'Trust receipt', body: 'One-time receipt with action hash, policy hash, nonce, expiry. SOX-ready.' },
  { n: '5', title: 'One-time consume', body: 'SWIFT/ACH/Fedwire connector consumes the receipt at release. Reuse fails.' },
  { n: '6', title: 'Evidence packet', body: 'Complete event timeline ready for audit, regulator review, and incident reconstruction.' },
];

const SCENARIOS = [
  {
    title: 'Vendor bank-account swap before payment',
    body: 'AP user changes a vendor\'s bank account, then immediately submits a $250K payment release. FinGuard requires treasury signoff on the bank change before any release referencing the vendor will consume.',
  },
  {
    title: 'AI agent triggers a transfer',
    body: 'An autonomous agent attempts to initiate a wire. Policy flags ai_agent_payment_action — human signoff required regardless of amount. The agent\'s receipt is issued in pending_signoff state.',
  },
  {
    title: 'Large payment escalation',
    body: 'Threshold-based escalation: > $50K requires single signoff, > $1M requires out-of-band verification (configurable per workflow).',
  },
];

export default function FinGuardPage() {
  return (
    <>
      <SiteNav activePage="FinGuard" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.section, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.container}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA FINGUARD · FIN-00X</div>
            <h1 style={{ ...styles.h1, marginTop: 16 }}>Pre-execution trust for treasury & payment ops.</h1>
            <p style={{ ...styles.lead, maxWidth: 720, marginTop: 16 }}>
              FinGuard binds beneficiary changes, vendor remittance updates, and payout
              destination changes to a one-time, action-bound trust receipt before SWIFT,
              ACH, Fedwire, RTP, or internal treasury release. The receipt cannot be replayed,
              cannot outlive its expiry, and cannot be consumed without the exact action it
              authorizes.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 32, flexWrap: 'wrap' }}>
              <a href="#how-it-works" style={cta.primary}>How it works</a>
              <a href="#api" style={cta.secondary}>API reference</a>
              <a href="mailto:team@emiliaprotocol.ai?subject=FinGuard%20pilot" style={cta.secondary}>Request pilot</a>
            </div>
          </div>
        </section>

        {/* Why */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>WHY FINGUARD</div>
            <h2 style={{ ...styles.h2, marginTop: 12, maxWidth: 720 }}>
              Most expensive failures happen inside approved-looking workflows.
            </h2>
            <p style={{ ...styles.body, maxWidth: 640, marginTop: 16 }}>
              The session is authenticated. The role has the right permissions. The form passes
              validation. None of that detects that the vendor&apos;s bank account was swapped
              by a phisher 90 seconds before the wire is released. FinGuard binds the wire to
              the exact pre-change state. Anything else fails consume.
            </p>
          </div>
        </section>

        {/* Protected actions */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>PROTECTED ACTIONS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Initial FinGuard policy pack.</h2>
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
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Six stages from precheck to evidence.</h2>
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

        {/* Scenarios */}
        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>SCENARIOS</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>What FinGuard catches.</h2>
            <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
              {SCENARIOS.map((s) => (
                <div key={s.title} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ ...styles.h3, fontSize: 17 }}>{s.title}</div>
                  <div style={{ ...styles.body, fontSize: 14, marginTop: 10, color: color.t2 }}>{s.body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* API */}
        <section id="api" style={styles.section}>
          <div style={styles.container}>
            <div style={styles.eyebrow}>API</div>
            <h2 style={{ ...styles.h2, marginTop: 12 }}>Same v1 surface as GovGuard.</h2>
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
              The same v1 product surface powers GovGuard and FinGuard. Action types and policy
              packs differ; the underlying receipt invariants do not.
            </p>
          </div>
        </section>

        {/* Pilot CTA */}
        <section style={{ ...styles.section, paddingBottom: 96 }}>
          <div style={styles.container}>
            <div style={{ ...styles.card, padding: 40, textAlign: 'center' }}>
              <h2 style={{ ...styles.h2, fontSize: 28 }}>Pilot in 30 days.</h2>
              <p style={{ ...styles.body, maxWidth: 540, margin: '16px auto 24px' }}>
                Pick one workflow — beneficiary change, payout destination change, vendor
                remittance update, or treasury release approval. We wire it to observe mode.
                You get the audit of what would have been blocked. Flip to enforce on your timeline.
              </p>
              <a href="mailto:team@emiliaprotocol.ai?subject=FinGuard%20pilot" style={cta.primary}>
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
