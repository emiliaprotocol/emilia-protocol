// SPDX-License-Identifier: Apache-2.0
// EP GovGuard - observe-mode authorization receipts for government payment integrity.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const PROTECTED_ACTIONS = [
  {
    type: 'gov.vendor_payment_destination_change',
    label: 'Vendor payment-destination change',
    sample: 'A supplier payment destination changes before the next disbursement run.',
  },
  {
    type: 'gov.disbursement_release',
    label: 'Disbursement release',
    sample: 'A high-value payment is ready to leave treasury or accounts payable.',
  },
  {
    type: 'gov.grant_disbursement',
    label: 'Grant disbursement',
    sample: 'A program payment is released against a grant or award.',
  },
  {
    type: 'benefit_bank_account_change',
    label: 'Benefit bank-account change',
    sample: 'A direct-deposit destination changes on a benefits case.',
  },
  {
    type: 'benefit_address_change',
    label: 'Benefit address/contact change',
    sample: 'A mailing address or contact route changes in a way that can redirect notices or credentials.',
  },
  {
    type: 'caseworker_override',
    label: 'Caseworker override',
    sample: 'An operator bypasses a system recommendation or eligibility control.',
  },
  {
    type: 'gov.provider_enrollment_change',
    label: 'Provider enrollment change',
    sample: 'A provider status or payment address changes before future public funds flow.',
  },
  {
    type: 'gov.eligibility_override',
    label: 'Eligibility override',
    sample: 'A regulated benefit decision is manually changed from the system result.',
  },
];

const STAGES = [
  {
    n: '1',
    title: 'Observe',
    body: 'GovGuard receives a copy of the proposed action. It logs the action, evaluates policy, and does not block the existing system.',
  },
  {
    n: '2',
    title: 'Classify',
    body: 'The action is checked for payment destination changes, new vendors, after-hours updates, missing authority, and policy-specific risk flags.',
  },
  {
    n: '3',
    title: 'Bind',
    body: 'The actor, policy, action parameters, nonce, and time window are bound into the authorization context for the exact action.',
  },
  {
    n: '4',
    title: 'Signoff',
    body: 'If policy would require approval, GovGuard records the named approver path and forbids self-approval in the evidence model.',
  },
  {
    n: '5',
    title: 'Receipt',
    body: 'The completed authorization receipt proves who authorized what, under which policy, for which exact parameters.',
  },
  {
    n: '6',
    title: 'Evidence packet',
    body: 'The fire-drill report shows which actions would have required signoff and gives auditors verification material they can check offline.',
  },
];

const PILOT_TERMS = [
  ['One workflow', 'Pick a single disbursement or change flow to watch first.'],
  ['Observe mode', 'Nothing is blocked. You see what would have needed signoff.'],
  ['60 days', 'Long enough to catch the actions that matter, short enough to scope.'],
  ['$25K', 'Scoped enough for a departmental pilot.'],
  ['Audit packet', 'Receipts, decisions, and evidence your auditors can verify offline.'],
];

// The wound: vendor bank-account-change fraud. Two columns — what happens
// without GovGuard vs. with it — matching the page's card component style.
const WOUND_STEPS = [
  'A "we changed banks, please update our payment details" email arrives, formatted like every other vendor notice.',
  'The vendor banking record is updated. The clerk is logged in, the role can edit the field, the form submits.',
  'The next disbursement run queues a payment to the new account.',
];

const WOUND_COMPARE = [
  {
    label: 'Without GovGuard',
    accent: 'red',
    body: 'The payment releases to the fraudulent account. The money is gone and irreversible. The audit log shows a valid session, but no one can prove who approved the bank-account change before it moved.',
  },
  {
    label: 'With GovGuard',
    accent: 'gold',
    body: 'The bank-account change is flagged at the action boundary and held pending a named human\'s device signoff. Once that person approves, an authorization receipt is issued and the payment releases with provable approval. If no one approves, no money moves.',
  },
];

const MODES = [
  {
    mode: 'observe',
    body: 'Evaluate protected actions, produce authorization receipts, and report what would have required signoff. No production blocking.',
  },
  {
    mode: 'warn',
    body: 'Return a decision to the caller while the agency decides when to honor warnings by workflow.',
  },
  {
    mode: 'enforce',
    body: 'Fail closed only after policy owners are comfortable with the evidence and escalation path.',
  },
];

export default function GovGuardPage() {
  return (
    <>
      <SiteNav activePage="GovGuard" />
      <main style={styles.page}>
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.eyebrow}>EMILIA GOVGUARD</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 880 }}>
            Pre-payment control for government fraud.
          </h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18, fontSize: 18 }}>
            GovGuard catches the fraud path authentication misses: vendor payment
            destinations, disbursements, benefit routing, provider enrollment, and
            eligibility overrides changing inside valid sessions. High-risk actions
            get named human approval and a verifiable authorization receipt before
            money or regulated state moves.
          </p>
          <p style={{ ...styles.body, maxWidth: 740, marginTop: 8 }}>
            For treasurers, controllers, program-integrity teams, and Inspectors
            General: your logs prove it to you. The receipt proves it to everyone else -
            auditors, insurers, regulators, and courts - without trusting your logs,
            your vendor, or EMILIA.
          </p>
          <p style={{ ...styles.body, maxWidth: 740, marginTop: 8, fontSize: 15, color: color.t2 }}>
            The <a href="https://www.gao.gov/products/gao-24-105833" style={{ color: color.t1, textDecoration: 'underline' }}>Government Accountability Office estimated in 2024</a> that federal
            fraud losses are hundreds of billions of dollars annually. GovGuard does
            not claim to detect every fraud pattern; it closes the action-level proof
            gap before high-risk changes execute.
          </p>
          <p style={{ ...styles.body, maxWidth: 740, marginTop: 8, fontSize: 15, color: color.t2 }}>
            GovGuard binds each action to one accountable approver. Where statute or policy
            requires dual approval — the two-person rule — escalate to a multi-party quorum
            with <a href="/quorum" style={{ color: color.t1, textDecoration: 'underline' }}>EMILIA Quorum</a>.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href="/pilot/sandbox?v=gov" style={cta.primary}>Run the GovGuard fire drill</a>
            <a href="/pilot?v=gov" style={cta.secondary}>Scope a 60-day pilot</a>
          </div>
          <p style={{ fontSize: 13, color: color.t3, marginTop: 16, maxWidth: 740, lineHeight: 1.6 }}>
            Start in observe mode. Nothing gets blocked at first. You see what would
            have needed signoff and get a procurement-grade evidence packet.
          </p>
          <div style={{ marginTop: 18, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontFamily: font.mono, fontWeight: 700, fontSize: 12.5, letterSpacing: 1, textTransform: 'uppercase', color: '#fff', background: color.green, padding: '6px 12px', borderRadius: 6 }}>GG-1 Enforced</span>
            <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/GOVGUARD-CONFORMANCE.md" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>Conformance spec</a>
            <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/tests/govguard-gg1-conformance.test.js" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>CI test</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>PILOT SHAPE</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Start with a fire drill on one workflow.</h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 16 }}>
            {PILOT_TERMS.map(([label, body]) => (
              <div key={label} style={{ ...styles.card, padding: 22 }}>
                <div style={{ ...styles.h3, fontSize: 22, marginBottom: 8 }}>{label}</div>
                <div style={{ ...styles.cardBody }}>{body}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE WOUND</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>
            A fake bank-change email is how the money leaves.
          </h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            Government payment fraud often doesn&rsquo;t break in. It walks through an
            approved-looking workflow:
          </p>
          <div style={{ marginTop: 8 }}>
            {WOUND_STEPS.map((step, i) => (
              <div key={i} style={{ display: 'flex', gap: 20, padding: '16px 0', borderTop: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{i + 1}</div>
                <div style={{ ...styles.body, fontSize: 15, margin: 0, maxWidth: 680 }}>{step}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
            {WOUND_COMPARE.map((c) => (
              <div key={c.label} style={{ ...styles.card, padding: 24, borderTop: `3px solid ${color[c.accent]}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color[c.accent], letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>
                  {c.label}
                </div>
                <div style={{ ...styles.cardBody, marginTop: 12, fontSize: 15, lineHeight: 1.7 }}>{c.body}</div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 15, color: color.t1, marginTop: 28, maxWidth: 720, lineHeight: 1.7, fontWeight: 600 }}>
            Your audit evidence survives vendor turnover, acquisition, and SaaS sunset.
          </p>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrow}>WHY AUTHENTICATION IS NOT ENOUGH</div>
          <h2 style={styles.h2}>
            Most payment failures start inside approved-looking workflows.
          </h2>
          <p style={styles.body}>
            The employee is logged in. The role can edit the record. The form submits.
            The audit log records a valid session. None of that proves the exact action
            was authorized before money moved.
          </p>
          <p style={styles.body}>
            GovGuard sits at the action boundary and asks the question authentication
            cannot answer: who approved this irreversible change, under which policy,
            for these exact parameters?
          </p>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>PROTECTED ACTIONS</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Government fraud-control action pack.</h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
            {PROTECTED_ACTIONS.map((action) => (
              <div key={action.type} style={{ ...styles.card, padding: 24 }}>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 1, textTransform: 'uppercase' }}>
                  {action.type}
                </div>
                <div style={{ ...styles.h3, fontSize: 18, marginTop: 8 }}>{action.label}</div>
                <div style={{ ...styles.cardBody, marginTop: 12 }}>{action.sample}</div>
              </div>
            ))}
          </div>
        </section>

        <section id="how-it-works" style={styles.sectionWide}>
          <div style={styles.eyebrow}>HOW IT WORKS</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Six audit points, from action to evidence.</h2>
          <div style={{ marginTop: 28 }}>
            {STAGES.map((stage) => (
              <div key={stage.n} style={{ display: 'flex', gap: 24, padding: '20px 0', borderTop: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{stage.n}</div>
                <div>
                  <div style={{ ...styles.h3, fontSize: 18 }}>{stage.title}</div>
                  <div style={{ ...styles.body, fontSize: 15, marginTop: 6, maxWidth: 680 }}>{stage.body}</div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>ENFORCEMENT MODES</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Observe first. Enforce only after the evidence is trusted.</h2>
          <p style={{ ...styles.body, maxWidth: 680 }}>
            Government programs cannot move from zero to blocking overnight. GovGuard
            begins as a fire drill: an evidence layer that shows what would have needed
            signoff before it becomes a control layer.
          </p>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 16 }}>
            {MODES.map((mode) => (
              <div key={mode.mode} style={{ ...styles.card, padding: 24 }}>
                <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, letterSpacing: 2, textTransform: 'uppercase', fontWeight: 600 }}>
                  {mode.mode}
                </div>
                <div style={{ ...styles.cardBody, marginTop: 12 }}>{mode.body}</div>
              </div>
            ))}
          </div>
        </section>

        <section id="api" style={styles.section}>
          <div style={styles.eyebrow}>AUTHORIZATION RECEIPTS</div>
          <h2 style={styles.h2}>The artifact auditors can verify later.</h2>
          <p style={styles.body}>
            A GovGuard pilot produces <code>EP-RECEIPT-v1</code> authorization receipts. Each
            receipt is tied to the action hash, policy hash, approver path, nonce,
            expiry, and log checkpoint.
          </p>
          <div style={{ marginTop: 24, padding: 24, background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, fontFamily: font.mono, fontSize: 13, lineHeight: 1.9, overflowX: 'auto' }}>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/adapters/gov/vendor-payment-destination-change/precheck</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/adapters/gov/disbursement-release/precheck</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/adapters/gov/grant-disbursement/precheck</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/adapters/gov/provider-enrollment-change/precheck</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/adapters/gov/eligibility-override/precheck</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/trust-receipts</div>
            <div><span style={{ color: color.gold }}>GET</span> /api/v1/trust-receipts/&#123;receiptId&#125;/evidence</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/signoffs/request</div>
            <div><span style={{ color: color.gold }}>POST</span> /api/v1/signoffs/&#123;signoffId&#125;/approve</div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrow}>DEPLOYMENT &amp; ASSURANCE</div>
          <h2 style={styles.h2}>It runs where your security review needs it to run.</h2>
          <p style={{ ...styles.body, maxWidth: 700 }}>
            On-prem and air-gapped deployment is available - a self-contained offline
            installer that runs with no route off the host. SSO (SAML 2.0 / OIDC) and
            SCIM 2.0 provisioning connect the named humans who can sign off to your
            directory. And the evidence is verifiable offline, without EMILIA: a receipt
            checks out with pure crypto, on a machine that has never touched our network.
          </p>
        </section>

        <section style={{ ...styles.section, paddingBottom: 96 }}>
          <div style={{ ...styles.card, padding: 36, textAlign: 'center' }}>
            <h2 style={{ ...styles.h2, fontSize: 28 }}>Run the fire drill. Then scope the pilot.</h2>
            <p style={{ ...styles.body, maxWidth: 560, margin: '16px auto 24px' }}>
              Pick one workflow: vendor payment destination, disbursement release,
              grant disbursement, provider enrollment, benefit routing, or eligibility
              override. GovGuard observes for 60 days, produces the authorization
              evidence, and shows what would have required named signoff. Pilot fee:
              $25K.
            </p>
            <a href="/pilot/sandbox?v=gov" style={cta.primary}>
              Run the GovGuard fire drill
            </a>
            <p style={{ fontSize: 13, color: color.t3, marginTop: 18 }}>
              For your compliance file: <a href="/compliance/emilia-eu-ai-act-government.pdf" style={{ color: color.blue, textDecoration: 'none' }}>EU AI Act mapping for government programs</a>
              {' '}· <a href="/rfp" style={{ color: color.blue, textDecoration: 'none' }}>RFP language</a>
            </p>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
