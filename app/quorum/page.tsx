// SPDX-License-Identifier: Apache-2.0
// EP Quorum — multi-party (two-person rule) signoff for the highest-stakes
// irreversible actions. Landing page for the Quorum product. Sits alongside the
// single-signoff products (FinGuard, GovGuard); this is the multi-party tier.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const AUDIENCES = [
  ['Defense & national security', 'Actions that already mandate two-person control — release authority, taskings, weapons-adjacent decisions. The rule made cryptographic, with evidence an inspector general can verify offline.'],
  ['Treasury & large-value payments', 'Dual control on the wire desk: the largest transfers and account changes require two distinct, named approvers — not a policy memo, a fail-closed predicate.'],
  ['Government benefit integrity', 'Disbursement approvals and caseworker overrides that move public money require a quorum, so a single forged approval cannot redirect a payment.'],
  ['Critical infrastructure & production', 'Irreversible deploys, infrastructure and IAM changes with real blast radius — held until the quorum signs.'],
];

const PREDICATE = [
  ['Threshold or order', 'M-of-N (any two of three controllers) or a strict sequence (program officer → authorizing official → inspector general). The policy names which.'],
  ['Each signer bound to the exact action', 'Every approval covers the same action hash — the same destination, amount, and parameters. No one signs a summary; everyone signs the bytes.'],
  ['Distinct humans — and distinct keys', 'Separation of duties is enforced, not assumed: one person cannot fill two seats, the initiator cannot approve their own request, and no single device key can fill two seats under two names.'],
  ['Bounded window', 'Signatures must land close enough in time to describe one decision, not a stale collection.'],
  ['Provable order, not just timestamps', 'In strong ordered mode each approval is cryptographically chained to the one before it — so the sequence is proven by the signatures themselves, and no one, including the operator, can reorder or backdate an approval undetected.'],
  ['Fail-closed', 'If any element is missing, mismatched, or unverifiable, the quorum is not satisfied — and the action does not proceed.'],
];

export default function QuorumPage() {
  return (
    <>
      <SiteNav activePage="Quorum" />
      <main style={styles.page}>
        {/* Hero */}
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.eyebrow}>EMILIA QUORUM</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 900 }}>
            The two-person rule for AI actions.
          </h1>
          <p style={{ ...styles.body, maxWidth: 800, marginTop: 18, fontSize: 18 }}>
            Some actions are too consequential for one signature. EMILIA Quorum holds a
            high-stakes, irreversible action until a quorum of named humans — M-of-N or in
            strict order, each bound to the exact action — has signed. The result is a
            cryptographic, offline-verifiable proof that the rule held for this exact action.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8 }}>
            It is additive over single signoff: where one accountable human is enough, use{' '}
            <a href="/finguard" style={{ color: color.t1, textDecoration: 'underline' }}>FinGuard</a> or{' '}
            <a href="/govguard" style={{ color: color.t1, textDecoration: 'underline' }}>GovGuard</a>.
            Where the stakes demand more than one, require a quorum.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href="/try/multi-party" style={cta.primary}>Try the live demo</a>
            <a href="/partners" style={cta.secondary}>Scope a pilot</a>
          </div>
        </section>

        {/* Who it's for */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>WHO IT&rsquo;S FOR</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Where one approval is too small a target for the stakes.</h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
            {AUDIENCES.map(([label, body]) => (
              <div key={label} style={{ ...styles.card, padding: 24 }}>
                <div style={{ ...styles.h3, fontSize: 20, marginBottom: 8 }}>{label}</div>
                <div style={styles.cardBody}>{body}</div>
              </div>
            ))}
          </div>
        </section>

        {/* The predicate */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>WHAT &ldquo;SATISFIED&rdquo; MEANS</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>A quorum either holds or it doesn&rsquo;t.</h2>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            A policy document that says &ldquo;two people must approve&rdquo; is only as strong as the
            system that enforces it. EMILIA Quorum makes the rule a fail-closed predicate, checkable
            by anyone:
          </p>
          <div style={{ marginTop: 8 }}>
            {PREDICATE.map(([label, body], i) => (
              <div key={i} style={{ display: 'flex', gap: 20, padding: '16px 0', borderTop: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 14, color: color.gold, fontWeight: 600, minWidth: 24 }}>{i + 1}</div>
                <div style={{ ...styles.body, fontSize: 15, margin: 0, maxWidth: 720 }}>
                  <strong style={{ color: color.t1 }}>{label}.</strong> {body}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Verifiable / proof */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>VERIFIABLE BY ANYONE</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Evidence, not testimony.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            A decision log that says &ldquo;three people approved&rdquo; is testimony, controlled by the
            party who acted. A quorum receipt is evidence: an auditor, regulator, or counterparty can
            verify it offline, with open-source code, without trusting the system that issued it. To
            earn that, the verification is unambiguous enough that separate verifiers should agree.
            EMILIA ships three cross-language reference verifiers (JavaScript, Python, Go) that pass
            the same adversarial quorum vectors identically, on every change.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 16 }}>
            See it without trusting us. One command issues a dual-approval receipt, then verifies
            it offline — with EMILIA disconnected — and rejects a forged copy:
          </p>
          <pre style={{ fontFamily: font.mono, fontSize: 14, background: color.card, border: `1px solid ${color.border}`, borderRadius: 8, padding: '14px 18px', maxWidth: 760, overflowX: 'auto', marginTop: 8 }}>npx -y @emilia-protocol/crash-test</pre>
          <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
            <a href="/try/multi-party" style={cta.secondary}>Run the demo</a>
            <a href="/blog/the-two-person-rule-for-ai-agents" style={cta.secondary}>Read the primer</a>
            <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/" target="_blank" rel="noopener noreferrer" style={cta.secondary}>IETF spec (EP-QUORUM)</a>
            <a href="https://doi.org/10.5281/zenodo.20780638" target="_blank" rel="noopener noreferrer" style={cta.secondary}>Read the paper</a>
          </div>
        </section>

        {/* Honest status */}
        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>HONEST STATUS</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>What&rsquo;s real today.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Multi-party quorum is a verifiable protocol capability today: the three-language reference
            verifiers agree on it, the server-side enforcement that holds an action until the quorum is
            satisfied is built and merged into the authorization path, and a live in-browser demo runs
            an ordered three-party signoff and rejects a duplicate signer in front of you.
          </p>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            A recent hardening release closes the quorum failure modes behind predicates{' '}
            <strong style={{ color: color.t1 }}>3</strong> and <strong style={{ color: color.t1 }}>6</strong>:
            an offline quorum no longer accepts the initiator&rsquo;s own approval, one device key can no
            longer fill two seats (key-uniqueness is unconditional), and a satisfied gate decision is
            consumed once &mdash; it cannot be replayed for a second high-stakes issuance. Each is pinned by
            a negative conformance vector that passes identically across JavaScript, Python, and Go.
          </p>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            It is also <strong>verified end-to-end</strong>: an automated test drives three independent
            devices through an ordered signoff and proves a quorum-gated action cannot be consumed until
            every required human has signed. What is deliberately still ahead: a production deployment of
            that flow and — for defense — an accredited environment. We would rather state that plainly
            than overclaim a control this consequential. We are taking design partners now.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 22, flexWrap: 'wrap' }}>
            <a href="/partners" style={cta.primary}>Become a design partner</a>
          </div>
        </section>

        <SiteFooter />
      </main>
    </>
  );
}
