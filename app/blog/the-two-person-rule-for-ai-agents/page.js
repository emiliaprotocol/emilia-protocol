'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color } from '@/lib/tokens';

export default function BlogTwoPersonRulePage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Blog · Concepts · June 2026</div>
        <h1 className="ep-hero-text" style={styles.h1}>The two-person rule for AI agents</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          Some actions are too consequential for one signature. The fix is old — launch keys turned by two officers, dual control on a wire desk, four-eyes on a deployment. The new problem is making that rule hold when the thing about to act is an autonomous agent, not a person at a keyboard.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>One approval is a single point of failure</h2>
        <p className="ep-reveal" style={styles.body}>
          A single human signoff is a real control — it puts a named person on the hook for an exact action. But for the highest-stakes operations, one signature is also one thing to phish, coerce, or socially engineer. Treasury learned this and answered with dual control. The military answered with the two-person concept. Auditors call it separation of duties. The principle is the same: <em>no single individual can unilaterally execute the irreversible thing.</em>
        </p>
        <p className="ep-reveal" style={styles.body}>
          AI agents make the case sharper, not softer. An agent with tool access can be steered — by a prompt-injected document, a poisoned data source, a malformed model response — toward an action no human intended. If one approval gates that action, the attacker only has to manufacture one approval. If a quorum of distinct, named humans gates it, the bar is categorically higher.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>The two-person rule, made cryptographic</h2>
        <p className="ep-reveal" style={styles.body}>
          A policy document that says "two people must approve" is only as strong as the system that enforces it. The point of a <em>protocol</em> is to make the rule fail-closed and checkable by anyone — not a process you trust an org to follow, but a predicate that either holds or doesn't. A cryptographic quorum binds these properties together:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>Threshold or order.</strong> M-of-N (any two of three controllers) or a strict sequence (program officer → authorizing official → inspector general). The policy names which.</li>
          <li><strong style={{ color: color.t1 }}>Each signer bound to the exact action.</strong> Every approval covers the same action hash — the same destination, amount, and parameters. No one is signing a summary; everyone is signing the bytes.</li>
          <li><strong style={{ color: color.t1 }}>Distinct humans.</strong> Separation of duties is enforced, not assumed: one person cannot fill two seats, and the initiator cannot approve their own request.</li>
          <li><strong style={{ color: color.t1 }}>A bounded window.</strong> The signatures must land close enough in time that they describe one decision, not a stale collection.</li>
          <li><strong style={{ color: color.t1 }}>Fail-closed.</strong> If any element is missing, mismatched, or unverifiable, the quorum is not satisfied — and the action does not proceed.</li>
        </ul>
        <p className="ep-reveal" style={styles.body}>
          Each individual approval is a device-bound WebAuthn signoff — a passkey assertion (Face ID, Touch ID, a security key) over the exact action context. What the human saw is what they signed. The quorum is just the composition of those signoffs under a stated policy.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Why it has to be verifiable by anyone</h2>
        <p className="ep-reveal" style={styles.body}>
          A decision log that says "three people approved" is testimony — controlled by the party who acted. A quorum receipt is evidence: an auditor, a regulator, or a counterparty can verify it offline, with open-source code, without trusting the system that issued it. That is the difference between "we have a policy" and "here is proof the policy held for this exact action."
        </p>
        <p className="ep-reveal" style={styles.body}>
          To earn that claim, the verification has to be unambiguous enough that independent implementations agree. EMILIA ships three reference verifiers — JavaScript, Python, and Go — that share no code, and a cross-language conformance suite feeds the same adversarial vectors through all three. They agree on authorization receipts, on device signoffs, and on multi-party quorum: the accept cases pass and each reject case (under threshold, duplicate human, out of order, action mismatch, expired window, one bad signature, wrong role) is refused identically. That is the standards bar — multiple independent interoperable implementations — and it runs on every change.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 48 }}>
        <h2 className="ep-reveal" style={styles.h2}>Where it earns its weight</h2>
        <p className="ep-reveal" style={styles.body}>
          The two-person rule is overkill for most actions and exactly right for a few — the ones where a single forged approval is unrecoverable:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li>Defense and national-security actions that already mandate two-person control.</li>
          <li>Treasury and large-value payment release — dual control on the wire desk.</li>
          <li>Government benefit disbursement and caseworker overrides, where payment-redirect fraud is the threat.</li>
          <li>Production and infrastructure changes with blast radius — a quorum before the irreversible deploy.</li>
          <li>Any agent-issued action where one approval is too small a target for the stakes involved.</li>
        </ul>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 32 }}>
        <h2 style={styles.h2}>Honest status</h2>
        <p style={styles.body}>
          Multi-party quorum in EMILIA is a verifiable protocol capability today: the three-language reference verifiers agree on it, and a live in-browser demo runs an ordered three-party signoff and rejects a duplicate signer in front of you. The server-side enforcement that holds a high-stakes action until the full quorum is satisfied is built, merged, and verified end-to-end — an automated test drives three independent devices through an ordered signoff and proves the action cannot be consumed until every required human has signed. What is deliberately still ahead: a production deployment of that flow and, for defense, an accredited environment. We would rather state that plainly than overclaim a control this consequential.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See it work</h2>
        <p style={styles.body}>
          Run an ordered multi-party quorum in your browser — three named approvers, each bound to the exact action, with a duplicate signer rejected live and the whole thing verified client-side. Nothing uploaded, no account, no EP server trusted.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/try/multi-party" className="ep-cta" style={cta.primary}>Try the multi-party demo</a>
          <a href="/protocol" className="ep-cta-secondary" style={cta.secondary}>Read the protocol</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
