/**
 * /pre-execution-accountability — the category page.
 * @license Apache-2.0
 *
 * Names the category EMILIA defines and explains why the existing control
 * stack (audit logs, IAM, GRC dashboards, human-in-the-loop) is insufficient
 * for irreversible AI-agent actions. Buyer-facing; protocol depth lives on
 * /protocol.
 */

import type { Metadata } from 'next';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import Link from 'next/link';
import { color, font, styles } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Pre-Execution Accountability Infrastructure — EMILIA Protocol',
  description:
    'Audit logs, IAM, and GRC dashboards tell you what happened. EMILIA decides what is allowed to happen — binding identity, authority, policy, exact action, and a named human signoff before an irreversible AI action executes.',
  alternates: { canonical: '/pre-execution-accountability' },
};

const FAILURES = [
  ['Audit logs', 'Forensic archaeology. They record the action after it executed — the money already left. A log written by the same system whose integrity is in question is testimony, not independent evidence.'],
  ['IAM / OAuth', 'Proves who the actor is and that they hold a scope. It does not prove a named human authorized this exact action, now. Once a token is exfiltrated or a session hijacked, every downstream action is silently authorized.'],
  ['GRC dashboards', 'Govern from above — inventory, policy, mapping, reporting. Useful, but they do not sit in the execution path. They know what happened; they do not stop the thing before it happens.'],
  ['Human-in-the-loop', 'Unfalsifiable as usually built. "A human reviewed it" with no artifact bound to the exact action, verifiable by a third party, is theater. The approval has to produce evidence.'],
];

const MODEL = [
  ['Observe', 'See every irreversible action that would require stronger approval — report-only, zero blocking. The safe on-ramp.'],
  ['Verify', 'Bind identity, authority, policy, and the exact action context before execution. Allow, allow-with-signoff, or deny.'],
  ['Own', 'When policy requires it, a named human signs off on the exact action on their own device. Profiles can require initiator exclusion and distinct-human quorum.'],
  ['Seal', 'Emit a portable, tamper-evident receipt anyone can verify offline — no trust in the operator, no backend call.'],
];

const SURFACES = [
  ['Payments & treasury', 'Vendor bank-account changes, wire releases, payee onboarding — the BEC and authorized-push-payment vectors.'],
  ['Government benefits', 'Payment-destination redirects, eligibility overrides, operator actions — appeal-ready by construction.'],
  ['AI agents', 'Irreversible tool calls at the MCP boundary — prompt injection can change what an agent proposes, not what a named human signed.'],
];

export default function PreExecutionAccountabilityPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav />
      <main style={{ maxWidth: 860, margin: '0 auto', padding: '56px 24px 96px' }}>
        <div style={styles.eyebrow}>The category</div>
        <h1 style={{ ...styles.h1, maxWidth: 760 }}>Pre-Execution Accountability Infrastructure</h1>
        <p style={{ ...styles.body, maxWidth: 720 }}>
          Audit logs, IAM, and GRC dashboards tell you what happened. EMILIA decides what is
          allowed to happen — binding identity, authority, policy, the exact action, and a named
          human&rsquo;s signoff <em style={{ fontStyle: 'normal', color: color.t1, fontWeight: 600 }}>before</em>{' '}
          an irreversible action executes. Post-hoc governance is forensic archaeology; this sits in
          the execution path.
        </p>

        <h2 style={styles.h2}>Why the existing control stack falls short</h2>
        <div style={{ display: 'grid', gap: 14, marginBottom: 40 }}>
          {FAILURES.map(([k, v]) => (
            <div key={k} style={{ ...styles.card }}>
              <div style={styles.cardTitle}>{k}</div>
              <div style={styles.cardBody}>{v}</div>
            </div>
          ))}
        </div>

        <h2 style={styles.h2}>The model: Observe &rarr; Verify &rarr; Own &rarr; Seal</h2>
        <ol style={{ ...styles.list, marginBottom: 40 }}>
          {MODEL.map(([k, v]) => (
            <li key={k} style={{ marginBottom: 10 }}>
              <strong style={{ color: color.t1 }}>{k}.</strong> {v}
            </li>
          ))}
        </ol>

        <h2 style={styles.h2}>Where it applies</h2>
        <div style={{ display: 'grid', gap: 14, marginBottom: 40 }}>
          {SURFACES.map(([k, v]) => (
            <div key={k} style={{ ...styles.card }}>
              <div style={styles.cardTitle}>{k}</div>
              <div style={styles.cardBody}>{v}</div>
            </div>
          ))}
        </div>

        <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, maxWidth: 720, marginBottom: 36 }}>
          The receipt proves a named human authorized this exact action under a stated policy before
          it executed, verifiable offline. It does not assert the decision was correct; one-time-use
          and revocation are relying-party server state.
        </p>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <Link href="/try" className="ep-cta" style={{ ...styles.body, fontWeight: 600, color: color.gold, fontFamily: font.sans }}>
            Approve one yourself with Face ID &rarr;
          </Link>
          <Link href="/pilot" className="ep-cta-secondary" style={{ ...styles.body, fontWeight: 600, color: color.t2, fontFamily: font.sans }}>
            Run a 14-day observe-mode pilot
          </Link>
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
