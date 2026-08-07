/**
 * AI agent audit trail pillar page.
 *
 * The affirmative counterpart to /compare/audit-logs: that page argues against
 * logs as a control, this one specifies the record that replaces them.
 *
 * @license Apache-2.0
 */
'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';
import { FAQ } from './_content';

const CONFORMANCE_SUITES = String(proofStats.conformance.suites);
const CONFORMANCE_VECTORS = String(proofStats.conformance.vectors);
const TEST_CASES = Number(proofStats.tests.total).toLocaleString('en-US');

// Each row is a field the record carries and the review question that field
// closes. Ordered the way a reviewer works: what ran, who said yes, how the
// yes was established, under what rule, was it reused, did it take effect.
const FIELDS = [
  {
    field: 'The exact action, parameter by parameter',
    closes: 'Was the thing that ran the thing that was approved? A record of the action type alone cannot answer that; the amount, the beneficiary, and the target are where substitution happens.',
  },
  {
    field: 'The named approver, signing over that action',
    closes: 'Who said yes? A session identifier names a login. It does not name a person who accepted a consequence.',
  },
  {
    field: 'The assurance tier actually proven',
    closes: 'How was the yes established? EMILIA ranks software below class_a (device signoff) below quorum (m-of-n). A receipt that merely claims the higher tier is graded down to software and refused.',
  },
  {
    field: 'The policy pinned at request time',
    closes: 'Under which rule? Pinning is what stops a later policy edit from retroactively legitimizing an action taken before it.',
  },
  {
    field: 'A one-time consumption key',
    closes: 'Was this approval used more than once? Reuse has to surface as an explicit refusal, not as a second successful action that looks identical to the first.',
  },
  {
    field: 'The outcome, including "not established"',
    closes: 'Did it actually take effect? A record that can only say success or failure will assert one of them when neither was observed.',
  },
];

export default function AiAgentAuditTrailPage(): React.ReactElement {
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

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Audit Trail / AI Agents</div>
        <h1 className="ep-hero-text" style={styles.h1}>What an AI agent audit trail has to contain</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          A log tells a reviewer what your system says happened. An audit trail for autonomous actions has to answer a harder question: who authorized <em>this exact action</em>, under which policy, and can that be checked without asking you.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>The question a reviewer is actually asking</h2>
        <p className="ep-reveal" style={styles.body}>
          Every review of an agent action converges on the same four questions. What exactly executed. Who authorized it. Under what rule, as the rule stood at the time. And what the record says when none of that can be established. A trail built for debugging answers the first question well and the other three badly.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The gap is not thoroughness. You can capture every field of every request and still not hold evidence, because the capture is a statement by the system whose behavior is in question.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>What the record must carry</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Field</th>
                <th style={styles.tableHead}>The review question it closes</th>
              </tr>
            </thead>
            <tbody>
              {FIELDS.map(f => (
                <tr key={f.field}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600, minWidth: 220 }}>{f.field}</td>
                  <td style={styles.tableCell}>{f.closes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Application logs are self-attested</h2>
        <p className="ep-reveal" style={styles.body}>
          Your application log is written by the system under review, into storage that system controls, and read back through an interface that system provides. Every step of the verification path runs through the party being questioned. Checking the record needs your database, your access grant, and your continued cooperation. When the system itself is what is in doubt, its record inherits the doubt.
        </p>
        <p className="ep-reveal" style={styles.body}>
          That is not an argument against logging. Logs are the right instrument for operating a system and the wrong one for settling a dispute about an irreversible action, and the two jobs are usually assigned to the same file.
        </p>
        <p className="ep-reveal" style={{ ...styles.body, marginBottom: 0 }}>
          <a href="/compare/audit-logs" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>The full argument, side by side: audit logs vs authorization receipts</a>
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>What a signed per-action record adds</h2>
        <p className="ep-reveal" style={styles.body}>
          An EMILIA authorization receipt is an Ed25519 signature over the canonical JSON of a claim, optionally anchored in a sorted-pair Merkle tree. Verifying one needs the receipt, the canonicalization rule, and the issuer public key the checker pinned. It does not need our servers, your database, or anyone&rsquo;s permission.
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong>It can be handed over.</strong> An auditor, an insurer, or a counterparty checks it themselves, with the Apache-2.0 reference verifiers for JavaScript and Python.</li>
          <li><strong>It cannot be quietly amended.</strong> Any edit to a signed field breaks the signature, so a record that still verifies is the record that was issued.</li>
          <li><strong>It outlives the issuer.</strong> The evidence does not depend on the issuing system still running, still being reachable, or still being on your side.</li>
        </ul>
        <p className="ep-reveal" style={{ ...styles.body, marginTop: 24 }}>
          The receipt format is public and implementable in any language: see <a href="/spec/trust-receipt" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>EP-RECEIPT-v1</a>.
        </p>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal ep-tag" style={{ color: color.gold }}>The hard case</div>
          <h2 className="ep-reveal" style={styles.h2}>When the provider goes silent, the honest answer is INDETERMINATE</h2>
          <p className="ep-reveal" style={styles.body}>
            The hardest case in the design is not the attacker. It is the executor that stops answering. An action is authorized, the gate reserves it, the executor is invoked, and then the call throws: a timeout, a dropped connection, a 500 after the write. From where the caller stands, &ldquo;it fully executed&rdquo; and &ldquo;it never happened&rdquo; are indistinguishable.
          </p>
          <p className="ep-reveal" style={styles.body}>
            A retry-shaped system resolves that by guessing. Treat it as failure and retry, and the effect may land twice. Treat it as success and the record now asserts an effect nobody observed. Either way the trail states something no one checked, and it states it with the same confidence as everything else in the file.
          </p>
          <p className="ep-reveal" style={styles.body}>
            EMILIA records the third answer. Once the executor has been entered, a thrown error is an <em>indeterminate effect</em>, not proof that nothing happened. The authorization is burned rather than reopened, a blind retry on the same operation is refused before the provider can be re-entered, and the reserved budget is not silently restored. The entry stays indeterminate until authenticated provider evidence resolves it: signed by a pinned provider key, bound to the same operation identifier and the same canonical action digest. Evidence for a different destination, or with a broken signature, does not reconcile and never enters the ledger.
          </p>
          <pre className="ep-reveal" style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.8, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '20px 22px', margin: '0 0 24px', overflowX: 'auto', whiteSpace: 'pre' }}>{`$ node examples/indeterminate-effect-reconciliation/demo.mjs

1  PROVIDER COMMITTED     effects=1
2  RESPONSE LOST          effect_indeterminate
3  CAPABILITY FINALIZED   indeterminate
4  BLIND RETRY            operation_already_committed
5  AUTHENTICATED GET      executed
6  PROVIDER EXECUTIONS    1`}</pre>
          <p className="ep-reveal" style={{ ...styles.body, marginBottom: 0 }}>
            That is what surviving review means in practice. The record is allowed to say it does not know, and it is not allowed to guess.
          </p>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 72, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Where the mechanism is checked</h2>
        <p className="ep-reveal" style={styles.body}>
          The properties above are behaviors of code, so they are tested as behaviors: {CONFORMANCE_SUITES} conformance suites covering {CONFORMANCE_VECTORS} vectors, and {TEST_CASES} automated test cases, with the refusal paths tested as explicitly as the happy path. The full evidence index, including what each artifact does <em>not</em> establish, is on the engineering evidence page.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Questions</h2>
        <div className="ep-reveal" style={{ borderTop: `1px solid ${color.border}` }}>
          {FAQ.map(f => (
            <div key={f.q} style={{ padding: '22px 0', borderBottom: `1px solid ${color.border}` }}>
              <h3 style={{ ...styles.h3, marginBottom: 8 }}>{f.q}</h3>
              <p style={{ fontSize: 14.5, color: color.t2, lineHeight: 1.7, margin: 0 }}>{f.a}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Next</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 24 }}>
          <a href="/proof" className="ep-cta" style={cta.primary}>Read the engineering evidence</a>
          <a href="/compare/audit-logs" className="ep-cta-secondary" style={cta.secondary}>Audit logs vs receipts</a>
        </div>
        <p style={{ ...styles.body, marginBottom: 0 }}>
          The record described here is what an approval leaves behind. For the workflow that produces it, see <a href="/ai-agent-approvals" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>AI agent approval workflows</a>.
        </p>
      </section>

      <SiteFooter />
    </div>
  );
}
