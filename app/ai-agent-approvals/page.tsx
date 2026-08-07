/**
 * AI agent approval workflow pillar page.
 *
 * Consolidates the approval argument that was scattered across /quickstart and
 * the human-in-the-loop comparison pages into one buyer-facing surface.
 *
 * @license Apache-2.0
 */
'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';
import { FAQ } from './_content';

const TLA_INVARIANTS = String(proofStats.tla.invariants);
const TLA_CHECKER = String(proofStats.tla.checker);

// The three outcomes of one evaluation. Most approval systems ship the first
// and the third; the product is in the middle one and in what it produces.
const ROUTES = [
  {
    key: 'ALLOW',
    tone: color.green,
    title: 'Inside policy',
    body: 'The action runs. Nobody is interrupted, and the decision is still recorded, because "no human was needed" is itself something a reviewer will want to see justified.',
  },
  {
    key: 'ESCALATE',
    tone: color.gold,
    title: 'Outside policy, not forbidden',
    body: 'Execution stops and a named human is asked for this exact action. The refusal is machine-readable (HTTP 428, carrying what to bring back), so the agent knows what would unblock it instead of retrying blind.',
  },
  {
    key: 'DENY',
    tone: color.red,
    title: 'No approver would make it acceptable',
    body: 'Refused outright, with a reason. There is no signoff path, because the problem is not missing authority; it is that the action is out of bounds.',
  },
];

const ROWS = [
  { dim: 'What was approved', msg: 'An action, described in prose', bound: 'The exact parameters, covered by the signature' },
  { dim: 'Who approved', msg: 'Whoever held the session', bound: 'A named principal, inside the signed payload' },
  { dim: 'How the yes was established', msg: 'A click', bound: 'An assurance tier that had to be proven, not claimed' },
  { dim: 'Reuse', msg: 'Nothing prevents it', bound: 'One-time consumption; a second presentation is refused' },
  { dim: 'Drift between approval and execution', msg: 'Undetected', bound: 'Compared against the observed action; refused on mismatch' },
  { dim: 'How a third party checks it', msg: 'Ask the operator', bound: 'Verify the signature against a pinned issuer key' },
  { dim: 'What the agent can influence', msg: 'The framing it presents', bound: 'Nothing that sits inside the signature' },
];

export default function AiAgentApprovalsPage(): React.ReactElement {
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
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Approvals / AI Agents</div>
        <h1 className="ep-hero-text" style={styles.h1}>Designing an AI agent approval workflow</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 640 }}>
          Most of what an agent does should never reach a person. The workflow&rsquo;s job is to let routine work run inside policy, stop the rest at a named human, and make sure the agent can never move the line between the two.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Three routes out of one decision point</h2>
        <p className="ep-reveal" style={styles.body}>
          Every consequential action an agent attempts passes through a single evaluation, and that evaluation has exactly three outcomes.
        </p>
        <div className="ep-reveal" style={grid.auto(220)}>
          {ROUTES.map(r => (
            <div key={r.key} className="ep-card-hover" style={{ ...styles.card, borderTop: `3px solid ${r.tone}` }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.7, textTransform: 'uppercase', color: r.tone, marginBottom: 12 }}>{r.key}</div>
              <div style={styles.cardTitle}>{r.title}</div>
              <div style={styles.cardBody}>{r.body}</div>
            </div>
          ))}
        </div>
        <p className="ep-reveal" style={{ ...styles.body, marginTop: 24, marginBottom: 0 }}>
          Almost every approval system has the first and the third. The value is in the middle one, and specifically in what the escalation leaves behind once the human has answered.
        </p>
      </section>

      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal ep-tag" style={{ color: color.gold }}>The load-bearing rule</div>
          <h2 className="ep-reveal" style={styles.h2}>The agent must never widen its own authority</h2>
          <p className="ep-reveal" style={styles.body}>
            A workflow that can be argued into granting itself more room is not a control, it is a suggestion. Three rules carry most of the weight here, and each of them is a refusal rather than a warning.
          </p>
          <ul className="ep-reveal" style={styles.list}>
            <li><strong>Authority only narrows on the way down.</strong> A principal that itself holds delegated authority cannot re-delegate more than it holds. A request for a scope outside what the grantor actually has is refused as a scope escalation, and the offending scope is named in the refusal.</li>
            <li><strong>Unverifiable authority is not authority.</strong> If the delegation record cannot be read, the request does not degrade to permissive. It refuses, because a store that is unreachable and a store that says no should not produce different outcomes.</li>
            <li><strong>The tier cannot be self-declared.</strong> Assurance runs software, then class_a (a device signoff), then quorum (m-of-n, the two-person rule). The action&rsquo;s risk sets the floor, and a receipt that merely claims a higher tier is graded down to software and refused.</li>
          </ul>
          <p className="ep-reveal" style={{ ...styles.body, marginTop: 24, marginBottom: 0 }}>
            The models behind those transitions are analyzed as models, not only tested as code: {TLA_INVARIANTS} TLA+ invariants checked by {TLA_CHECKER} in CI.
          </p>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 72, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>An approval that is a message, and an approval that is bound</h2>
        <p className="ep-reveal" style={styles.body}>
          When a request goes to Slack and someone clicks Approve, the artifact produced is a message: a person, at a time, approved something. It reads like authorization. Structurally it is a notification with a timestamp, and two properties separate it from an approval that can carry weight.
        </p>
        <p className="ep-reveal" style={styles.body}>
          <strong>Bound to the exact action.</strong> The signature covers the parameters, not just the action type: the amount, the beneficiary, the repository, the record. At execution the gate compares what was authorized against what the system of record actually observes and refuses on drift. When a field is declared as required and no observed value is supplied, the check fails closed instead of passing quietly, which is the difference between a control and a formality.
        </p>
        <p className="ep-reveal" style={styles.body}>
          <strong>Used once.</strong> Consumption is keyed to a stable, issuer-generated receipt identifier, and a second presentation of the same approval is refused as a replay. The key is deliberately not a hash of the content: canonicalization can differ between language implementations, which would silently break replay detection exactly when services written in different languages share a consumption store.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Dimension</th>
                <th style={styles.tableHead}>Approval as a message</th>
                <th style={styles.tableHead}>Approval bound to the action</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  <td style={styles.tableCell}>{r.msg}</td>
                  <td style={styles.tableCell}>{r.bound}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>
        <h2 className="ep-reveal" style={styles.h2}>Choosing what escalates</h2>
        <p className="ep-reveal" style={styles.body}>
          The failure mode of approval workflows is not being too strict. It is asking so often that approving becomes reflexive, at which point the human is a rubber stamp with a pager and the evidence trail records a ritual. Two heuristics keep the volume honest.
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong>Escalate on irreversibility, not on size.</strong> A small payment that cannot be clawed back deserves more scrutiny than a large one that can be reversed with a phone call.</li>
          <li><strong>Escalate on the parameters that would hurt if they were wrong.</strong> Beneficiary, destination, deletion scope, blast radius. Not the name of the tool being called.</li>
        </ul>
        <p className="ep-reveal" style={{ ...styles.body, marginTop: 24, marginBottom: 0 }}>
          When an action is both rare and severe, raise the tier rather than the frequency. Requiring quorum on the few actions that warrant it costs the team less attention than requiring a click on everything, and it produces a stronger record for the actions that matter.
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
        <h2 style={styles.h2}>Wire it into your agent</h2>
        <p style={styles.body}>
          The quickstart takes an irreversible action in MCP, LangChain, CrewAI, AutoGen, or any Node service and puts this decision point in front of it.
        </p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 24 }}>
          <a href="/quickstart" className="ep-cta" style={cta.primary}>Open the quickstart</a>
          <a href="/gate" className="ep-cta-secondary" style={cta.secondary}>How enforcement works</a>
        </div>
        <p style={{ ...styles.body, marginBottom: 0 }}>
          For the record an approval leaves behind and what a reviewer does with it, see <a href="/ai-agent-audit-trail" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>AI agent audit trails</a>. For how this compares with a hand-rolled Slack approval, see <a href="/compare/human-in-the-loop" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>EMILIA vs DIY human-in-the-loop</a>.
        </p>
      </section>

      <SiteFooter />
    </div>
  );
}
