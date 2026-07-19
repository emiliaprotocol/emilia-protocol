// SPDX-License-Identifier: Apache-2.0
// EP-AEC (Authorization Evidence Chain) - the composition layer.
// Marketing + SEO landing for draft-schrock-ep-authorization-evidence-chain.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const DT = 'https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/';

const PROBLEM = [
  {
    label: 'A receipt per hop',
    body: 'A delegation receipt attests an agent was authorized to act for a principal. A '
      + 'policy or permit receipt attests a rule allowed the effect. A human-authorization '
      + 'receipt attests a named person approved it. Each is signed, each lives in its own '
      + 'format — and each only speaks for its own hop.',
  },
  {
    label: 'No one owns the verdict',
    body: 'The mature efforts independently converged on one substrate: bind the action with a '
      + 'canonical digest (JCS, RFC 8785) and sign it. But no specification defines how a '
      + 'relying party checks that the several receipts it was handed all bind the same action '
      + 'and each verify — and turns that into one decision.',
  },
  {
    label: 'Trust leaks in the gaps',
    body: 'Without a composite check, a verifier either trusts an operator to have stapled the '
      + 'right receipts together, or accepts a receipt that was issued for a different action. '
      + 'The join between “what was authorized” and “what actually happened” is exactly where '
      + 'audit breaks down.',
  },
];

const STEPS = [
  ['01 · Canonical action',
    'Compute one canonical digest of the exact action (JCS / RFC 8785 + SHA-256). This is the '
    + 'single thing every receipt must point at.'],
  ['02 · Collect receipts',
    'Gather the heterogeneous receipts for that action — delegation, policy/permit, decision, '
    + 'and EP’s named-human authorization — regardless of which format or hop produced them.'],
  ['03 · Cross-binding check',
    'Verify every receipt binds the same canonical action. A receipt issued for a different '
    + 'action — replayed or swapped in — fails the chain by construction.'],
  ['04 · Per-receipt verify',
    'Each receipt is verified under its own rules by a pluggable verifier. AEC composes them; '
    + 'it does not replace or reinterpret any one format’s signature checks.'],
  ['05 · Requirement policy',
    'Apply the relying party’s requirement — e.g. “delegation AND policy AND a named human” — '
    + 'as an explicit, inspectable rule over receipt types.'],
  ['06 · One verdict',
    'Return a single, offline, fail-closed SATISFIED or UNSATISFIED evidence verdict. '
    + 'No network, no introspection endpoint, no trust in the operator. The relying party '
    + 'separately decides whether that evidence is sufficient to authorize execution.'],
];

const BOUNDS = [
  ['What an evidence chain proves',
    'That, for one canonical action, every receipt presented binds that exact action, each '
    + 'verifies under its own rules, and the relying party’s composition requirement was met — '
    + 'checkable offline, by anyone, years later.'],
  ['What it does not prove',
    'That the underlying decision was correct, or real-world identity beyond each receipt’s own '
    + 'enrollment layer. AEC is a composition and verification object, not a judgment about the '
    + 'merits — and we state that plainly, because auditors and insurers are the buyers and an '
    + 'oversold claim is disqualifying.'],
];

const FAQ = [
  ['Is EP-AEC just another receipt format?',
    'No. It is deliberately not a 13th receipt. The field already converged on a common '
    + 'substrate for individual receipts; what was missing is the layer that composes several '
    + 'heterogeneous receipts for one action into a single offline verdict. AEC is that layer — '
    + 'a composition object plus a verifier with pluggable per-receipt checks.'],
  ['What exactly does the verifier return?',
    'A single fail-closed SATISFIED or UNSATISFIED evidence verdict for one canonical action, '
    + 'computed entirely offline. SATISFIED requires that every presented receipt binds the same '
    + 'action, each verifies, and the relying party’s evidence requirement is met. It is not an '
    + 'ALLOW decision: the executor applies its own authorization policy separately.'],
  ['How does it relate to DRP, permit receipts, or PSEA?',
    'As complements, not competitors. Delegation (e.g. DRP), policy/permit, and decision '
    + 'receipts each answer their own hop; AEC verifies that those receipts — plus EP’s '
    + 'named-human authorization, the one leg the others do not supply — all bind the same action '
    + 'and verify together. It is the verifier-side convergence point for the cluster.'],
  ['Does it need to be online?',
    'No. Verification is fully offline and asymmetric: no introspection endpoint, no account, no '
    + 'trust in the issuer or operator. A chain stays verifiable even if EMILIA disappears.'],
  ['Is this real, or just a draft?',
    'It is filed as an IETF Internet-Draft (draft-schrock-ep-authorization-evidence-chain), with '
    + 'a reference verifier in three languages (JavaScript, Python, Go) — one team’s ports in one '
    + 'repository, a cross-language consistency check, not independent reimplementations — that '
    + 'agree over portable conformance vectors. An outside party has reproduced the EP conformance '
    + 'suite against our published vectors and reported it on the IETF SecDispatch list.'],
];

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map(([q, a]) => ({
    '@type': 'Question',
    name: q,
    acceptedAnswer: { '@type': 'Answer', text: a },
  })),
};

export default function EvidenceChainPage() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <SiteNav activePage="Evidence Chain" />
      <main style={styles.page}>
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 56 }}>
          <div style={styles.eyebrow}>COMPOSITION · OFFLINE VERIFICATION · IETF INTERNET-DRAFT</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 900 }}>
            One verdict from many receipts.
          </h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18, fontSize: 18 }}>
            An AI agent’s action leaves a trail of signed receipts — one says it was delegated,
            one says a policy permitted it, one says a named human approved it. They are written
            by different parties, in different formats, at different hops. Nothing defines how a
            relying party checks that they all describe the <em>same</em> action and each verify,
            then turns that into a single decision.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8 }}>
            The Authorization Evidence Chain (EP-AEC) is that missing layer: a composition object
            and verifier that returns one offline, fail-closed <strong>SATISFIED</strong> or{' '}
            <strong>UNSATISFIED</strong> evidence verdict. The executor separately decides whether
            to authorize the action.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href={DT} target="_blank" rel="noopener noreferrer" style={cta.primary}>Read the Internet-Draft</a>
            <a href="/spec" style={cta.secondary}>See the full spec</a>
          </div>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 18, fontSize: 15, color: color.t2 }}>
            Run a receipt and verify it in 30 seconds, offline, no account:{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>npx @emilia-protocol/crash-test</span>
          </p>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE GAP</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>
            The field agreed on the receipt. Nobody agreed on the verdict.
          </h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
            {PROBLEM.map((c) => (
              <div key={c.label} style={{ ...styles.card, padding: 24, borderTop: `3px solid ${color.gold}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>
                  {c.label}
                </div>
                <div style={{ ...styles.cardBody, marginTop: 12, fontSize: 15, lineHeight: 1.7 }}>{c.body}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>WHAT EP-AEC DOES</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>A composition object, and a verifier for it.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            EP-AEC takes the heterogeneous receipts handed to a relying party for one action and
            binds them to a single canonical action digest. Each receipt is checked under its own
            rules by a pluggable verifier; the chain then enforces an explicit requirement —
            which receipt types must be present — and yields one offline decision. It supplies the
            one leg the rest of the cluster does not: a named, accountable human’s authorization,
            composed alongside the machine-side delegation and policy receipts.
          </p>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {STEPS.map(([label, body]) => (
              <div key={label} style={{ ...styles.card, padding: 22 }}>
                <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, letterSpacing: 1, marginBottom: 8 }}>{label}</div>
                <div style={{ ...styles.cardBody, fontSize: 15, lineHeight: 1.7 }}>{body}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.sectionWide}>
            <div style={styles.eyebrow}>WHY IT MATTERS</div>
            <h2 style={{ ...styles.h2, maxWidth: 820 }}>
              EP didn’t add a thirteenth receipt. It defined the layer that composes the other twelve.
            </h2>
            <p style={{ ...styles.body, maxWidth: 820 }}>
              A dozen efforts are racing to define “a receipt for an agent’s action,” and they have
              largely agreed on how to build one. The unclaimed ground is the verifier’s side: a
              single, offline way to combine them into a trustworthy decision. By owning composition —
              not competing on yet another format — EMILIA becomes the convergence point for the
              field rather than one of its entries.
            </p>
            <div style={{ display: 'flex', gap: 12, marginTop: 24, flexWrap: 'wrap' }}>
              <a href="/compare/landscape" style={cta.secondary}>See the landscape</a>
              <a href="/protocol" style={cta.secondary}>How the protocol fits</a>
            </div>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>BOUNDED CLAIMS</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>What it proves — and what it doesn’t.</h2>
          <div style={{ marginTop: 28, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
            {BOUNDS.map(([label, body]) => (
              <div key={label} style={{ ...styles.card, padding: 24 }}>
                <div style={{ ...styles.h3, fontSize: 20, marginBottom: 8 }}>{label}</div>
                <div style={{ ...styles.cardBody, fontSize: 15, lineHeight: 1.7 }}>{body}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>STANDING</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Filed, implemented, externally reproduced.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            EP-AEC is filed as an IETF Internet-Draft,{' '}
            <a href={DT} target="_blank" rel="noopener noreferrer" style={{ color: color.gold, textDecoration: 'none' }}>draft-schrock-ep-authorization-evidence-chain</a>,
            with a reference verifier in three languages — JavaScript, Python, and Go, one team’s
            ports in one repository, a cross-language consistency check, not independent
            reimplementations — that agree over portable conformance vectors. An outside party has
            reproduced the EP conformance suite against our published vectors and reported the
            result on the IETF SecDispatch list.
            It composes with the receipts already published across the cluster, including the EP{' '}
            <a href="/spec" style={{ color: color.gold, textDecoration: 'none' }}>authorization-receipts</a>{' '}
            and <a href="/quorum" style={{ color: color.gold, textDecoration: 'none' }}>quorum</a> drafts.
          </p>
          <div style={{ marginTop: 24 }}>
            <a href="/partners" style={cta.primary}>Talk to us about composing your receipts</a>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>FREQUENTLY ASKED</div>
          {FAQ.map(([q, a]) => (
            <div key={q} style={{ padding: '18px 0', borderTop: `1px solid ${color.border}` }}>
              <div style={{ ...styles.h3, fontSize: 18, marginBottom: 6 }}>{q}</div>
              <p style={{ ...styles.body, margin: 0, fontSize: 15, maxWidth: 820 }}>{a}</p>
            </div>
          ))}
        </section>

        <section style={styles.section}>
          <p style={{ fontSize: 13, color: color.t3, maxWidth: 760, lineHeight: 1.6 }}>
            An Authorization Evidence Chain proves that, for one canonical action, the receipts
            presented bind that action, each verify under their own rules, and a stated composition
            requirement was met — offline and without trust in the operator. It does not establish
            that the decision was correct, nor real-world identity beyond each receipt’s enrollment
            layer. Open protocol (Apache-2.0), IETF Internet-Drafts; no production deployment claim
            implied.
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
