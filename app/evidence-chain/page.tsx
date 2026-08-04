// SPDX-License-Identifier: Apache-2.0
// EP-AEC (Authorization Evidence Chain) - the composition layer.
// Marketing + SEO landing for draft-schrock-ep-authorization-evidence-chain.

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';

const DRAFT = 'draft-schrock-ep-authorization-evidence-chain-05';
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
    label: 'The bundle needs its own result',
    body: 'The mature efforts independently converged on one substrate: bind the action with a '
      + 'canonical digest (JCS, RFC 8785) and sign it. But no specification defines how a '
      + 'relying party checks that the several receipts it was handed all bind the same action '
      + 'and each verify — then evaluates them against its explicit evidence requirement.',
  },
  {
    label: 'Trust leaks in the gaps',
    body: 'Without a composite check, a relying party either trusts an operator to have stapled '
      + 'the right receipts together or risks accepting an artifact issued for a different action. '
      + 'AEC makes the action match and the evidence requirement explicit and inspectable.',
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
    + 'Closed, stapled inputs need no EMILIA service call; the relying party still pins trust, '
    + 'freshness, and current-status rules. It separately decides whether to authorize execution.'],
];

const BOUNDS = [
  ['What an evidence chain proves',
    'That, for one exact material action and the stated evaluation inputs, the required artifacts '
    + 'verify under their native rules, match that action, and fill the relying party’s explicit '
    + 'evidence requirement.'],
  ['What it does not prove',
    'That the underlying decision was correct; real-world identity beyond each artifact’s '
    + 'enrollment layer; current status not supplied by the evaluation profile; local authorization; '
    + 'execution; or complete mediation. AEC is an evidence-satisfaction object, not a universal ALLOW.'],
];

const FAQ = [
  ['Is EP-AEC just another receipt format?',
    'No. It is deliberately not a 13th receipt. The field already converged on a common '
    + 'substrate for individual receipts; what was missing is the layer that composes several '
    + 'heterogeneous receipts for one action into a single offline verdict. AEC is that layer — '
    + 'a composition object plus a verifier with pluggable per-receipt checks.'],
  ['What exactly does the verifier return?',
    'A SATISFIED or UNSATISFIED evidence verdict for one exact material action. SATISFIED requires '
    + 'that each required artifact natively verifies, matches the action, and fills the relying '
    + 'party’s evidence requirement. It is not an ALLOW decision: the executor applies its own '
    + 'authorization policy separately.'],
  ['How does it relate to DRP, permit receipts, or PSEA?',
    'As complements, not competitors. Delegation (e.g. DRP), policy/permit, and decision '
    + 'receipts each answer their own hop; AEC can verify that those receipts, plus named-human '
    + 'authorization evidence when the relying party requires it, all bind the same action and '
    + 'verify together. It is a verifier-side composition point for the cluster.'],
  ['Does it need to be online?',
    'A closed bundle can be evaluated offline without an EMILIA account or service call. The '
    + 'relying party still chooses trusted issuers, keys, reference time, freshness, and any '
    + 'current-status evidence; a profile that requires live status can require network access.'],
  ['Is this real, or just a draft?',
    'Revision -05 is filed as an individual IETF Internet-Draft (draft-schrock-ep-authorization-evidence-chain), with '
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
      <SiteNav activePage="Protocol" />
      <main style={styles.page}>
        <section style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 56 }}>
          <nav aria-label="Canonical four-document path" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16, flexWrap: 'wrap', paddingBottom: 18, marginBottom: 36, borderBottom: `1px solid ${color.border}`, fontFamily: font.mono, fontSize: 11 }}>
            <a href="/protocol" style={{ color: color.gold, textDecoration: 'none' }}>← Four-document protocol hub</a>
            <span style={{ color: color.t3 }}>Canonical path · 04 of 04</span>
          </nav>
          <div style={styles.eyebrow}>DOCUMENT 04 · EVIDENCE SATISFACTION · IETF INTERNET-DRAFT</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 900 }}>
            One evidence result from many artifacts.
          </h1>
          <p style={{ ...styles.body, maxWidth: 780, marginTop: 18, fontSize: 18 }}>
            An AI agent’s action leaves a trail of signed receipts — one says it was delegated,
            one says a policy permitted it, one says a named human approved it. They are written
            by different parties, in different formats, at different hops. A relying party needs
            an explicit way to check that they all describe the <em>same</em> action, verify under
            their native rules, and fill its stated evidence requirement.
          </p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 8 }}>
            The Authorization Evidence Chain (EP-AEC) is that composition layer: an object
            and verifier that returns a fail-closed <strong>SATISFIED</strong> or{' '}
            <strong>UNSATISFIED</strong> evidence verdict. The executor separately decides whether
            to authorize the action.
          </p>
          <div style={{ display: 'flex', gap: 12, marginTop: 30, flexWrap: 'wrap' }}>
            <a href={DT} target="_blank" rel="noopener noreferrer" style={cta.primary}>Read AEC -05</a>
            <a href="/protocol" style={cta.secondary}>Back to the four-document path</a>
          </div>
          <p style={{ fontFamily: font.mono, color: color.t3, fontSize: 11, marginTop: 20 }}>{DRAFT}</p>
          <p style={{ ...styles.body, maxWidth: 760, marginTop: 18, fontSize: 15, color: color.t2 }}>
            Run a receipt and verify it in 30 seconds, offline, no account:{' '}
            <span style={{ fontFamily: font.mono, color: color.t1 }}>npx @emilia-protocol/crash-test</span>
          </p>
        </section>

        <section style={styles.sectionWide}>
          <div style={styles.eyebrow}>THE GAP</div>
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>
            Individual artifacts are not yet an evidence decision.
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
            which receipt types must be present — and yields one evidence-satisfaction result. When
            required, it can compose named-human authorization evidence alongside machine-side
            delegation and policy receipts without redefining their native semantics.
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
          <h2 style={{ ...styles.h2, maxWidth: 760 }}>Filed, implemented, reproducibly tested.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            EP-AEC -05 is filed as an individual IETF Internet-Draft,{' '}
            <a href={DT} target="_blank" rel="noopener noreferrer" style={{ color: color.gold, textDecoration: 'none' }}>draft-schrock-ep-authorization-evidence-chain</a>,
            with a reference verifier in three languages — JavaScript, Python, and Go, one team’s
            ports in one repository, a cross-language consistency check, not independent
            reimplementations — that agree over portable conformance vectors. An outside party
            reproduced a time-pinned EP conformance bundle and reported that result on the IETF
            SecDispatch list; that historical run is not silently extended to later AEC revisions
            or newly added vectors.
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
            requirement was met under relying-party-pinned evaluation inputs. It does not establish
            that the decision was correct, nor real-world identity beyond each receipt’s enrollment
            layer, local authorization, execution, or complete mediation. Open protocol (Apache-2.0),
            individual IETF Internet-Draft; no production deployment claim implied.
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
