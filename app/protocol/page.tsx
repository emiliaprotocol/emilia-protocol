'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import EmailCapture from '@/components/EmailCapture';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const goldText = '#765A13';

// Canonical presentation path from standards/STATUS.json. Keep these visible
// revisions aligned with that file.
const CANONICAL_DOCUMENTS = [
  {
    order: '01',
    label: 'Authorization Receipts',
    draft: 'draft-schrock-ep-authorization-receipts-10',
    question: 'What action-bound organizational approval evidence was produced under the receipt profile?',
    boundary: 'One approval-evidence profile. It does not establish scoped authority or evidence satisfaction by itself.',
    href: '/spec',
    linkLabel: 'Read Receipts -10',
    external: false,
  },
  {
    order: '02',
    label: 'Human Authorization Binding',
    draft: 'draft-schrock-human-authorization-binding-00',
    question: 'How is named-human authorization evidence bound into an adjacent host record?',
    boundary: 'A host-agnostic by-value or by-reference binding. It does not redefine the authorization artifact or host format.',
    href: 'https://datatracker.ietf.org/doc/draft-schrock-human-authorization-binding/',
    linkLabel: 'Read Binding -00',
    external: true,
  },
  {
    order: '03',
    label: 'Authority Introduction',
    draft: 'draft-schrock-ep-authority-introduction-02',
    question: "Under the relying party's trust roots, did the verified key have authority for this scope?",
    boundary: 'Trust-root introduction and scoped authority. Signature verification alone does not create authority.',
    href: 'https://datatracker.ietf.org/doc/draft-schrock-ep-authority-introduction/',
    linkLabel: 'Read Authority -02',
    external: true,
  },
  {
    order: '04',
    label: 'Authorization Evidence Chain',
    draft: 'draft-schrock-ep-authorization-evidence-chain-05',
    question: "Does the natively verified, action-matched bundle satisfy the relying party's evidence requirement?",
    boundary: 'Returns SATISFIED or UNSATISFIED. It never returns a universal authorization verdict.',
    href: '/evidence-chain',
    linkLabel: 'Read AEC -05',
    external: false,
  },
];

const DECISIONS = [
  { term: 'VERIFIED', definition: 'One artifact passed its native verifier under relying-party-selected trust inputs.' },
  { term: 'MATCH', definition: 'Independently verified artifacts denote the same exact material action under pinned mapping rules.' },
  { term: 'SATISFIED', definition: "Verified, matched evidence fills every slot in the relying party's evidence requirement." },
  { term: 'AUTHORIZED', definition: "The relying party's separate local policy permits execution." },
  { term: 'EXECUTED', definition: 'An executor asserts or attests that an effect occurred; evidence satisfaction does not prove the effect.' },
];

const GATE_STEPS = [
  {
    order: '01',
    title: 'Describe one exact action',
    body: 'Bind the operation, target, material parameters, actor, and context before asking for authority. A receipt for a different payload does not transfer.',
  },
  {
    order: '02',
    title: 'Verify the required evidence',
    body: 'Check each artifact under its native rules and relying-party-pinned trust inputs, then match every required leg to the same material action.',
  },
  {
    order: '03',
    title: 'Authorize and reserve before invocation',
    body: 'AEC satisfaction is evidence, not permission. Gate applies local policy and current-status checks, then reserves one-time admission at the protected boundary before the provider call begins.',
  },
  {
    order: '04',
    title: 'Record the outcome without inventing certainty',
    body: 'Preserve refusal, consumption, and outcome evidence. An indeterminate provider result enters authenticated reconciliation; it is not fresh authority to retry.',
  },
];

const COVERAGE_CONTROLS = [
  'Inventory every effect-capable route and credential in the declared deployment scope.',
  'Put admission at each executor or system-of-record boundary where the consequence can still be stopped.',
  'Probe protected and alternate paths; a verified bypass overrides a successful blocked-path demonstration.',
  'Classify coverage as gated, ungated, stale, or unknown, and re-evaluate it when routes or credentials change.',
];

export default function ProtocolPage() {
  useEffect(() => {
    const elements = document.querySelectorAll('.ep-reveal');
    const observer = new IntersectionObserver(
      entries => entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      }),
      { threshold: 0.12 },
    );

    elements.forEach(element => observer.observe(element));
    return () => observer.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="Protocol" />

      <main>
        <section style={{ ...styles.sectionWide, paddingTop: 104, paddingBottom: 72 }}>
          <div className="ep-tag ep-hero-badge">Gate first · Open protocol</div>
          <h1 className="ep-hero-text" style={{ ...styles.h1Large, maxWidth: 860 }}>
            Gate exact actions before consequences.
          </h1>
          <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 740, marginTop: 24, fontSize: 18 }}>
            EMILIA Gate sits on a configured executor or system-of-record path where an action can
            still be refused. For one exact material action, it verifies the required evidence under
            relying-party-pinned trust, applies local authorization policy, and reserves admission
            before invocation.
          </p>
          <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 740 }}>
            The four-document path below explains the evidence Gate can consume. It does not turn a
            <strong> SATISFIED</strong> evidence result into an <strong>AUTHORIZED</strong> decision,
            prove execution, or establish complete mediation across routes a deployment has not put
            behind Gate.
          </p>
          <div className="ep-hero-text" style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
            <a href="#canonical-path" className="ep-cta" style={cta.primary}>Follow the four-document path</a>
            <a href="/gate" className="ep-cta-secondary" style={cta.secondary}>See EMILIA Gate</a>
          </div>
        </section>

        <section id="canonical-path" style={styles.sectionAlt}>
          <div style={styles.sectionWide}>
            <div className="ep-reveal" style={{ marginBottom: 36 }}>
              <div style={styles.eyebrow}>Canonical presentation path</div>
              <h2 style={{ ...styles.h2, fontSize: 30, maxWidth: 720 }}>Four documents. One evidence path.</h2>
              <p style={{ ...styles.body, maxWidth: 780 }}>
                Start with the approval artifact, carry it into the host record, establish scoped
                authority under the relying party&apos;s trust roots, then evaluate whether the verified,
                action-matched bundle satisfies that party&apos;s evidence requirement.
              </p>
              <p style={{ ...styles.body, maxWidth: 780, fontSize: 14, color: color.t3, marginBottom: 0 }}>
                This is a reader-facing path over four active individual Internet-Drafts. It does not
                merge, replace, retire, or subordinate the rest of the protocol portfolio.
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
              {CANONICAL_DOCUMENTS.map((document, index) => (
                <article
                  key={document.draft}
                  data-testid={`canonical-document-${index + 1}`}
                  className={`ep-card-lift ep-reveal ep-stagger-${index + 1}`}
                  style={{
                    ...styles.card,
                    display: 'flex',
                    minHeight: 340,
                    flexDirection: 'column',
                    borderTop: `3px solid ${index === 0 ? color.gold : color.borderHover}`,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, marginBottom: 22 }}>
                    <span style={{ fontFamily: font.mono, fontSize: 11, color: goldText, letterSpacing: 1.5 }}>
                      {document.order} / 04
                    </span>
                    <span style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 1.2, textTransform: 'uppercase' }}>
                      Internet-Draft
                    </span>
                  </div>
                  <h3 style={{ ...styles.h3, fontSize: 21 }}>{document.label}</h3>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, lineHeight: 1.5, overflowWrap: 'anywhere', marginBottom: 18 }}>
                    {document.draft}
                  </div>
                  <p style={{ ...styles.cardBody, fontSize: 15, marginBottom: 14 }}><strong>{document.question}</strong></p>
                  <p style={{ ...styles.cardBody, marginBottom: 24 }}>{document.boundary}</p>
                  <a
                    href={document.href}
                    target={document.external ? '_blank' : undefined}
                    rel={document.external ? 'noopener noreferrer' : undefined}
                    aria-label={`${document.linkLabel}: ${document.label}`}
                    style={{ ...cta.ghost, marginTop: 'auto', color: goldText }}
                  >
                    {document.linkLabel}{document.external ? ' ↗' : ' →'}
                  </a>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div className="ep-reveal" style={{ marginBottom: 36 }}>
            <div style={styles.eyebrow}>Terms that do not collapse</div>
            <h2 style={{ ...styles.h2, fontSize: 30, maxWidth: 760 }}>
              Evidence is an input to authorization, not a synonym for it.
            </h2>
            <p style={{ ...styles.body, maxWidth: 760 }}>
              Each result has a separate owner and claim. Passing one stage never silently proves a later one.
            </p>
          </div>
          <div className="ep-reveal" style={{ borderTop: `1px solid ${color.border}`, borderLeft: `1px solid ${color.border}` }}>
            {DECISIONS.map(decision => (
              <div
                key={decision.term}
                className="ep-row-hover ep-protocol-detail-row"
                style={{
                  display: 'flex',
                  gap: 28,
                  alignItems: 'flex-start',
                  padding: '18px 24px',
                  borderRight: `1px solid ${color.border}`,
                  borderBottom: `1px solid ${color.border}`,
                }}
              >
                <span style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 600, color: goldText, minWidth: 110, paddingTop: 3 }}>
                  {decision.term}
                </span>
                <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.7 }}>{decision.definition}</span>
              </div>
            ))}
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.sectionWide}>
            <div className="ep-reveal" style={{ marginBottom: 36 }}>
              <div style={styles.eyebrow}>Gate execution path</div>
              <h2 style={{ ...styles.h2, fontSize: 30, maxWidth: 760 }}>
                Put the decision where the consequence can still be stopped.
              </h2>
              <p style={{ ...styles.body, maxWidth: 780 }}>
                The protocol keeps evidence portable. Gate joins that evidence to local authority
                and one-time admission at the protected effect boundary.
              </p>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
              {GATE_STEPS.map((step, index) => (
                <article key={step.order} className={`ep-card-lift ep-reveal ep-stagger-${index + 1}`} style={{ ...styles.card, padding: 24 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: goldText, letterSpacing: 1.5, marginBottom: 14 }}>
                    STEP {step.order}
                  </div>
                  <h3 style={styles.h3}>{step.title}</h3>
                  <p style={{ ...styles.cardBody, margin: 0 }}>{step.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={{ background: '#1C1917', borderTop: `4px solid ${color.gold}` }}>
          <div style={{ ...styles.sectionWide, paddingTop: 76, paddingBottom: 76 }}>
            <div className="ep-reveal" style={{ maxWidth: 840 }}>
              <div style={{ ...styles.eyebrow, color: goldText }}>Deployment boundary</div>
              <h2 style={{ ...styles.h2, color: '#FAFAF9', fontSize: 32, lineHeight: 1.2 }}>
                A protected path is not proof of complete mediation.
              </h2>
              <p style={{ fontSize: 16, lineHeight: 1.75, color: 'rgba(250,250,249,0.7)', maxWidth: 760, marginBottom: 28 }}>
                The four documents define portable evidence semantics. Gate enforces only on the
                configured effect-capable boundaries a deployment actually controls. A complete-mediation
                claim needs current deployment evidence that every in-scope route is covered.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
                {COVERAGE_CONTROLS.map((control, index) => (
                  <div key={control} style={{ display: 'flex', gap: 12, padding: '16px 18px', border: '1px solid rgba(255,255,255,0.12)', borderRadius: radius.base }}>
                    <span style={{ fontFamily: font.mono, fontSize: 10, color: goldText, paddingTop: 3 }}>{String(index + 1).padStart(2, '0')}</span>
                    <span style={{ fontSize: 14, lineHeight: 1.65, color: 'rgba(250,250,249,0.72)' }}>{control}</span>
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 32 }}>
                <a href="/gate" className="ep-cta" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917' }}>See the Gate product</a>
                <a href="/proof" className="ep-cta-secondary" style={{ ...cta.secondary, color: '#FAFAF9', borderColor: 'rgba(255,255,255,0.2)' }}>Inspect the evidence</a>
              </div>
            </div>
          </div>
        </section>

        <section style={styles.sectionWide}>
          <div className="ep-reveal" style={{ ...styles.card, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 28, alignItems: 'center', padding: '32px 36px' }}>
            <div>
              <div style={styles.eyebrow}>Start with document 01</div>
              <h2 style={{ ...styles.h2, marginBottom: 10 }}>Authorization Receipts -10</h2>
              <p style={{ ...styles.cardBody, fontSize: 15, margin: 0 }}>
                Read the current posted receipt profile, then continue through binding, authority, and AEC.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <a href="/spec" className="ep-cta" style={cta.primary}>Read Receipts -10</a>
              <a href="/standards" className="ep-cta-secondary" style={cta.secondary}>View the full portfolio</a>
            </div>
          </div>
        </section>
      </main>

      <EmailCapture
        eyebrow="Track the standard"
        heading="Follow the protocol as it develops."
        sub="New drafts, conformance releases, and reference updates — sent only when there’s something worth your time."
      />

      <SiteFooter />
    </div>
  );
}
