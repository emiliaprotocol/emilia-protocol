import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';
import claimSource from '@/security/claims.v1.json';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';
const number = (value) => Number(value).toLocaleString('en-US');

const EVIDENCE = [
  {
    value: proofStats.tamarin.verifiedObligations,
    label: 'Composed Tamarin obligations',
    detail: `${proofStats.tamarin.deliberatelyUnsafeCounterexamples} weakened variants produce concrete attack traces`,
  },
  {
    value: proofStats.securityCase.claims,
    label: 'Executable security claims',
    detail: `${proofStats.securityCase.evidenceFiles} hashed evidence files in one resolved case`,
  },
  {
    value: proofStats.conformance.vectors,
    label: 'Current conformance vectors',
    detail: `${proofStats.conformance.suites} suites across same-team JS, Python, and Go ports`,
  },
  {
    value: proofStats.externalImplementation.hostilityCases,
    label: 'External hostility cases',
    detail: `Pinned ${proofStats.externalImplementation.language} source; construction scope disclosed`,
  },
  {
    value: number(proofStats.tests.total),
    label: 'Automated test cases',
    detail: `${number(proofStats.tests.files)} files; all platform-applicable cases pass`,
  },
];

const PROOF_LAYERS = [
  {
    label: 'Hostile-network composition',
    method: 'Tamarin 1.10.0 · Dolev-Yao',
    result: `${proofStats.tamarin.verifiedObligations} obligations verified in one model from challenge through execution`,
    meaning: 'The attacker may control the network and obtain unrelated honest signatures. Under uncompromised pinned roots, execution still requires the exact challenge, action, two distinct approvals, issuer and authority pins, registry view, revocation state, and one-time consumption.',
  },
  {
    label: 'State-machine safety',
    method: `${proofStats.tla.checker} · TLA+`,
    result: `${proofStats.tla.invariants} invariants checked with no reported error`,
    meaning: 'The bounded authorization state machine checks replay resistance, terminal-state behavior, signoff binding, delegation limits, and write-bypass safety.',
  },
  {
    label: 'Relational structure',
    method: `${proofStats.alloy.version} · Alloy`,
    result: `${proofStats.alloy.facts} facts and ${proofStats.alloy.assertions} assertions`,
    meaning: 'Alloy checks structural relationships that the temporal TLA+ model does not express, including identity, signoff, receipt, and federation constraints.',
  },
  {
    label: 'Claim-to-code traceability',
    method: 'EP-SECURITY-CASE-SOURCE-v2',
    result: `${proofStats.securityCase.claims} claims resolved over ${proofStats.securityCase.evidenceFiles} hashed files`,
    meaning: 'Every public security claim names its enforcement path, positive and negative vectors, language coverage, formal status or explicit gap, assumptions, exclusions, and evidence artifact hash.',
  },
  {
    label: 'Portable implementation behavior',
    method: 'Shared vectors + evaluator-controlled rebuild',
    result: `${proofStats.conformance.vectors} vectors plus ${proofStats.externalImplementation.hostilityCases} external hostility cases`,
    meaning: 'The three reference ports are honestly labeled same-team consistency evidence. A separately authored Rust verifier is pinned to exact public source and tested against the current vector set; strict construction attestation remains separately disclosed.',
  },
  {
    label: 'Stateful enforcement under faults',
    method: 'Generated schedules + concurrent reservation storms',
    result: '5,000 generated schedules and a 100-way reservation race',
    meaning: 'The durable gate checks at-most-once effects across concurrent workers, process restarts, abandoned reservations, stale-replica promotion, rollback attempts, and ambiguous executor outcomes.',
  },
];

const LIMITS = [
  'The formal models do not prove that an AI model behaves well or that an approved action is wise, legal, or safe.',
  'The symbolic model assumes perfect cryptography and authentic pinned roots; it does not model WebAuthn internals, parser correctness, clock arithmetic, collusion, or registry completeness.',
  'JavaScript, Python, and Go are same-team ports. Their agreement demonstrates consistency, not independent construction.',
  'The external Rust run is pinned interoperability evidence. Strict clean-room construction acceptance remains false until separately attested under an independently pinned key.',
  'Complete mediation exists only when every protected path reaches the verifier at the actual system of record or actuator.',
];

export default async function ProofPage() {
  const nonce = (await headers()).get('x-nonce') ?? '';
  const jsonLd = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'TechArticle',
        headline: 'EMILIA Protocol Engineering Evidence',
        description: `A machine-verifiable security case with ${proofStats.securityCase.claims} executable claims, ${proofStats.tamarin.verifiedObligations} composed Tamarin obligations, and ${proofStats.conformance.vectors} conformance vectors.`,
        url: 'https://www.emiliaprotocol.ai/proof',
        dateModified: proofStats.generatedAt,
        author: { '@type': 'Organization', name: 'EMILIA Protocol' },
        publisher: { '@type': 'Organization', name: 'EMILIA Protocol' },
        about: ['AI agent authorization', 'formal verification', 'security protocol conformance'],
      },
      {
        '@type': 'Dataset',
        name: 'EMILIA Machine-Verifiable Security Case',
        description: `${proofStats.securityCase.claims} executable security claims with code paths, vectors, formal scope, assumptions, exclusions, and hashes.`,
        url: 'https://www.emiliaprotocol.ai/.well-known/emilia-context.json',
        dateModified: proofStats.generatedAt,
        license: 'https://www.apache.org/licenses/LICENSE-2.0',
        creator: { '@type': 'Organization', name: 'EMILIA Protocol' },
        distribution: {
          '@type': 'DataDownload',
          encodingFormat: 'application/json',
          contentUrl: 'https://www.emiliaprotocol.ai/.well-known/emilia-context.json',
        },
      },
    ],
  };

  return (
    <div style={styles.page}>
      <script type="application/ld+json" nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <SiteNav activePage="Proof" />

      <main>
        <section style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 36 }}>
          <div style={{ ...styles.eyebrow, color: color.gold }}>EMILIA Engineering Evidence</div>
          <h1 style={{ ...styles.h1Large, maxWidth: 840, lineHeight: 1.02 }}>
            Security claims you can execute, not architecture you have to trust.
          </h1>
          <p style={{ ...styles.body, fontSize: 18, maxWidth: 780, marginTop: 26 }}>
            EMILIA is implemented security infrastructure. This snapshot joins an executable
            claim-to-code case, a composed symbolic attacker model, TLA+ and Alloy checking,
            cross-language negative vectors, external Rust interoperability, and durable fault tests.
          </p>
          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, lineHeight: 1.6, margin: 0 }}>
            Evidence snapshot: <time dateTime={proofStats.generatedAt}>{proofStats.generatedAt}</time>
            {' · '}Generated from repository manifests; CI rejects drift.
          </p>
        </section>

        <section style={{ borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`, background: '#F5F5F4' }}>
          <div style={{ ...styles.sectionWide, paddingTop: 34, paddingBottom: 34 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))' }}>
              {EVIDENCE.map((item) => (
                <div key={item.label} style={{ padding: '16px 22px 16px 0', minHeight: 112 }}>
                  <div style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: color.gold, lineHeight: 1, marginBottom: 10 }}>{item.value}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, color: color.t1, lineHeight: 1.45 }}>{item.label}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, lineHeight: 1.5, marginTop: 5 }}>{item.detail}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 88, paddingBottom: 80 }}>
          <div style={{ maxWidth: 720, marginBottom: 48 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>What was demonstrated</div>
            <h2 style={{ ...styles.h2, fontSize: 'clamp(26px, 3vw, 38px)' }}>Six evidence layers, each answering a different failure mode.</h2>
            <p style={styles.body}>
              Formal proofs do not substitute for tests, and implementation agreement does not
              prove construction independence. EMILIA keeps those claims separate and joins them
              only in the public security case.
            </p>
          </div>

          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {PROOF_LAYERS.map((layer, index) => (
              <article key={layer.label} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))', gap: 32, padding: '34px 0', borderBottom: `1px solid ${color.border}` }}>
                <div>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.4, marginBottom: 9 }}>0{index + 1}</div>
                  <h3 style={{ ...styles.h3, margin: 0 }}>{layer.label}</h3>
                  <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, marginTop: 8, lineHeight: 1.5 }}>{layer.method}</div>
                </div>
                <div>
                  <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 600, color: color.t1, lineHeight: 1.5, marginBottom: 9 }}>{layer.result}</div>
                  <p style={{ ...styles.body, fontSize: 15, margin: 0 }}>{layer.meaning}</p>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={{ ...styles.sectionWide, paddingTop: 80, paddingBottom: 80 }}>
            <div style={{ maxWidth: 720, marginBottom: 42 }}>
              <div style={{ ...styles.eyebrow, color: color.gold }}>Executable claim inventory</div>
              <h2 style={{ ...styles.h2, fontSize: 'clamp(26px, 3vw, 38px)' }}>
                Every headline resolves to code, vectors, scope, and assumptions.
              </h2>
              <p style={styles.body}>
                These are the current machine-verifiable claim statements. The JSON security case
                contains the exact enforcement paths and evidence hashes behind each one.
              </p>
            </div>

            <div style={{ borderTop: `1px solid ${color.borderHover}` }}>
              {claimSource.claims.map((claim) => {
                const formalStatuses = [...new Set((claim.formal || []).map((entry) => entry.status))];
                return (
                  <article key={claim.claim_id} style={{ padding: '24px 0', borderBottom: `1px solid ${color.border}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 20, flexWrap: 'wrap', marginBottom: 8 }}>
                      <code style={{ fontFamily: font.mono, fontSize: 11, color: color.gold }}>{claim.claim_id}</code>
                      <span style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, textTransform: 'uppercase', letterSpacing: 1 }}>
                        formal: {formalStatuses.join(' + ').replaceAll('_', ' ') || 'not modeled'}
                      </span>
                    </div>
                    <p style={{ fontFamily: font.sans, fontSize: 15, color: color.t1, lineHeight: 1.65, margin: 0 }}>{claim.statement}</p>
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 84, paddingBottom: 84 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))', gap: 56 }}>
            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>Run it yourself</div>
              <h2 style={{ ...styles.h2, fontSize: 30 }}>The review path is one command at a time.</h2>
              <pre style={{ margin: '24px 0 0', padding: 24, overflowX: 'auto', background: color.t1, color: '#FAFAF9', borderRadius: 8, fontFamily: font.mono, fontSize: 12, lineHeight: 1.8 }}>
{`npm run check:security-case
npm run conformance
npm run check:proof-stats
npm run check:llm-context`}
              </pre>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
                <a href="/.well-known/emilia-context.json" className="ep-cta" style={cta.primary}>Machine-readable evidence</a>
                <a href={`${REPO}/blob/main/security/security-case.json`} className="ep-cta-secondary" style={cta.secondary}>Resolved security case</a>
              </div>
            </div>

            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>Boundaries</div>
              <h2 style={{ ...styles.h2, fontSize: 30 }}>What this evidence does not establish.</h2>
              <div style={{ borderTop: `1px solid ${color.border}` }}>
                {LIMITS.map((limit) => (
                  <p key={limit} style={{ ...styles.body, fontSize: 14, margin: 0, padding: '15px 0', borderBottom: `1px solid ${color.border}` }}>{limit}</p>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section style={{ borderTop: `1px solid ${color.border}`, background: color.t1, color: '#FAFAF9' }}>
          <div style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 72 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>The shortest honest verdict</div>
            <h2 style={{ fontFamily: font.sans, fontSize: 'clamp(26px, 4vw, 42px)', lineHeight: 1.14, letterSpacing: -1, maxWidth: 780, margin: '0 0 20px', color: '#FAFAF9' }}>
              The architecture is the proposal. The executable security case is the evidence.
            </h2>
            <p style={{ fontFamily: font.sans, fontSize: 16, lineHeight: 1.7, color: 'rgba(250,250,249,0.72)', maxWidth: 680, marginBottom: 26 }}>
              Read the assumptions, run the vectors, inspect the attack traces, and decide from the
              artifacts rather than from our adjectives.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/try/receipt-required" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: color.t1 }}>Try to break the gate</Link>
              <a href={`${REPO}/tree/main/formal/tamarin`} className="ep-cta-secondary" style={{ ...cta.secondary, color: '#FAFAF9', borderColor: 'rgba(250,250,249,0.3)' }}>Inspect Tamarin source</a>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
