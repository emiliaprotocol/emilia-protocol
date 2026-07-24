import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';
import claimSource from '@/security/claims.v1.json';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';
const number = (value: number | string): string => Number(value).toLocaleString('en-US');

type FormalCoverage =
  | 'verified-formal-obligations'
  | 'bounded-runtime-traced'
  | 'bounded-formal-evidence'
  | 'partial-symbolic-coverage'
  | 'executable-operational-evidence';

type FormalEvidence = {
  status: string;
  method?: string;
  trace_evidence?: string;
  trace_runner?: string;
  refinement_evidence?: string;
};

const formalCoverage = (formal: readonly FormalEvidence[]): FormalCoverage => {
  if (formal.length > 0 && formal.every((entry) => entry.status === 'verified')) {
    return 'verified-formal-obligations';
  }

  const partial = formal.filter((entry) => entry.status === 'partial');
  if (
    partial.some(
      (entry) =>
        entry.method?.startsWith('bounded_') &&
        entry.trace_evidence &&
        entry.trace_runner &&
        entry.refinement_evidence,
    )
  ) {
    return 'bounded-runtime-traced';
  }
  if (partial.some((entry) => entry.method?.startsWith('bounded_'))) {
    return 'bounded-formal-evidence';
  }
  if (partial.length > 0) {
    return 'partial-symbolic-coverage';
  }
  return 'executable-operational-evidence';
};

const CLAIM_ROWS = claimSource.claims.map((claim) => {
  return {
    claim,
    coverage: formalCoverage(claim.formal || []),
  };
});

const FORMAL_COUNTS = CLAIM_ROWS.reduce<Record<FormalCoverage, number>>(
  (counts, row) => {
    counts[row.coverage] += 1;
    return counts;
  },
  {
    'verified-formal-obligations': 0,
    'bounded-runtime-traced': 0,
    'bounded-formal-evidence': 0,
    'partial-symbolic-coverage': 0,
    'executable-operational-evidence': 0,
  },
);

const FORMAL_LABELS: Record<FormalCoverage, string> = {
  'verified-formal-obligations': 'Verified formal obligations',
  'bounded-runtime-traced': 'Bounded + runtime-traced',
  'bounded-formal-evidence': 'Bounded formal evidence',
  'partial-symbolic-coverage': 'Partial symbolic coverage',
  'executable-operational-evidence': 'Executable/operational evidence',
};

const FORMAL_TAXONOMY: ReadonlyArray<{ coverage: FormalCoverage; detail: string }> = [
  {
    coverage: 'verified-formal-obligations',
    detail: 'Every cited formal obligation is verified. The result remains limited to each model’s stated scope and does not prove implementation refinement.',
  },
  {
    coverage: 'bounded-runtime-traced',
    detail: 'Bounded same-team formal evidence is paired with selected governed runtime traces and refinement evidence; the bridge is not a complete refinement proof.',
  },
  {
    coverage: 'bounded-formal-evidence',
    detail: 'Bounded same-team model checking or exhaustive state exploration covers stated obligations without a selected runtime trace bridge.',
  },
  {
    coverage: 'partial-symbolic-coverage',
    detail: 'A symbolic model covers part of the claim; concrete implementation behavior and external assumptions remain outside that model.',
  },
  {
    coverage: 'executable-operational-evidence',
    detail: 'The exact claim is exercised by code, tests, vectors, or operational controls; no formal model covers the claim itself.',
  },
];

const FORMAL_BADGE_STYLES: Record<FormalCoverage, { color: string; background: string }> = {
  'verified-formal-obligations': { color: '#166534', background: '#DCFCE7' },
  'bounded-runtime-traced': { color: '#1D4ED8', background: '#DBEAFE' },
  'bounded-formal-evidence': { color: '#0F766E', background: '#CCFBF1' },
  'partial-symbolic-coverage': { color: '#92400E', background: '#FEF3C7' },
  'executable-operational-evidence': { color: color.t3, background: '#F5F5F4' },
};

const EVIDENCE = [
  {
    value: proofStats.formalRefinement.traces,
    label: 'Runtime-refined formal traces',
    detail: `${proofStats.formalRefinement.coveredTransitions}/${proofStats.formalRefinement.requiredTransitions} declared end-to-end transitions covered; ${proofStats.formalRefinement.unsafeMutationsDetected} unsafe mutations detected`,
  },
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
    result: `${proofStats.tla.invariants} core invariants plus ${proofStats.tla.composedLifecycleInvariants} end-to-end lifecycle invariants checked with no reported error`,
    meaning: 'The bounded models cover replay resistance, terminal-state behavior, signoff binding, delegation limits, revocation and poisoned-witness refusal, effect profiles, indeterminate execution, reconciliation, and separate remedy authority.',
  },
  {
    label: 'Formal-to-runtime selected traces',
    method: 'Content-addressed TLA+ action forcing + production entry points',
    result: `${proofStats.formalRefinement.traces} traces across ${proofStats.formalRefinement.models} models; ${proofStats.formalRefinement.coveredTransitions}/${proofStats.formalRefinement.requiredTransitions} declared end-to-end transitions covered`,
    meaning: `The harness forces exact formal transition sequences, calls the corresponding production runtime APIs, compares abstract state projections, and requires both layers to reject ${proofStats.formalRefinement.unsafeMutationsDetected} governed unsafe mutations. Declared-transition coverage is complete for one bounded composed model; this is not a complete implementation refinement proof.`,
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

const LIMITS = ['The formal models do not prove that an AI model behaves well or that an approved action is wise, legal, or safe.', 'Formal-to-runtime refinement covers selected governed traces. It is not a mechanized proof that every implementation execution refines every formal behavior.', 'The symbolic model assumes perfect cryptography and authentic pinned roots; it does not model WebAuthn internals, parser correctness, clock arithmetic, collusion, or registry completeness.', 'JavaScript, Python, and Go are same-team ports. Their agreement demonstrates consistency, not independent construction.', 'The external Rust run is pinned interoperability evidence. Strict clean-room construction acceptance remains false until separately attested under an independently pinned key.', 'Complete mediation exists only when every protected path reaches the verifier at the actual system of record or actuator.'];

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
          <h1 style={{ ...styles.h1Large, maxWidth: 840, lineHeight: 1.02 }}>Security claims you can execute, not architecture you have to trust.</h1>
          <p
            style={{
              ...styles.body,
              fontSize: 18,
              maxWidth: 780,
              marginTop: 26,
            }}
          >
            EMILIA is implemented security infrastructure. This snapshot joins an executable claim-to-code case, a composed symbolic attacker model, TLA+ and Alloy checking, content-addressed formal-to-runtime traces, cross-language negative vectors, external Rust interoperability, and durable fault tests.
          </p>
          <p
            style={{
              fontFamily: font.mono,
              fontSize: 11,
              color: color.t3,
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            Evidence snapshot: <time dateTime={proofStats.generatedAt}>{proofStats.generatedAt}</time>
            {' · '}Generated from repository manifests; CI rejects drift.
          </p>
        </section>

        <section
          style={{
            borderTop: `1px solid ${color.border}`,
            borderBottom: `1px solid ${color.border}`,
            background: '#F5F5F4',
          }}
        >
          <div style={{ ...styles.sectionWide, paddingTop: 34, paddingBottom: 34 }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))',
              }}
            >
              {EVIDENCE.map((item) => (
                <div key={item.label} style={{ padding: '16px 22px 16px 0', minHeight: 112 }}>
                  <div
                    style={{
                      fontFamily: font.sans,
                      fontSize: 32,
                      fontWeight: 700,
                      color: color.gold,
                      lineHeight: 1,
                      marginBottom: 10,
                    }}
                  >
                    {item.value}
                  </div>
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 10,
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: 1,
                      color: color.t1,
                      lineHeight: 1.45,
                    }}
                  >
                    {item.label}
                  </div>
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 10,
                      color: color.t3,
                      lineHeight: 1.5,
                      marginTop: 5,
                    }}
                  >
                    {item.detail}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 88, paddingBottom: 80 }}>
          <div style={{ maxWidth: 720, marginBottom: 48 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>What was demonstrated</div>
            <h2 style={{ ...styles.h2, fontSize: 'clamp(26px, 3vw, 38px)' }}>Seven evidence layers, each answering a different failure mode.</h2>
            <p style={styles.body}>Formal proofs do not substitute for tests, and implementation agreement does not prove construction independence. EMILIA keeps those claims separate and joins them only in the public security case.</p>
          </div>

          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {PROOF_LAYERS.map((layer, index) => (
              <article
                key={layer.label}
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))',
                  gap: 32,
                  padding: '34px 0',
                  borderBottom: `1px solid ${color.border}`,
                }}
              >
                <div>
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 10,
                      color: color.gold,
                      letterSpacing: 1.4,
                      marginBottom: 9,
                    }}
                  >
                    0{index + 1}
                  </div>
                  <h3 style={{ ...styles.h3, margin: 0 }}>{layer.label}</h3>
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 10,
                      color: color.t3,
                      marginTop: 8,
                      lineHeight: 1.5,
                    }}
                  >
                    {layer.method}
                  </div>
                </div>
                <div>
                  <div
                    style={{
                      fontFamily: font.sans,
                      fontSize: 17,
                      fontWeight: 600,
                      color: color.t1,
                      lineHeight: 1.5,
                      marginBottom: 9,
                    }}
                  >
                    {layer.result}
                  </div>
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
              <h2 style={{ ...styles.h2, fontSize: 'clamp(26px, 3vw, 38px)' }}>Two evidence axes. No hidden “done” label.</h2>
              <p style={styles.body}>Every row below is a resolved executable security-case claim with enforcement paths, tests, vectors, assumptions, exclusions, and hashed evidence. Formal model scope is reported separately through a five-way taxonomy derived from each claim’s formal metadata. No category asserts that the full implementation is formally modeled.</p>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 210px), 1fr))',
                gap: 1,
                background: color.border,
                border: `1px solid ${color.border}`,
                marginBottom: 24,
              }}
            >
              <div
                style={{
                  background: color.t1,
                  color: '#FAFAF9',
                  padding: 24,
                  minHeight: 154,
                }}
              >
                <div
                  style={{
                    fontFamily: font.mono,
                    fontSize: 10,
                    color: color.gold,
                    letterSpacing: 1.2,
                    textTransform: 'uppercase',
                    marginBottom: 14,
                  }}
                >
                  Executable evidence
                </div>
                <div
                  style={{
                    fontFamily: font.sans,
                    fontSize: 36,
                    fontWeight: 700,
                    lineHeight: 1,
                    marginBottom: 10,
                  }}
                >
                  {claimSource.claims.length}/{claimSource.claims.length}
                </div>
                <div
                  style={{
                    fontFamily: font.sans,
                    fontSize: 13,
                    lineHeight: 1.55,
                    color: 'rgba(250,250,249,0.7)',
                  }}
                >
                  Claims resolved in the generated security case.
                </div>
              </div>
              {FORMAL_TAXONOMY.map(({ coverage, detail }) => (
                <div key={coverage} style={{ background: '#FFFFFF', padding: 24, minHeight: 154 }}>
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 10,
                      color: color.t3,
                      letterSpacing: 1.2,
                      textTransform: 'uppercase',
                      marginBottom: 14,
                    }}
                  >
                    Formal evidence taxonomy
                  </div>
                  <div
                    style={{
                      fontFamily: font.sans,
                      fontSize: 36,
                      fontWeight: 700,
                      color: color.t1,
                      lineHeight: 1,
                      marginBottom: 8,
                    }}
                  >
                    {FORMAL_COUNTS[coverage]}
                  </div>
                  <div
                    style={{
                      fontFamily: font.mono,
                      fontSize: 10,
                      fontWeight: 700,
                      color: color.gold,
                      textTransform: 'uppercase',
                      letterSpacing: 0.7,
                      marginBottom: 8,
                    }}
                  >
                    {FORMAL_LABELS[coverage]}
                  </div>
                  <div
                    style={{
                      fontFamily: font.sans,
                      fontSize: 12,
                      lineHeight: 1.5,
                      color: color.t3,
                    }}
                  >
                    {detail}
                  </div>
                </div>
              ))}
            </div>

            <p
              style={{
                fontFamily: font.mono,
                fontSize: 11,
                lineHeight: 1.65,
                color: color.t2,
                margin: '0 0 36px',
                padding: '14px 16px',
                borderLeft: `3px solid ${color.gold}`,
                background: '#FFFFFF',
              }}
            >
              “Bounded + runtime-traced” does not mean a refinement proof. It identifies bounded same-team formal evidence paired with selected governed runtime traces. The separate {claimSource.claims.length}/{claimSource.claims.length} executable-evidence axis reports inspectable implementation or operational evidence for every claim.
            </p>

            <div style={{ borderTop: `1px solid ${color.borderHover}` }}>
              {CLAIM_ROWS.map(({ claim, coverage }) => {
                const evidenceCount = claim.enforcement_path.length + claim.vectors.length + claim.tests.length;
                const badgeStyle = FORMAL_BADGE_STYLES[coverage];
                return (
                  <article
                    key={claim.claim_id}
                    style={{
                      padding: '24px 0',
                      borderBottom: `1px solid ${color.border}`,
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'baseline',
                        gap: 20,
                        flexWrap: 'wrap',
                        marginBottom: 8,
                      }}
                    >
                      <code
                        style={{
                          fontFamily: font.mono,
                          fontSize: 11,
                          color: color.gold,
                        }}
                      >
                        {claim.claim_id}
                      </code>
                      <div
                        style={{
                          display: 'flex',
                          gap: 8,
                          alignItems: 'center',
                          flexWrap: 'wrap',
                        }}
                      >
                        <span
                          style={{
                            fontFamily: font.mono,
                            fontSize: 9,
                            color: color.t2,
                            textTransform: 'uppercase',
                            letterSpacing: 0.8,
                            padding: '5px 8px',
                            border: `1px solid ${color.border}`,
                          }}
                        >
                          Executable evidence · resolved · {evidenceCount} cited checks
                        </span>
                        <span
                          style={{
                            fontFamily: font.mono,
                            fontSize: 9,
                            color: badgeStyle.color,
                            background: badgeStyle.background,
                            textTransform: 'uppercase',
                            letterSpacing: 0.8,
                            padding: '5px 8px',
                          }}
                        >
                          Formal model · {FORMAL_LABELS[coverage]}
                        </span>
                      </div>
                    </div>
                    <p
                      style={{
                        fontFamily: font.sans,
                        fontSize: 15,
                        color: color.t1,
                        lineHeight: 1.65,
                        margin: 0,
                      }}
                    >
                      {claim.statement}
                    </p>
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        <section style={{ ...styles.sectionWide, paddingTop: 84, paddingBottom: 84 }}>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))',
              gap: 56,
            }}
          >
            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>Run it yourself</div>
              <h2 style={{ ...styles.h2, fontSize: 30 }}>The review path is one command at a time.</h2>
              <pre
                style={{
                  margin: '24px 0 0',
                  padding: 24,
                  overflowX: 'auto',
                  background: color.t1,
                  color: '#FAFAF9',
                  borderRadius: 8,
                  fontFamily: font.mono,
                  fontSize: 12,
                  lineHeight: 1.8,
                }}
              >
                {`npm run check:security-case
npm run check:formal-traces
npm run conformance
npm run check:proof-stats
npm run check:llm-context`}
              </pre>
              <div
                style={{
                  display: 'flex',
                  gap: 12,
                  flexWrap: 'wrap',
                  marginTop: 24,
                }}
              >
                <a href="/.well-known/emilia-context.json" className="ep-cta" style={cta.primary}>
                  Machine-readable evidence
                </a>
                <Link href="/verify-live" className="ep-cta-secondary" style={cta.secondary}>
                  Repository verification snapshot
                </Link>
                <a href={`${REPO}/blob/main/security/security-case.json`} className="ep-cta-secondary" style={cta.secondary}>
                  Resolved security case
                </a>
              </div>
            </div>

            <div>
              <div style={{ ...styles.eyebrow, color: color.gold }}>Boundaries</div>
              <h2 style={{ ...styles.h2, fontSize: 30 }}>What this evidence does not establish.</h2>
              <div style={{ borderTop: `1px solid ${color.border}` }}>
                {LIMITS.map((limit) => (
                  <p
                    key={limit}
                    style={{
                      ...styles.body,
                      fontSize: 14,
                      margin: 0,
                      padding: '15px 0',
                      borderBottom: `1px solid ${color.border}`,
                    }}
                  >
                    {limit}
                  </p>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section
          style={{
            borderTop: `1px solid ${color.border}`,
            background: color.t1,
            color: '#FAFAF9',
          }}
        >
          <div style={{ ...styles.sectionWide, paddingTop: 72, paddingBottom: 72 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>The shortest honest verdict</div>
            <h2
              style={{
                fontFamily: font.sans,
                fontSize: 'clamp(26px, 4vw, 42px)',
                lineHeight: 1.14,
                letterSpacing: -1,
                maxWidth: 780,
                margin: '0 0 20px',
                color: '#FAFAF9',
              }}
            >
              The architecture is the proposal. The executable security case is the evidence.
            </h2>
            <p
              style={{
                fontFamily: font.sans,
                fontSize: 16,
                lineHeight: 1.7,
                color: 'rgba(250,250,249,0.72)',
                maxWidth: 680,
                marginBottom: 26,
              }}
            >
              Read the assumptions, run the vectors, inspect the attack traces, and decide from the artifacts rather than from our adjectives.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link
                href="/try/receipt-required"
                className="ep-cta"
                style={{
                  ...cta.primary,
                  background: color.gold,
                  color: color.t1,
                }}
              >
                Try to break the gate
              </Link>
              <a
                href={`${REPO}/tree/main/formal/tamarin`}
                className="ep-cta-secondary"
                style={{
                  ...cta.secondary,
                  color: '#FAFAF9',
                  borderColor: 'rgba(250,250,249,0.3)',
                }}
              >
                Inspect Tamarin source
              </a>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
