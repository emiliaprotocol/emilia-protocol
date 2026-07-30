import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { GATE_QUALIFICATION } from '@/lib/commercial-offer';
import { styles, cta, color, font } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';
import claimSource from '@/security/claims.v1.json';

const REPO = 'https://github.com/emiliaprotocol/emilia-protocol';
const SOURCE_REVISION = /^[0-9a-f]{40}$/i.test(process.env.VERCEL_GIT_COMMIT_SHA || '')
  ? (process.env.VERCEL_GIT_COMMIT_SHA as string)
  : 'main';
const SOURCE_BLOB = `${REPO}/blob/${SOURCE_REVISION}`;
const number = (value: number | string): string => Number(value).toLocaleString('en-US');

type FormalCoverage =
  | 'verified-formal-obligations'
  | 'bounded-runtime-traced'
  | 'bounded-formal-evidence'
  | 'partial-symbolic-coverage'
  | 'executable-operational-evidence';

type ProofStatsCoverage =
  | 'verifiedFormalObligations'
  | 'boundedRuntimeTraced'
  | 'boundedFormalEvidence'
  | 'partialSymbolicCoverage'
  | 'executableOperationalEvidence';

const COVERAGE_KEYS: ReadonlyArray<{
  stats: ProofStatsCoverage;
  page: FormalCoverage;
}> = [
  { stats: 'verifiedFormalObligations', page: 'verified-formal-obligations' },
  { stats: 'boundedRuntimeTraced', page: 'bounded-runtime-traced' },
  { stats: 'boundedFormalEvidence', page: 'bounded-formal-evidence' },
  { stats: 'partialSymbolicCoverage', page: 'partial-symbolic-coverage' },
  { stats: 'executableOperationalEvidence', page: 'executable-operational-evidence' },
];

const CLAIM_COVERAGE = new Map<string, FormalCoverage>(
  COVERAGE_KEYS.flatMap(({ stats, page }) =>
    proofStats.formalEvidenceCoverage[stats].claimIds.map((claimId) => [claimId, page] as const),
  ),
);

if (CLAIM_COVERAGE.size !== claimSource.claims.length) {
  throw new Error('Generated proof taxonomy does not cover the public claim inventory');
}

const CLAIM_ROWS = claimSource.claims.map((claim) => {
  const coverage = CLAIM_COVERAGE.get(claim.claim_id);
  if (!coverage) throw new Error(`Generated proof taxonomy omits ${claim.claim_id}`);
  return { claim, coverage };
});

const FORMAL_COUNTS = Object.fromEntries(
  COVERAGE_KEYS.map(({ stats, page }) => [
    page,
    proofStats.formalEvidenceCoverage[stats].count,
  ]),
) as Record<FormalCoverage, number>;

const FORMAL_LABELS: Record<FormalCoverage, string> = {
  'verified-formal-obligations': 'Verified formal obligations',
  'bounded-runtime-traced': 'Bounded + selected runtime scenarios',
  'bounded-formal-evidence': 'Bounded formal evidence',
  'partial-symbolic-coverage': 'Partial symbolic coverage',
  'executable-operational-evidence': 'Executable/operational evidence (not formally modeled)',
};

const FORMAL_TAXONOMY: ReadonlyArray<{ coverage: FormalCoverage; detail: string }> = [
  {
    coverage: 'verified-formal-obligations',
    detail: 'Every cited formal obligation is verified. The result remains limited to each model’s stated scope and does not prove implementation refinement.',
  },
  {
    coverage: 'bounded-runtime-traced',
    detail: 'Bounded same-team formal evidence is paired with selected deterministic runtime scenarios under hand-authored mappings; the bridge is not a complete refinement proof.',
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
    value: proofStats.formalScenarioConformance.scenarios,
    label: 'Selected model/runtime scenarios',
    detail: `${proofStats.formalScenarioConformance.soundScenarios} positive-path scenarios; ${proofStats.formalScenarioConformance.pairedNegativeControls} paired formal counterexamples and runtime refusals`,
  },
  {
    value: proofStats.tamarin.verifiedObligations,
    label: 'Verified Tamarin lemmas',
    detail: `${proofStats.tamarin.allTraceObligations} all-traces obligations and ${proofStats.tamarin.existsTraceWitnesses} exists-trace witnesses across ${proofStats.tamarin.models} models`,
  },
  {
    value: proofStats.securityCase.claims,
    label: 'Executable security claims',
    detail: `${proofStats.securityCase.evidenceFiles} hashed evidence files in one passing generated case`,
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
    result: `${proofStats.tamarin.verifiedObligations} lemmas verified: ${proofStats.tamarin.allTraceObligations} all-traces obligations and ${proofStats.tamarin.existsTraceWitnesses} reachability witnesses`,
    meaning: 'The attacker may control the network and obtain unrelated honest signatures. Under uncompromised pinned roots, execution still requires the exact challenge, action, two distinct approvals, issuer and authority pins, registry view, revocation state, one-time consumption, and the dedicated six-claim boundaries.',
  },
  {
    label: 'State-machine safety',
    method: `${proofStats.tla.checker} · TLA+`,
    result: `${proofStats.tla.invariants} core invariants plus ${proofStats.tla.composedLifecycleInvariants} end-to-end lifecycle invariants checked with no reported error`,
    meaning: 'The bounded models cover replay resistance, terminal-state behavior, signoff binding, delegation limits, revocation and poisoned-witness refusal, effect profiles, indeterminate execution, reconciliation, and separate remedy authority.',
  },
  {
    label: 'Selected model/runtime scenario conformance',
    method: 'Content-addressed bounded models + deterministic runtime scenarios',
    result: `${proofStats.formalScenarioConformance.scenarios} scenarios across ${proofStats.formalScenarioConformance.models} models and ${proofStats.formalScenarioConformance.claims} claims`,
    meaning: `The same-team harness pairs bounded formal scenarios with deterministic runtime executions under an explicit, hand-authored projection relation. Its ${proofStats.formalScenarioConformance.pairedNegativeControls} negative controls pair a formal counterexample with a safe-runtime refusal; they do not mutate the runtime implementation. This is selected-scenario conformance, not a complete implementation refinement proof.`,
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
    result: `${proofStats.securityCase.claims} claims validated over ${proofStats.securityCase.evidenceFiles} hashed files`,
    meaning: 'Every public security claim has resolvable enforcement paths, positive and negative vectors, language coverage, formal status or explicit gap, assumptions, exclusions, and evidence hashes, and its configured executable checks pass.',
  },
  {
    label: 'Portable implementation behavior',
    method: 'Shared vectors + evaluator-controlled rebuild',
    result: `${proofStats.conformance.vectors} vectors plus ${proofStats.externalImplementation.hostilityCases} external hostility cases`,
    meaning: 'The three reference ports are honestly labeled same-team consistency evidence. A separately authored Rust verifier is tested against the pinned 16-suite/164-vector bundle and 359-case hostility campaign; newer suites are not attributed to Rust, and strict construction acceptance remains false.',
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
  GATE_QUALIFICATION.disclaimer,
  'The Reliance Risk Plane does not insure, bear or allocate loss, adjudicate disputes or losses, prove coverage, causation, solvency, or population completeness, or move money.',
  'Selected model/runtime scenarios are same-team conformance evidence under hand-authored mappings. They are not a mechanized proof that every implementation execution refines every formal behavior.',
  'The negative controls pair formal counterexamples with safe-runtime refusals; they do not inject those defects into the runtime implementation.',
  'Deterministic or in-memory scenario adapters are not production-deployment, storage-durability, provider-truth, sensor-truth, or physical-execution evidence.',
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
        description: `A machine-verifiable security case with ${proofStats.securityCase.claims} executable claims, ${proofStats.tamarin.verifiedObligations} verified Tamarin lemmas, and ${proofStats.conformance.vectors} conformance vectors.`,
        url: 'https://www.emiliaprotocol.ai/proof',
        dateModified: proofStats.generatedAt,
        author: { '@type': 'Organization', name: 'EMILIA Protocol' },
        publisher: { '@type': 'Organization', name: 'EMILIA Protocol' },
        about: ['AI agent authorization', 'AI agent qualification evidence', 'formal verification', 'security protocol conformance'],
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
            EMILIA is implemented security infrastructure. This snapshot joins an executable claim-to-code case, a composed symbolic attacker model, TLA+ and Alloy checking, selected same-team scenarios that exercise public runtime entry points and compare hand-authored projections, cross-language negative vectors, external Rust interoperability, and durable fault tests.
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
            {' · '}Source revision: {SOURCE_REVISION === 'main' ? 'local/main preview' : SOURCE_REVISION.slice(0, 12)}
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

        <section style={{ ...styles.sectionWide, paddingTop: 76, paddingBottom: 76 }}>
          <div style={{ maxWidth: 800 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>
              {GATE_QUALIFICATION.name} · evidence boundary
            </div>
            <h2 style={{ ...styles.h2, fontSize: 'clamp(26px, 3vw, 38px)', maxWidth: 760 }}>
              Evaluation evidence can qualify a candidate without authorizing an action.
            </h2>
            <p style={{ ...styles.body, fontSize: 16, maxWidth: 760 }}>
              The public experimental profile turns accepted evaluation evidence into a portable,
              time-bounded qualification for one exact measured candidate and assignment. At request
              time, the relying party rechecks current status, candidate measurement, assignment, and
              protected-request binding before Gate composes that evidence with AEB, AEC, and local policy.
            </p>
            <p style={{ fontFamily: font.mono, fontSize: 14, fontWeight: 600, color: color.gold, lineHeight: 1.65, margin: '22px 0 0' }}>
              {GATE_QUALIFICATION.boundaryLine}
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 230px), 1fr))', gap: 16, marginTop: 32 }}>
            {[
              ['Qualified', 'Accepted evidence matches the exact candidate, assignment, policy, validity window, and protected request.'],
              ['Authorized', 'The resource owner separately decides whether local policy permits the exact action with its required AEB and AEC evidence.'],
              ['Admitted and executed', 'Gate separately reserves resources, consumes one-time authority before provider entry, and records provider and effect evidence.'],
            ].map(([label, detail]) => (
              <div key={label} style={{ borderTop: `2px solid ${color.gold}`, padding: '18px 4px 0 0' }}>
                <h3 style={{ ...styles.h3, fontSize: 17, margin: 0 }}>{label}</h3>
                <p style={{ ...styles.body, fontSize: 14, color: color.t2, margin: '9px 0 0' }}>{detail}</p>
              </div>
            ))}
          </div>

          <p style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, lineHeight: 1.65, maxWidth: 820, margin: '26px 0 0' }}>
            {GATE_QUALIFICATION.disclaimer} Current evidence totals remain sourced from the generated
            repository snapshot dated <time dateTime={proofStats.generatedAt}>{proofStats.generatedAt}</time>;
            no separate qualification count is hand-maintained on this page.{' '}
            <a href={`${SOURCE_BLOB}/docs/protocol/gate-qualification-v2.md`} style={{ color: color.gold }}>
              Inspect the profile source.
            </a>
          </p>
        </section>

        <section
          id="reliance-risk-plane"
          style={{
            borderTop: `1px solid ${color.border}`,
            borderBottom: `1px solid ${color.border}`,
            background: '#1C1917',
            color: '#FAFAF9',
          }}
        >
          <div style={{ ...styles.sectionWide, paddingTop: 76, paddingBottom: 76 }}>
            <div style={{ ...styles.eyebrow, color: color.gold }}>SHIPPED CLAIM · GATE 0.20.0</div>
            <h2 style={{ ...styles.h2, color: '#FAFAF9', fontSize: 'clamp(26px, 3vw, 38px)', maxWidth: 820 }}>
              The Reliance Risk Plane has an executable claim, not an insurance claim.
            </h2>
            <p style={{ fontSize: 16, lineHeight: 1.72, color: 'rgba(250,250,249,0.72)', maxWidth: 820, marginTop: 18 }}>
              The generated security case traces the loss-schedule verifier, durable exposure
              custody, exact-action refusal, coverage reconciliation, receipt census, and
              loss-experience feed to implementation paths, positive and negative vectors, tests,
              assumptions, exclusions, and evidence hashes.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 240px), 1fr))', gap: 16, marginTop: 32 }}>
              {[
                ['Preventive path', 'Declared exposure is reserved before provider invocation, remains open through uncertain outcomes, and closes only through the configured independent reconciliation authority.'],
                ['Non-authorizing artifacts', 'A loss schedule, refusal statement, coverage attestation, receipt census, or loss feed cannot create authority for an action.'],
                ['Current implementation scope', 'The stateful risk plane and signed risk artifacts have TypeScript source and a packaged JavaScript runtime. No Python or Go implementation, production source connector, insurer adoption, or loss-data network is claimed.'],
              ].map(([label, detail]) => (
                <div key={label} style={{ borderTop: `2px solid ${color.gold}`, padding: '18px 4px 0 0' }}>
                  <h3 style={{ ...styles.h3, fontSize: 17, color: '#FAFAF9', margin: 0 }}>{label}</h3>
                  <p style={{ fontSize: 14, lineHeight: 1.65, color: 'rgba(250,250,249,0.68)', margin: '9px 0 0' }}>{detail}</p>
                </div>
              ))}
            </div>
            <p style={{ fontFamily: font.mono, fontSize: 11, lineHeight: 1.65, color: 'rgba(250,250,249,0.58)', maxWidth: 900, margin: '26px 0 0' }}>
              Coverage reconciliation proves only the supplied roots and conserving counts. Receipt
              census suppression is not differential privacy. Loss records are externally reported
              observations, not verified or adjudicated losses. A refusal is exact technical-action
              evidence, not a legal or adverse-benefit denial.
            </p>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 22 }}>
              <a href="/gate/consequence-coverage" style={{ fontFamily: font.mono, fontSize: 11, color: color.gold }}>
                Run the synthetic coverage lab &rarr;
              </a>
              <a href={`${SOURCE_BLOB}/security/claims.v1.json`} style={{ fontFamily: font.mono, fontSize: 11, color: color.gold }}>
                Open the exact claim manifest &rarr;
              </a>
              <a href={`${SOURCE_BLOB}/docs/architecture/RELIANCE-RISK-PLANE.md`} style={{ fontFamily: font.mono, fontSize: 11, color: 'rgba(250,250,249,0.72)' }}>
                Read the bounded architecture &rarr;
              </a>
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
              <p style={styles.body}>Every row below is a claim validated by the generated security case: references resolve, cited artifacts are hashed, and configured executable checks pass. Formal model scope is reported separately through a five-way taxonomy generated only after the evidence gates run. No category asserts that the full implementation is formally modeled.</p>
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
                  {proofStats.securityCase.claims}/{claimSource.claims.length}
                </div>
                <div
                  style={{
                    fontFamily: font.sans,
                    fontSize: 13,
                    lineHeight: 1.55,
                    color: 'rgba(250,250,249,0.7)',
                  }}
                >
                  Claims validated by the passing generated security case.
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
              “Bounded + selected runtime scenarios” does not mean a refinement proof. It identifies bounded same-team formal evidence paired with selected governed runtime scenarios under an explicit projection relation. The separate {proofStats.securityCase.claims}/{claimSource.claims.length} executable-evidence axis means references resolved, artifacts were hashed, and configured checks passed.
            </p>

            <div style={{ borderTop: `1px solid ${color.borderHover}` }}>
              {CLAIM_ROWS.map(({ claim, coverage }) => {
                const evidenceCount = claim.enforcement_path.length + claim.vectors.length + claim.tests.length;
                const badgeStyle = FORMAL_BADGE_STYLES[coverage];
                const evidenceFiles = Array.from(
                  new Set([
                    ...claim.enforcement_path.map((entry) => entry.file),
                    ...claim.tests.map((entry) => entry.file),
                    ...claim.vectors.map((entry) => entry.suite),
                  ]),
                );
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
                          Executable evidence · validated · {evidenceCount} cited evidence references
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
                          Formal coverage · {FORMAL_LABELS[coverage]}
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
                    <details
                      style={{
                        marginTop: 14,
                        borderTop: `1px solid ${color.border}`,
                        paddingTop: 12,
                      }}
                    >
                      <summary
                        style={{
                          fontFamily: font.mono,
                          fontSize: 10,
                          color: color.t2,
                          cursor: 'pointer',
                          textTransform: 'uppercase',
                          letterSpacing: 0.8,
                        }}
                      >
                        Acceptance roots, assumptions, exclusions, and exact evidence
                      </summary>
                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 230px), 1fr))',
                          gap: 24,
                          marginTop: 18,
                        }}
                      >
                        {[
                          ['Acceptance roots', claim.acceptance_roots],
                          ['Assumptions', claim.assumptions],
                          ['Exclusions', claim.exclusions],
                        ].map(([label, items]) => (
                          <div key={label as string}>
                            <div
                              style={{
                                fontFamily: font.mono,
                                fontSize: 9,
                                color: color.gold,
                                textTransform: 'uppercase',
                                letterSpacing: 0.8,
                                marginBottom: 8,
                              }}
                            >
                              {label}
                            </div>
                            <ul style={{ margin: 0, paddingLeft: 18, color: color.t2 }}>
                              {(items as string[]).map((item) => (
                                <li key={item} style={{ fontSize: 12, lineHeight: 1.55, marginBottom: 5 }}>
                                  {item}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ))}
                      </div>
                      <div
                        style={{
                          display: 'flex',
                          flexWrap: 'wrap',
                          gap: '8px 14px',
                          marginTop: 18,
                        }}
                      >
                        <a
                          href={`${SOURCE_BLOB}/security/claims.v1.json`}
                          style={{ fontFamily: font.mono, fontSize: 10, color: color.gold }}
                        >
                          Exact claim manifest
                        </a>
                        {evidenceFiles.map((file) => (
                          <a
                            key={file}
                            href={`${SOURCE_BLOB}/${file}`}
                            style={{ fontFamily: font.mono, fontSize: 10, color: color.t2 }}
                          >
                            {file}
                          </a>
                        ))}
                      </div>
                    </details>
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
curl -fsSLo /tmp/tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
echo "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88  /tmp/tla2tools.jar" | shasum -a 256 -c -
TLA2TOOLS_JAR=/tmp/tla2tools.jar npm run check:formal-traces
npm run conformance:aeb-1
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
                <Link href="/conformance" className="ep-cta-secondary" style={cta.secondary}>
                  AEB-1 consequence admission
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
