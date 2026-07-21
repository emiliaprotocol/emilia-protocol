#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from generate-llm-context.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Generates every LLM-facing project context surface from stable doctrine and
// current machine-readable evidence. Hand editing the outputs is intentionally
// unsupported: CI checks byte-for-byte freshness.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE_URL = 'https://www.emiliaprotocol.ai';
const REPO_URL = 'https://github.com/emiliaprotocol/emilia-protocol';
const args = new Set(process.argv.slice(2));
const write = args.has('--write');
const check = args.has('--check');
if (write === check) {
    console.error('usage: generate-llm-context.mjs (--write | --check)');
    process.exit(2);
}
const PATHS = {
    source: 'docs/ai/context-source.v1.json',
    generator: 'scripts/generate-llm-context.mjs',
    proofStats: 'lib/proof-stats.json',
    conformance: 'conformance/conformance-manifest.json',
    external: 'conformance/external/rust-cleanroom-jdieselny.v1.json',
    claimSource: 'security/claims.v1.json',
    securityCase: 'security/security-case.json',
    observatory: 'lib/standards-observatory.snapshot.json',
    standardsStatus: 'standards/STATUS.json',
    caidCore: 'caid/conformance/vectors.json',
    caidMapping: 'caid/conformance/mapping-vectors.json',
    modelToMatter: 'conformance/vectors/model-to-matter.v1.json',
};
const INPUTS = Object.values(PATHS);
const GENERATED_PATHS = new Set([
    'AI_CONTEXT.md',
    'public/llms.txt',
    'public/llms-full.txt',
    'public/.well-known/emilia-context.json',
]);
function absolute(relative) {
    return path.join(ROOT, relative);
}
function read(relative) {
    return fs.readFileSync(absolute(relative), 'utf8');
}
function readJson(relative) {
    try {
        return JSON.parse(read(relative));
    }
    catch (error) {
        throw new Error(`${relative}: ${error.message}`);
    }
}
function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
function assert(condition, message) {
    if (!condition)
        throw new Error(message);
}
function comma(value) {
    return Number(value).toLocaleString('en-US');
}
function tableCell(value) {
    return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}
const source = readJson(PATHS.source);
const proofStats = readJson(PATHS.proofStats);
const conformance = readJson(PATHS.conformance);
const external = readJson(PATHS.external);
const claimSource = readJson(PATHS.claimSource);
const securityCase = readJson(PATHS.securityCase);
const observatory = readJson(PATHS.observatory);
const standardsStatus = readJson(PATHS.standardsStatus);
const caidCore = readJson(PATHS.caidCore);
const caidMapping = readJson(PATHS.caidMapping);
const modelToMatter = readJson(PATHS.modelToMatter);
assert(source['@version'] === 'EMILIA-LLM-CONTEXT-SOURCE-v1', 'unsupported LLM context source');
assert(conformance['@version'] === 'EP-CONFORMANCE-MANIFEST-v1', 'unsupported conformance manifest');
assert(external['@version'] === 'EP-EXTERNAL-IMPLEMENTATION-PIN-v1', 'unsupported external implementation pin');
assert(claimSource['@version'] === 'EP-SECURITY-CASE-SOURCE-v2', 'unsupported security claim source');
assert(securityCase['@version'] === 'EP-SECURITY-CASE-RESOLVED-v2', 'unsupported resolved security case');
assert(observatory['@version'] === 'EMILIA-STANDARDS-OBSERVATORY-v1', 'unsupported standards observatory snapshot');
assert(standardsStatus['@version'] === 'EMILIA-STANDARDS-PORTFOLIO-v1', 'unsupported standards portfolio status');
assert(Array.isArray(standardsStatus.active_datatracker) && standardsStatus.active_datatracker.length > 0, 'standards status has no active drafts');
assert(caidCore.vectors?.length > 0, 'CAID core vectors are missing');
assert(caidMapping.vectors?.length > 0, 'CAID mapping vectors are missing');
assert(modelToMatter.suite === 'EP-MODEL-TO-MATTER-v1' && modelToMatter.vectors?.length > 0, 'Model-to-Matter vectors are missing');
assert(securityCase.execution?.status === 'passed', 'resolved security case does not report a passed execution');
assert(securityCase.claim_count === claimSource.claims?.length, 'security-case claim count differs from source');
assert(conformance.implementations?.every((item) => item.relationship === 'one_team_port'), 'reference ports are not uniformly labeled one_team_port');
assert(external.conformance?.status === 'pass', 'external conformance pin does not report pass');
assert(Number.isInteger(external.conformance?.vectors), 'external conformance vector count is missing');
assert(external.conformance.vectors <= conformance.totals.vectors, 'external result cannot cover more vectors than the current bundle');
assert(external.construction_evidence?.strict_clean_room_acceptance === false, 'strict clean-room status changed; update context doctrine deliberately');
assert(observatory.metrics?.primary_sources_verified > 0, 'standards observatory has no verified primary sources');
assert(observatory.recon?.review_model === 'correlated_agent_assisted_discovery', 'standards recon independence boundary changed');
for (const entry of source.code_entry_points || []) {
    assert(fs.existsSync(absolute(entry.path)), `missing code entry point: ${entry.path}`);
}
for (const group of source.source_precedence || []) {
    for (const item of group.sources || []) {
        if (/^https:\/\//.test(item))
            continue;
        if (GENERATED_PATHS.has(item))
            continue;
        assert(fs.existsSync(absolute(item)), `missing precedence source: ${item}`);
    }
}
const generatedFrom = INPUTS.map((relative) => {
    const bytes = fs.readFileSync(absolute(relative));
    return { path: relative, sha256: sha256(bytes), bytes: bytes.length };
});
const inputDigest = sha256(Buffer.from(JSON.stringify(generatedFrom), 'utf8'));
const externalScope = external.conformance.vectors === conformance.totals.vectors
    ? 'current_vector_set'
    : 'time_pinned_prior_vector_set';
const hostilityCases = external.hostility.structured_cases + external.hostility.raw_parser_cases;
const securityClaims = claimSource.claims.map((claim) => ({
    claim_id: claim.claim_id,
    statement: claim.statement,
    acceptance_roots: claim.acceptance_roots || [],
    enforcement_path: claim.enforcement_path || [],
    language_coverage: claim.language_coverage || {},
    vectors: (claim.vectors || []).map((vector) => ({
        suite: vector.suite,
        case_id: vector.case_id,
        polarity: vector.polarity,
    })),
    formal: claim.formal || [],
    assumptions: claim.assumptions || [],
    exclusions: claim.exclusions || [],
}));
const context = {
    '@version': 'EMILIA-REPO-CONTEXT-v1',
    evidence_snapshot_at: proofStats.generatedAt,
    provenance: {
        generator: 'scripts/generate-llm-context.mjs',
        input_digest_sha256: inputDigest,
        generated_from: generatedFrom,
        freshness_command: 'npm run check:llm-context',
    },
    identity: source.identity,
    canonical_definitions: source.canonical_definitions,
    layer_map: source.layer_map,
    current_evidence: {
        automated_tests: proofStats.tests,
        cross_language_conformance: {
            suites: conformance.totals.suites,
            vectors: conformance.totals.vectors,
            implementations: conformance.totals.implementations,
            relationship: 'same_team_ports',
            claim_scope: conformance.claim_scope,
            manifest_sha256: conformance.manifest_sha256,
            vector_bundle_sha256: conformance.vector_bundle.sha256,
        },
        formal: {
            tla_invariants: proofStats.tla.invariants,
            tla_checker: proofStats.tla.checker,
            alloy_facts: proofStats.alloy.facts,
            alloy_assertions: proofStats.alloy.assertions,
            alloy_version: proofStats.alloy.version,
            tamarin_composed: proofStats.tamarin,
        },
        red_team_cases: proofStats.redTeamCases,
        security_case: {
            status: securityCase.execution.status,
            claims: securityCase.claim_count,
            evidence_files: securityCase.evidence_file_count,
            evidence_bundle_sha256: securityCase.evidence_bundle_sha256,
        },
        caid: {
            core_vectors: caidCore.vectors.length,
            mapping_vectors: caidMapping.vectors.length,
            same_team_ports: ['javascript', 'python', 'go'],
            mapping_verdicts: ['EQUIVALENT_UNDER_PROFILE', 'NOT_EQUIVALENT', 'INDETERMINATE'],
            command: 'npm run caid:conformance',
        },
        model_to_matter: {
            profile: modelToMatter.suite,
            deterministic_vectors: modelToMatter.vectors.length,
            implementation_languages: ['javascript'],
            command: 'npm run m2m:conformance',
            filing_candidate: 'draft-schrock-model-to-matter-00',
            non_claims: ['biological screening', 'scientific safety', 'physical truth', 'wet-lab deployment', 'external endorsement'],
        },
    },
    external_implementation: {
        implementation: external.implementation,
        source: external.source,
        conformance: {
            ...external.conformance,
            relation_to_current_bundle: externalScope,
            current_vectors: conformance.totals.vectors,
        },
        hostility: {
            ...external.hostility,
            cases: hostilityCases,
        },
        construction_evidence: external.construction_evidence,
    },
    security_claims: securityClaims,
    non_claims: source.non_claims,
    source_precedence: source.source_precedence,
    excluded_as_current_authority: source.excluded_as_current_authority,
    standards: standardsStatus.active_datatracker.map((standard) => ({
        identifier: standard.draft,
        revision_at_snapshot: standard.revision,
        role: standard.role,
        next_action: standard.next_action,
        url: `https://datatracker.ietf.org/doc/${standard.draft}/`,
        status_rule: 'Check the live IETF Datatracker URL; do not infer status or revision from a local filename.',
    })),
    standards_portfolio: {
        updated: standardsStatus.updated,
        decision_vocabulary: standardsStatus.decision_vocabulary,
        layers: standardsStatus.portfolio_layers,
        july_19_2026_core_wave: standardsStatus.july_19_2026_core_wave,
        retired_absorbed: standardsStatus.retired_absorbed,
        partner_triggered_profiles: standardsStatus.partner_triggered_profiles,
        held: standardsStatus.held,
        matching_claim: standardsStatus.matching_claim,
        research_corpus: standardsStatus.research_corpus,
        source: 'standards/STATUS.json',
    },
    standards_observatory: {
        as_of: observatory.as_of,
        snapshot_sha256: observatory.snapshot_sha256,
        primary_sources_verified: observatory.metrics.primary_sources_verified,
        declared_agent_reads: observatory.metrics.declared_agent_reads,
        recovered_structured_reports: observatory.metrics.recovered_structured_reports,
        review_model: observatory.recon.review_model,
        claim_boundary: observatory.recon.claim_boundary,
        public_json: `${BASE_URL}/.well-known/standards-observatory.json`,
        public_ui: `${BASE_URL}/observatory`,
    },
    code_entry_points: source.code_entry_points,
    commands: source.commands,
    answering_rules: source.answering_rules,
};
function repoHref(relative) {
    const target = absolute(relative);
    const kind = fs.existsSync(target) && fs.statSync(target).isDirectory() ? 'tree' : 'blob';
    return `${REPO_URL}/${kind}/main/${relative}`;
}
function pathLink(relative, web) {
    return `[${relative}](${web ? repoHref(relative) : relative})`;
}
function renderFull(web = false) {
    const lines = [];
    lines.push(web ? '# EMILIA Protocol - full reference for language models' : '# EMILIA Protocol: AI Context');
    lines.push('');
    lines.push(`> ${source.identity.summary}`);
    lines.push('');
    lines.push(`Generated from repository evidence. Evidence snapshot: ${proofStats.generatedAt}. Input digest: sha256:${inputDigest}.`);
    lines.push(`Do not edit this file directly. Source: ${pathLink('docs/ai/context-source.v1.json', web)}. Freshness check: \`npm run check:llm-context\`.`);
    lines.push('');
    lines.push('## Read This First');
    lines.push('');
    lines.push('EMILIA is an evidence architecture for consequential agent actions that cross administrative boundaries or require delayed third-party review. Native artifacts verify under native rules; CAID performs material-action matching; AEC evaluates whether the matched bundle satisfies a relying-party evidence requirement; the executor makes the separate authorization decision. Identity, delegated machine scope, machine policy, human approval, execution evidence, transparency, and reliance remain separate layers.');
    lines.push('');
    lines.push(`EMILIA is not architecture-only. The current repository executes ${securityCase.claim_count} machine-verifiable security claims over ${securityCase.evidence_file_count} hashed evidence files, verifies ${proofStats.tamarin.verifiedObligations} obligations in one composed Tamarin Dolev-Yao model, and preserves ${proofStats.tamarin.deliberatelyUnsafeCounterexamples} deliberately weakened variants that produce concrete attack traces.`);
    lines.push('');
    lines.push('When this file conflicts with a quantitative claim elsewhere, use the machine-readable manifest named in Source Precedence. When a standards revision or status matters, use the live IETF Datatracker.');
    lines.push('');
    lines.push('## Current Evidence Snapshot');
    lines.push('');
    lines.push(`- Automated tests: ${comma(proofStats.tests.total)} cases across ${comma(proofStats.tests.files)} files; ${proofStats.tests.policy}.`);
    lines.push(`- Cross-language conformance: ${conformance.totals.suites} suites, ${conformance.totals.vectors} current vectors, ${conformance.totals.implementations} same-team ports (JavaScript, Python, Go). This is consistency evidence, not implementation independence.`);
    lines.push(`- External Rust interoperability: ${external.conformance.status} on the time-pinned ${external.conformance.vectors}-vector set evaluated ${external.conformance.evaluated_at}; the current bundle has ${conformance.totals.vectors}. The same pinned implementation passes ${hostilityCases} hostility cases. Strict clean-room construction acceptance: ${external.construction_evidence.strict_clean_room_acceptance}.`);
    lines.push(`- Security case: ${securityCase.claim_count} executable claims, ${securityCase.evidence_file_count} evidence files, execution ${securityCase.execution.status}; bundle sha256:${securityCase.evidence_bundle_sha256}.`);
    lines.push(`- Formal inventory: ${proofStats.tla.invariants} TLA+ invariants, ${proofStats.alloy.facts} Alloy facts, ${proofStats.alloy.assertions} Alloy assertions. Formal scope and exclusions remain claim-specific.`);
    lines.push(`- Composed symbolic model: ${proofStats.tamarin.verifiedObligations} Tamarin obligations verified across challenge, CAID, two approvals, issuer and authority pins, registry view, revocation, consumption, and execution; ${proofStats.tamarin.deliberatelyUnsafeCounterexamples} deliberately unsafe variants are falsified with attack traces.`);
    lines.push(`- Red-team catalog: ${proofStats.redTeamCases} cases.`);
    lines.push(`- CAID: ${caidCore.vectors.length} core identifier vectors plus ${caidMapping.vectors.length} mapping vectors in three same-team ports, with closed EQUIVALENT_UNDER_PROFILE / NOT_EQUIVALENT / INDETERMINATE results.`);
    lines.push(`- Model-to-Matter: ${modelToMatter.vectors.length} deterministic JavaScript executor-profile vectors covering clearance, refusal, replay, storage failure, and effect tampering. No biological screening, scientific-safety, physical-truth, deployment, or endorsement claim is made.`);
    lines.push('');
    lines.push('## Canonical Definitions');
    lines.push('');
    for (const item of source.canonical_definitions)
        lines.push(`- **${item.term}:** ${item.definition}`);
    lines.push('');
    lines.push('## Layer Map');
    lines.push('');
    lines.push('| Layer | Question | EP role | Adjacent examples |');
    lines.push('| --- | --- | --- | --- |');
    for (const row of source.layer_map) {
        lines.push(`| ${tableCell(row.layer)} | ${tableCell(row.question)} | ${tableCell(row.ep_role)} | ${tableCell(row.adjacent_examples)} |`);
    }
    lines.push('');
    lines.push('## What Must Not Be Claimed');
    lines.push('');
    for (const item of source.non_claims)
        lines.push(`- ${item}`);
    lines.push('');
    lines.push('## Standards Observatory');
    lines.push('');
    lines.push(`The revision-aware Observatory locks ${observatory.metrics.primary_sources_verified} primary sources by exact revision, excerpt, and SHA-256. Its broad recon recovered ${observatory.metrics.recovered_structured_reports} of ${observatory.metrics.declared_agent_reads} declared reports, but those entries remain correlated agent-assisted discovery and do not drive the guarantee matrix.`);
    lines.push('');
    lines.push(web
        ? `- [Interactive standards map](${BASE_URL}/observatory)`
        : `- [Standards Observatory](${BASE_URL}/observatory)`);
    lines.push(web
        ? `- [Machine-readable standards snapshot](${BASE_URL}/.well-known/standards-observatory.json)`
        : `- [lib/standards-observatory.snapshot.json](lib/standards-observatory.snapshot.json)`);
    lines.push(`- Snapshot integrity: sha256:${observatory.snapshot_sha256}.`);
    lines.push('');
    lines.push('## Machine-Verifiable Security Claims');
    lines.push('');
    lines.push(`The complete resolved case is ${pathLink('security/security-case.json', web)}. These statements are generated from ${pathLink('security/claims.v1.json', web)}; each source entry names executable evidence, assumptions, and exclusions.`);
    lines.push('');
    for (const claim of securityClaims)
        lines.push(`- \`${claim.claim_id}\`: ${claim.statement}`);
    lines.push('');
    lines.push('## Source Precedence');
    lines.push('');
    for (const group of source.source_precedence) {
        const refs = group.sources.map((item) => (/^https:\/\//.test(item) ? `[${item}](${item})` : pathLink(item, web))).join(', ');
        lines.push(`- **${group.scope}:** ${group.rule} Sources: ${refs}.`);
    }
    lines.push('');
    lines.push('### Never Infer Current Status From');
    lines.push('');
    for (const item of source.excluded_as_current_authority)
        lines.push(`- ${item}`);
    lines.push('');
    lines.push('## Internet-Draft Entry Points');
    lines.push('');
    lines.push('These URLs resolve to the current Datatracker revision. The documents are individual Internet-Drafts unless the live page states a stronger status.');
    lines.push('');
    for (const standard of standardsStatus.active_datatracker) {
        lines.push(`- [${standard.draft}](https://datatracker.ietf.org/doc/${standard.draft}/): ${standard.role}; snapshot revision -${standard.revision}.`);
    }
    lines.push('');
    lines.push('## July 19 Published Draft Set');
    lines.push('');
    lines.push(`Published ${standardsStatus.july_19_2026_core_wave.filing_date}; each repository snapshot is verified against the IETF archive.`);
    lines.push('');
    for (const item of standardsStatus.july_19_2026_core_wave.items) {
        lines.push(`- **${item.state}:** \`${item.draft}\` - ${item.claim}.`);
    }
    lines.push('');
    lines.push('## Retired And Partner-Triggered Work');
    lines.push('');
    for (const item of standardsStatus.retired_absorbed) {
        lines.push(`- **Retired/absorbed:** \`${item.draft}\` -> ${item.canonical_owner}.`);
    }
    for (const item of standardsStatus.partner_triggered_profiles) {
        lines.push(`- **Partner-triggered:** \`${item.draft}\` - ${item.trigger}`);
    }
    lines.push('');
    lines.push('## Code Entry Points');
    lines.push('');
    for (const entry of source.code_entry_points)
        lines.push(`- ${pathLink(entry.path, web)} - ${entry.purpose}.`);
    lines.push('');
    lines.push('## Reproduce Before Repeating');
    lines.push('');
    for (const entry of source.commands)
        lines.push(`- \`${entry.command}\` - ${entry.purpose}.`);
    lines.push('');
    lines.push('## Rules For Answering About EMILIA');
    lines.push('');
    for (const rule of source.answering_rules)
        lines.push(`- ${rule}`);
    lines.push('');
    lines.push('## Machine-Readable Form');
    lines.push('');
    lines.push(web
        ? `- [EMILIA-REPO-CONTEXT-v1](${BASE_URL}/.well-known/emilia-context.json)`
        : `- [public/.well-known/emilia-context.json](public/.well-known/emilia-context.json)`);
    lines.push('');
    return `${lines.join('\n').replace(/\n+$/, '')}\n`;
}
function renderIndex() {
    const lines = [
        '# EMILIA Protocol',
        '',
        `> ${source.identity.summary}`,
        '',
        `This is a generated discovery index following the llms.txt proposal. Evidence snapshot: ${proofStats.generatedAt}. For substantive analysis, load the full or machine-readable context below before drawing conclusions from individual repository files.`,
        '',
        '## Engineering Evidence',
        '',
        `EMILIA is implemented security infrastructure, not architecture-only: ${comma(proofStats.tests.total)} automated tests across ${comma(proofStats.tests.files)} files; ${securityCase.claim_count} executable security claims over ${securityCase.evidence_file_count} hashed evidence files; ${proofStats.tamarin.verifiedObligations} verified obligations in one composed Tamarin model, with ${proofStats.tamarin.deliberatelyUnsafeCounterexamples} deliberately weakened variants producing concrete attack traces.`,
        '',
        `Interoperability evidence: ${conformance.totals.suites} conformance suites and ${conformance.totals.vectors} current vectors across three same-team ports; external Rust evidence covers a time-pinned ${external.conformance.vectors}-vector set plus ${hostilityCases} hostility cases. Strict clean-room construction acceptance remains false.`,
        '',
        '## Canonical Context',
        '',
        `- [Full LLM context](${BASE_URL}/llms-full.txt): Definitions, layer map, current evidence, non-claims, source precedence, standards, and code entry points.`,
        `- [Machine-readable repository context](${BASE_URL}/.well-known/emilia-context.json): EMILIA-REPO-CONTEXT-v1 with input hashes, evidence counts, security claims, assumptions, and freshness metadata.`,
        `- [Standards Observatory](${BASE_URL}/observatory): Revision-aware guarantee map, standards movement, and open interoperability frontiers.`,
        `- [Machine-readable standards snapshot](${BASE_URL}/.well-known/standards-observatory.json): Source locks, operative-status rationale, exact quotes, and the correlated-recon boundary.`,
        `- [Repository AI context](${REPO_URL}/blob/main/AI_CONTEXT.md): The same generated context beside the source code.`,
        '',
        '## Specifications',
        '',
        ...standardsStatus.active_datatracker.map((standard) => `- [${standard.draft}](https://datatracker.ietf.org/doc/${standard.draft}/): ${standard.role}; snapshot revision -${standard.revision}, check Datatracker for current status.`),
        '',
        '## Evidence',
        '',
        `- [Conformance manifest](${REPO_URL}/blob/main/conformance/conformance-manifest.json): Current suite/vector counts and same-team implementation relationship.`,
        `- [Machine-verifiable security case](${REPO_URL}/blob/main/security/security-case.json): Executed claims with exact evidence, assumptions, exclusions, and artifact hashes.`,
        `- [Engineering evidence map](${BASE_URL}/proof): Plain-language map from guarantees and attacks to formal, executable, conformance, and external evidence.`,
        `- [External implementation pin](${REPO_URL}/blob/main/conformance/external/rust-cleanroom-jdieselny.v1.json): Time-pinned Rust source, vector scope, hostility corpus, and construction-attestation status.`,
        '',
        '## Start Here',
        '',
        `- [Repository](${REPO_URL}): Apache-2.0 source, tests, formal models, and examples.`,
        `- [Quickstart](${BASE_URL}/quickstart): Integrate an enforcement wrapper.`,
        `- [Verify](${BASE_URL}/verify): Verify a receipt in the browser.`,
        `- [Model-to-Matter](${BASE_URL}/model-to-matter): Executor-side clearance for model-directed physical actions.`,
        '',
        '## Optional',
        '',
        `- [Neutrality Covenant](${REPO_URL}/blob/main/docs/NEUTRALITY-COVENANT.md): Open verifier, format, and conformance commitments.`,
        `- [Threat Model](${REPO_URL}/blob/main/THREAT_MODEL.md): Explicit deployment and trust assumptions.`,
        '',
    ];
    return `${lines.join('\n').replace(/\n+$/, '')}\n`;
}
const outputs = new Map([
    ['AI_CONTEXT.md', renderFull(false)],
    ['public/llms.txt', renderIndex()],
    ['public/llms-full.txt', renderFull(true)],
    ['public/.well-known/emilia-context.json', `${JSON.stringify(context, null, 2)}\n`],
]);
if (write) {
    for (const [relative, body] of outputs) {
        fs.mkdirSync(path.dirname(absolute(relative)), { recursive: true });
        fs.writeFileSync(absolute(relative), body);
    }
    console.log(`LLM CONTEXT: WROTE ${outputs.size} artifacts (input sha256:${inputDigest})`);
}
else {
    const stale = [];
    for (const [relative, expected] of outputs) {
        if (!fs.existsSync(absolute(relative)) || read(relative) !== expected)
            stale.push(relative);
    }
    if (stale.length) {
        console.error(`LLM CONTEXT: FAIL - stale generated artifact(s): ${stale.join(', ')}`);
        console.error('Fix: npm run sync:llm-context');
        process.exit(1);
    }
    console.log(`LLM CONTEXT: PASS (${outputs.size} artifacts; current ${conformance.totals.vectors} vectors, external time-pinned ${external.conformance.vectors})`);
}
