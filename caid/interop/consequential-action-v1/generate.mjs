#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { targets } from './targets.mjs';

const HERE = new URL('./', import.meta.url);
const MATERIAL = ['operation', 'target_ref', 'parameters_digest'];
const PATH_KEY = {
  operation: 'operation',
  target_ref: 'target',
  parameters_digest: 'parameters',
};
const DEFAULT_TRANSFORM = {
  operation: 'copy',
  target_ref: 'sha256-utf8',
  parameters_digest: 'sha256-jcs',
};
const REFERENCE = {
  operation: 'medical.coverage.determine',
  target: 'urn:claim:example:2026:00042',
  parameters: {
    requested_service: 'J3490',
    amount: '1280.00',
    currency: 'USD',
  },
};

function stableJson(value) {
  return JSON.stringify(value, null, 2) + '\n';
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function nativeVerdict(target) {
  return target.native_binding === 'COMPLETE'
    && (target.omitted_source_fields?.length ?? 0) === 0
    ? 'EQUIVALENT_UNDER_PROFILE'
    : 'INDETERMINATE';
}

function projectionLoss(target) {
  const omittedSourceFields = structuredClone(target.omitted_source_fields ?? []);
  return {
    status: omittedSourceFields.length === 0 ? 'NONE' : 'DECLARED_SOURCE_SEMANTIC_LOSS',
    omitted_source_fields: omittedSourceFields,
  };
}

function slug(target) {
  return `${target.draft.replace(/^draft-/, '')}-${target.revision}`;
}

function setPointer(root, pointer, value) {
  const segments = pointer.slice(1).split('/');
  let current = root;
  for (const segment of segments.slice(0, -1)) {
    current[segment] ??= {};
    current = current[segment];
  }
  current[segments.at(-1)] = structuredClone(value);
}

function sourceFormat(target, kind) {
  return {
    media_type: 'application/json',
    schema: `urn:caid:interop:${target.draft}:${target.revision}:${kind}`,
    version: target.revision,
  };
}

function bindingsFor(target) {
  const missing = new Set(target.missing_material_fields);
  if (missing.size !== target.missing_material_fields.length
      || [...missing].some((field) => !MATERIAL.includes(field))) {
    throw new Error(`${slug(target)}: invalid missing_material_fields`);
  }

  return Object.fromEntries(MATERIAL.map((field) => {
    const path = target.paths[PATH_KEY[field]];
    if (missing.has(field)) {
      if (path !== null) {
        throw new Error(`${slug(target)}: unavailable ${field} must use a null source path`);
      }
      return [field, {
        status: 'UNAVAILABLE',
        source_path: null,
        path_kind: 'ABSENT_OR_NOT_PROFILE_INDEPENDENT',
        transform: null,
        reason: target.missing_reasons?.[field]
          ?? 'The pinned source does not expose a profile-independent value for this material field.',
      }];
    }
    if (typeof path !== 'string' || !path.startsWith('/')) {
      throw new Error(`${slug(target)}: mapped ${field} requires a JSON Pointer source path`);
    }
    return [field, {
      status: 'MAPPED',
      source_path: path,
      path_kind: target.path_kinds?.[field] ?? target.path_kind ?? 'ABSTRACT_MODEL_PATH',
      transform: target.transforms?.[field] ?? DEFAULT_TRANSFORM[field],
    }];
  }));
}

function probePath(field) {
  return `/__caid_unavailable__/${field}`;
}

function rulesForBindings(bindings) {
  return MATERIAL.map((field) => ({
    source_path: bindings[field].status === 'MAPPED'
      ? bindings[field].source_path
      : probePath(field),
    target_field: field,
    transform: bindings[field].status === 'MAPPED'
      ? bindings[field].transform
      : DEFAULT_TRANSFORM[field],
  }));
}

function profile(target, kind) {
  const isCarry = kind === 'carry';
  const omittedSourceFields = isCarry
    ? []
    : structuredClone(target.omitted_source_fields ?? []);
  const bindings = isCarry
    ? {
        operation: { status: 'MAPPED', source_path: '/caid_action/operation', transform: 'copy' },
        target_ref: { status: 'MAPPED', source_path: '/caid_action/target', transform: 'sha256-utf8' },
        parameters_digest: { status: 'MAPPED', source_path: '/caid_action/parameters', transform: 'sha256-jcs' },
      }
    : bindingsFor(target);
  const rules = rulesForBindings(bindings);
  return {
    '@version': 'CAID-MAPPING-PROFILE-v1',
    profile_id: `urn:caid:interop:${slug(target)}:${kind}:${isCarry ? 1 : 2}`,
    source_format: sourceFormat(target, kind),
    target_action_type: 'consequence.invoke.1',
    loss_policy: omittedSourceFields.length === 0
      ? 'no-material-field-loss'
      : 'declared-source-semantic-loss',
    omitted_source_fields: omittedSourceFields,
    material_source_paths: rules.map(({ source_path }) => source_path),
    rules,
  };
}

function referenceProfile() {
  const bindings = {
    operation: { status: 'MAPPED', source_path: '/operation', transform: 'copy' },
    target_ref: { status: 'MAPPED', source_path: '/target', transform: 'sha256-utf8' },
    parameters_digest: { status: 'MAPPED', source_path: '/parameters', transform: 'sha256-jcs' },
  };
  const rules = rulesForBindings(bindings);
  return {
    '@version': 'CAID-MAPPING-PROFILE-v1',
    profile_id: 'urn:caid:interop:reference-consequence:1',
    source_format: {
      media_type: 'application/json',
      schema: 'urn:caid:interop:reference-consequence:1',
      version: '1',
    },
    target_action_type: 'consequence.invoke.1',
    loss_policy: 'no-material-field-loss',
    omitted_source_fields: [],
    material_source_paths: rules.map(({ source_path }) => source_path),
    rules,
  };
}

function nativeSource(target) {
  const source = { draft: target.draft, revision: target.revision };
  const bindings = bindingsFor(target);
  for (const [pointer, value] of Object.entries(target.native_fixture_fields ?? {})) {
    setPointer(source, pointer, value);
  }
  const sourceValue = {
    operation: () => REFERENCE.operation,
    target_ref: (transform) => transform === 'copy'
      ? sha256(REFERENCE.target)
      : REFERENCE.target,
    parameters_digest: (transform) => {
      const digest = sha256(canonicalJson(REFERENCE.parameters));
      if (transform === 'copy') return digest;
      if (transform === 'sha256-hex-to-digest') return digest.slice('sha256:'.length);
      return REFERENCE.parameters;
    },
  };
  for (const [field, binding] of Object.entries(bindings)) {
    if (binding.status === 'MAPPED') {
      setPointer(source, binding.source_path, sourceValue[field](binding.transform));
    }
  }
  return source;
}

function carrySource(target) {
  return {
    draft: target.draft,
    revision: target.revision,
    caid_action: structuredClone(REFERENCE),
  };
}

function buildManifest() {
  return {
    '@version': 'CAID-CONSEQUENTIAL-ACTION-INTEROP-v2',
    title: 'Consequential Action Interoperability Project — 25 Source-Audited Candidate Mappings',
    frozen_at: '2026-07-28',
    status: 'SOURCE_AUDITED_CANDIDATE_MAPPINGS_PENDING_AUTHOR_REVIEW',
    claim_boundary: [
      'A mapping result is content correlation under a pinned profile; it is not authorization.',
      'INDETERMINATE is an expected fail-closed result when a mechanism does not expose every material action field.',
      'The optional carry profile is a proposed composition path, not a claim that the source draft defines or endorses CAID.',
      'Authorization audience and trust context remain outside this action identifier; target identifies where the material action occurs.',
      'No author participation, validation, implementation, adoption, or endorsement is claimed.',
      'A null source path means the field is absent or is not usable profile-independently; executable refusal probes use reserved /__caid_unavailable__/* sentinels that are not source-draft fields.',
    ],
    selection_policy: {
      target_count: 25,
      criteria: 'Consequential-action relevance, protocol diversity, and a reviewable action or evidence boundary.',
      excluded_contacts: 'Authors excluded by project-owner direction are enforced by tests and are not named in this public artifact.',
      mandatory_target: 'draft-dunbar-dmsc-gw-scenarios-gap-analysis-02',
    },
    local_action_definition: actionDefinition(),
    mappings: targets.map((target) => ({
      mapping_id: slug(target),
      draft: target.draft,
      revision: target.revision,
      title: target.title,
      datatracker_url: `https://datatracker.ietf.org/doc/${target.draft}/`,
      source_txt_url: `https://www.ietf.org/archive/id/${target.draft}-${target.revision}.txt`,
      source_sha256: target.source_sha256,
      source_kind: 'human-reviewed extraction fixture; not a native parser or implementation',
      native_binding: target.native_binding,
      native_verdict: nativeVerdict(target),
      missing_material_fields: target.missing_material_fields,
      projection_loss: projectionLoss(target),
      field_bindings: bindingsFor(target),
      excluded_native_candidates: target.excluded_native_candidates ?? [],
      evidence: [{ locator: target.evidence[0], finding: target.evidence[1] }],
      ...(target.native_profile_role
        ? { native_profile_role: target.native_profile_role }
        : { native_profile_role: 'Executable fail-closed probe. Reserved /__caid_unavailable__/* paths represent unavailable fields and are not claimed source fields.' }),
      native_profile: profile(target, 'native'),
      carry_profile: profile(target, 'carry'),
      author_review: target.author_review
        ? {
            ...target.author_review,
            endorsement_claimed: false,
            request: target.request,
          }
        : {
            status: 'PENDING_AUTHOR_REVIEW',
            endorsement_claimed: false,
            request: target.request,
          },
    })),
  };
}

function actionDefinition() {
  return {
    action_type: 'consequence.invoke.1',
    status: 'local-experimental',
    risk_class: 'consequential',
    summary: 'A profile-bounded consequential action used only by this interoperability project.',
    required_fields: [
      { name: 'operation', type: 'string' },
      { name: 'target_ref', type: 'digest' },
      { name: 'parameters_digest', type: 'digest' },
    ],
    optional_fields: [],
    digest_notes: 'Operation, target, and complete material parameters are material under this local profile. Authorization audience remains verifier context.',
    references: [],
  };
}

function buildCorpus() {
  const profiles = { reference: referenceProfile() };
  const sources = { reference: structuredClone(REFERENCE) };
  const vectors = [];

  for (const target of targets) {
    const id = slug(target);
    profiles[`${id}:native`] = profile(target, 'native');
    profiles[`${id}:carry`] = profile(target, 'carry');
    sources[`${id}:native`] = nativeSource(target);
    sources[`${id}:carry`] = carrySource(target);
    vectors.push({
      id: `${id}:native`,
      left: { source: 'reference', profile: 'reference', pin: 'profile' },
      right: { source: `${id}:native`, profile: `${id}:native`, pin: 'profile' },
      expect: nativeVerdict(target) === 'EQUIVALENT_UNDER_PROFILE'
        ? { verdict: 'EQUIVALENT_UNDER_PROFILE', reasons: [] }
        : (target.omitted_source_fields?.length ?? 0) > 0
          ? {
              verdict: 'INDETERMINATE',
              reason_contains: 'right:declared_source_semantic_loss',
            }
          : {
            verdict: 'INDETERMINATE',
            reason_contains: `right:missing_source_field:${probePath(target.missing_material_fields[0])}`,
          },
    });
    vectors.push({
      id: `${id}:carry`,
      left: { source: 'reference', profile: 'reference', pin: 'profile' },
      right: { source: `${id}:carry`, profile: `${id}:carry`, pin: 'profile' },
      expect: { verdict: 'EQUIVALENT_UNDER_PROFILE', reasons: [] },
    });
    vectors.push({
      id: `${id}:mutation`,
      left: { source: 'reference', profile: 'reference', pin: 'profile' },
      right: { source: `${id}:carry`, profile: `${id}:carry`, pin: 'profile' },
      mutations: [{
        side: 'right',
        target: 'source',
        op: 'set',
        path: '/caid_action/parameters/amount',
        value: '1280.01',
      }],
      expect: { verdict: 'NOT_EQUIVALENT', reasons: ['material_projection_mismatch'] },
    });
    vectors.push({
      id: `${id}:missing`,
      left: { source: 'reference', profile: 'reference', pin: 'profile' },
      right: { source: `${id}:carry`, profile: `${id}:carry`, pin: 'profile' },
      mutations: [{
        side: 'right',
        target: 'source',
        op: 'delete',
        path: '/caid_action/parameters',
      }],
      expect: {
        verdict: 'INDETERMINATE',
        reason_contains: 'right:missing_source_field:/caid_action/parameters',
      },
    });
  }

  return {
    '@version': 'CAID-CONSEQUENTIAL-ACTION-MAPPING-VECTORS-v2',
    description: 'Executable candidate mappings for 25 consequential mechanisms. Mapping is correlation, never authorization or endorsement.',
    suite: 'jcs-sha256',
    definitions: [actionDefinition()],
    profiles,
    sources,
    vectors,
  };
}

const OUTPUTS = {
  'manifest.json': buildManifest(),
  'mapping-vectors.json': buildCorpus(),
};

let failed = false;
for (const [name, value] of Object.entries(OUTPUTS)) {
  const expected = stableJson(value);
  const url = new URL(name, HERE);
  if (process.argv.includes('--check')) {
    let actual = '';
    try {
      actual = await readFile(url, 'utf8');
    } catch {
      // Report the same governed-drift error for a missing generated artifact.
    }
    if (actual !== expected) {
      process.stderr.write(`generated artifact drift: ${fileURLToPath(url)}\n`);
      failed = true;
    }
  } else {
    await writeFile(url, expected);
  }
}
if (failed) process.exitCode = 1;
