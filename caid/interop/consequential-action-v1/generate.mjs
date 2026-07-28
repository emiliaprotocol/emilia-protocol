#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { targets } from './targets.mjs';

const HERE = new URL('./', import.meta.url);
const MATERIAL = ['operation', 'target_ref', 'parameters_digest'];
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

function rulesFor(paths) {
  return [
    { source_path: paths.operation, target_field: 'operation', transform: 'copy' },
    { source_path: paths.target, target_field: 'target_ref', transform: 'sha256-utf8' },
    { source_path: paths.parameters, target_field: 'parameters_digest', transform: 'sha256-jcs' },
  ];
}

function profile(target, kind) {
  const isCarry = kind === 'carry';
  const paths = isCarry
    ? {
        operation: '/caid_action/operation',
        target: '/caid_action/target',
        parameters: '/caid_action/parameters',
      }
    : target.paths;
  return {
    '@version': 'CAID-MAPPING-PROFILE-v1',
    profile_id: `urn:caid:interop:${slug(target)}:${kind}:1`,
    source_format: sourceFormat(target, kind),
    target_action_type: 'consequence.invoke.1',
    loss_policy: 'no-material-field-loss',
    material_source_paths: Object.values(paths),
    rules: rulesFor(paths),
  };
}

function referenceProfile() {
  const paths = {
    operation: '/operation',
    target: '/target',
    parameters: '/parameters',
  };
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
    material_source_paths: Object.values(paths),
    rules: rulesFor(paths),
  };
}

function nativeSource(target) {
  const source = { draft: target.draft, revision: target.revision };
  const values = {
    operation: REFERENCE.operation,
    target_ref: REFERENCE.target,
    parameters_digest: REFERENCE.parameters,
  };
  const pathByField = {
    operation: target.paths.operation,
    target_ref: target.paths.target,
    parameters_digest: target.paths.parameters,
  };
  for (const field of MATERIAL) {
    if (!target.missing_material_fields.includes(field)) {
      setPointer(source, pathByField[field], values[field]);
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
    '@version': 'CAID-CONSEQUENTIAL-ACTION-INTEROP-v1',
    title: 'Consequential Action Interoperability Project — 25 Candidate Mappings',
    frozen_at: '2026-07-27',
    status: 'CANDIDATE_MAPPINGS_PENDING_AUTHOR_REVIEW',
    claim_boundary: [
      'A mapping result is content correlation under a pinned profile; it is not authorization.',
      'INDETERMINATE is an expected fail-closed result when a mechanism does not expose every material action field.',
      'The optional carry profile is a proposed composition path, not a claim that the source draft defines or endorses CAID.',
      'Authorization audience and trust context remain outside this action identifier; target identifies where the material action occurs.',
      'No author participation, validation, implementation, adoption, or endorsement is claimed.',
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
      native_verdict: target.native_binding === 'COMPLETE'
        ? 'EQUIVALENT_UNDER_PROFILE'
        : 'INDETERMINATE',
      missing_material_fields: target.missing_material_fields,
      evidence: [{ locator: target.evidence[0], finding: target.evidence[1] }],
      ...(target.native_profile_role
        ? { native_profile_role: target.native_profile_role }
        : {}),
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
      expect: target.native_binding === 'COMPLETE'
        ? { verdict: 'EQUIVALENT_UNDER_PROFILE', reasons: [] }
        : {
            verdict: 'INDETERMINATE',
            reason_contains: `right:missing_source_field:${target.paths[
              {
                operation: 'operation',
                target_ref: 'target',
                parameters_digest: 'parameters',
              }[target.missing_material_fields[0]]
            ]}`,
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
    '@version': 'CAID-CONSEQUENTIAL-ACTION-MAPPING-VECTORS-v1',
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
