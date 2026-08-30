// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalizeCrossingLab,
  digestCrossingLab,
  runCrossingLab,
} from '../../../packages/verify/dist/crossing-lab.js';
import { ACTION_DEFINITION, MAPPING_DEFINITION } from './workspace/adapter.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function readJson(name) {
  return JSON.parse(readFileSync(resolve(HERE, name), 'utf8'));
}

export function runCedulonCrossingProfile() {
  const sourceLock = readJson('source-lock.json');
  const actionDefinition = readJson('action-definition.json');
  const mappingProfile = readJson('mapping-profile.json');
  const workspace = readJson('workspace/workspace.json');
  if (canonicalizeCrossingLab(actionDefinition) !== canonicalizeCrossingLab(ACTION_DEFINITION)) {
    throw new Error('action definition differs from executable adapter');
  }
  if (canonicalizeCrossingLab(mappingProfile) !== canonicalizeCrossingLab(MAPPING_DEFINITION)
      || canonicalizeCrossingLab(workspace.config.profiles['cedulon:decision-token-payment-attempt'].definition)
        !== canonicalizeCrossingLab(mappingProfile)) {
    throw new Error('mapping profile differs from executable or workspace pin');
  }

  const lab = runCrossingLab(resolve(HERE, 'workspace'));
  const rows = Object.fromEntries(lab.adapter_rows.map((row) => [row.id, {
    passed: row.passed,
    native_verification: row.actual.native_verification,
    acceptance: row.actual.acceptance,
    mapping: row.actual.mapping,
    freshness: row.actual.freshness,
    satisfaction: row.actual.satisfaction,
    evaluation_valid: row.actual.evaluation_valid,
  }]));
  const harness = Object.fromEntries(lab.harness_self_tests.map((entry) => [entry.id, entry.passed]));
  const body = {
    '@version': 'EMILIA-CEDULON-AEB-CROSSING-REPORT-v0.1',
    source_lock_digest: digestCrossingLab(sourceLock),
    action_definition_digest: digestCrossingLab(actionDefinition),
    mapping_profile_digest: digestCrossingLab(mappingProfile),
    workspace_digest: lab.workspace_digest,
    adapter_module_digest: lab.adapter.module_digest,
    crossing_lab_report_digest: lab.report_digest,
    rows,
    harness,
    native_replay_unit: lab.adapter_rows.find((row) => row.id === 'native-artifact-through')?.evaluation.legs[0]?.replay_unit ?? null,
    claim_boundary: {
      native_artifact: 'Cedulon Decision Token',
      evidence_role: 'machine-policy-decision',
      pre_settlement: true,
      authorization: false,
      human_approval: false,
      settlement_or_payment_finality: false,
      rail_completeness: false,
      cross_relying_party_audience_binding: false,
      certification: false,
    },
    profile_passed: lab.lab_passed
      && Object.values(rows).every((row) => row.passed)
      && Object.values(harness).every(Boolean),
  };
  return { ...body, report_digest: digestCrossingLab(body) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const report = runCedulonCrossingProfile();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.profile_passed) process.exitCode = 1;
}
