// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { appendFile, chmod, copyFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  REFEREE_EVALUATION_VERSION,
  REFEREE_RESULT_VERSION,
  REFEREE_RUNNER_OUTPUT_VERSION,
  REFEREE_RUNNER_REQUEST_VERSION,
  RefereeValidationError,
  evaluateReferee,
  type RefereeEvaluationInputV1,
  type RefereeRunnerOutputV1,
  type RefereeRunnerPinV1,
  type RefereeRunnerRequestV1,
} from './referee.js';
import {
  REFEREE_RUNNER_MAX_INPUT_BYTES,
  REFEREE_RUNNER_MAX_OUTPUT_BYTES,
  runPinnedProtocolRunner,
  runReferee,
} from './referee-runner.js';

const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const ACTION_DIGEST = `sha256:${'1'.repeat(64)}`;
const NODE_EXECUTABLE_SHA256 = executableDigest(process.execPath);

function runnerRequest(
  overrides: Partial<RefereeRunnerRequestV1> = {},
): RefereeRunnerRequestV1 {
  return {
    version: REFEREE_RUNNER_REQUEST_VERSION,
    case_id: 'case:valid-payment-release',
    protocol_id: 'protocol:example-v1',
    expected_caid: CAID,
    expected_action_digest: ACTION_DIGEST,
    aec_required: true,
    execution_scope: 'local_atomic',
    input: {
      artifact: 'opaque-native-protocol-value',
      evidence: ['evidence:one'],
    },
    ...overrides,
  };
}

function runnerOutput(
  overrides: Partial<RefereeRunnerOutputV1> = {},
): RefereeRunnerOutputV1 {
  return {
    version: REFEREE_RUNNER_OUTPUT_VERSION,
    case_id: 'case:valid-payment-release',
    protocol_id: 'protocol:example-v1',
    native_verification: 'VERIFIED',
    rp_acceptance: 'ACCEPTED',
    caid: CAID,
    action_digest: ACTION_DIGEST,
    aec_satisfaction: 'SATISFIED',
    provider_outcome: 'COMMITTED',
    effect_relation: 'OBSERVED_AS_REQUESTED',
    execution_scope: 'local_atomic',
    ...overrides,
  };
}

function runnerPin(
  script = successfulRunnerScript(),
): RefereeRunnerPinV1 {
  return {
    executable: process.execPath,
    executable_sha256: NODE_EXECUTABLE_SHA256,
    args: ['-e', script],
  };
}

function executableDigest(executable: string): `sha256:${string}` {
  const digest = crypto.createHash('sha256').update(readFileSync(executable)).digest('hex');
  return `sha256:${digest}`;
}

function evaluation(
  output: RefereeRunnerOutputV1 = runnerOutput(),
  overrides: Partial<RefereeEvaluationInputV1> = {},
): RefereeEvaluationInputV1 {
  return {
    version: REFEREE_EVALUATION_VERSION,
    runner_pin: runnerPin(),
    request: runnerRequest(),
    output,
    ...overrides,
  };
}

function successfulRunnerScript(output: RefereeRunnerOutputV1 = runnerOutput()): string {
  return [
    "let raw = '';",
    "process.stdin.setEncoding('utf8');",
    "process.stdin.on('data', (chunk) => { raw += chunk; });",
    `process.stdin.on('end', () => { JSON.parse(raw); process.stdout.write(${JSON.stringify(JSON.stringify(output))}); });`,
  ].join('\n');
}

describe('offline EMILIA Referee core', () => {
  it('emits only the closed EP-REFEREE-RESULT-v1 self-test claim', () => {
    const result = evaluateReferee(evaluation());

    assert.equal(result.version, REFEREE_RESULT_VERSION);
    assert.equal(result.version, 'EP-REFEREE-RESULT-v1');
    assert.equal(result.status, 'CONFORMANT');
    assert.equal(result.claim_scope, 'SELF_TEST');
    assert.equal(result.execution_authorizing, false);
    assert.equal(result.execution_scope, 'local_atomic');
    assert.equal(result.remote_atomicity_claimed, false);
    assert.equal(result.runner_pin.executable_sha256, NODE_EXECUTABLE_SHA256);
    assert.deepEqual(Object.keys(result).sort(), [
      'case_id',
      'claim_scope',
      'dimensions',
      'execution_authorizing',
      'execution_scope',
      'protocol_id',
      'reason_codes',
      'remote_atomicity_claimed',
      'runner_pin',
      'status',
      'version',
    ]);
    assert.doesNotMatch(JSON.stringify(result), /"(?:AUTHORIZED|EXECUTED)"/);
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.runner_pin));
    assert.ok(Object.isFrozen(result.runner_pin.args));
    assert.ok(Object.isFrozen(result.dimensions));
  });

  it('keeps native verification, RP acceptance, CAID/action match, AEC, provider, and effect separate', () => {
    const result = evaluateReferee(evaluation(runnerOutput({
      provider_outcome: 'COMMITTED',
      effect_relation: 'DIVERGED',
    })));

    assert.deepEqual(result.dimensions.native_verification, {
      value: 'VERIFIED',
    });
    assert.deepEqual(result.dimensions.rp_acceptance, {
      value: 'ACCEPTED',
    });
    assert.deepEqual(result.dimensions.caid_action_match, {
      value: 'MATCH',
      expected_caid: CAID,
      observed_caid: CAID,
      expected_action_digest: ACTION_DIGEST,
      observed_action_digest: ACTION_DIGEST,
    });
    assert.deepEqual(result.dimensions.aec_satisfaction, {
      required: true,
      value: 'SATISFIED',
    });
    assert.deepEqual(result.dimensions.provider_outcome, {
      value: 'COMMITTED',
    });
    assert.deepEqual(result.dimensions.effect_relation, {
      value: 'DIVERGED',
    });
    assert.equal(result.status, 'NON_CONFORMANT');
    assert.deepEqual(result.reason_codes, ['effect_diverged']);
  });

  it('does not collapse relying-party rejection or uncertainty into native verification or AEC', () => {
    const rejected = evaluateReferee(evaluation(runnerOutput({
      native_verification: 'VERIFIED',
      rp_acceptance: 'REJECTED',
      aec_satisfaction: 'SATISFIED',
    })));
    assert.equal(rejected.status, 'NON_CONFORMANT');
    assert.equal(rejected.dimensions.native_verification.value, 'VERIFIED');
    assert.equal(rejected.dimensions.rp_acceptance.value, 'REJECTED');
    assert.equal(rejected.dimensions.caid_action_match.value, 'MATCH');
    assert.equal(rejected.dimensions.aec_satisfaction.value, 'SATISFIED');
    assert.deepEqual(rejected.reason_codes, ['rp_acceptance_rejected']);

    const uncertain = evaluateReferee(evaluation(runnerOutput({
      native_verification: 'VERIFIED',
      rp_acceptance: 'INDETERMINATE',
      aec_satisfaction: 'SATISFIED',
    })));
    assert.equal(uncertain.status, 'INDETERMINATE');
    assert.equal(uncertain.dimensions.native_verification.value, 'VERIFIED');
    assert.equal(uncertain.dimensions.rp_acceptance.value, 'INDETERMINATE');
    assert.equal(uncertain.dimensions.caid_action_match.value, 'MATCH');
    assert.equal(uncertain.dimensions.aec_satisfaction.value, 'SATISFIED');
    assert.deepEqual(uncertain.reason_codes, ['rp_acceptance_indeterminate']);
  });

  it('does not turn a proven non-commit into an observed-effect claim', () => {
    const result = evaluateReferee(evaluation(runnerOutput({
      provider_outcome: 'PROVEN_NOT_COMMITTED',
      effect_relation: 'NOT_ASSESSED',
    })));

    assert.equal(result.status, 'CONFORMANT');
    assert.equal(result.dimensions.provider_outcome.value, 'PROVEN_NOT_COMMITTED');
    assert.equal(result.dimensions.effect_relation.value, 'NOT_ASSESSED');
  });

  it('preserves every provider/effect pair without collapsing either dimension', () => {
    const providerOutcomes = [
      'COMMITTED',
      'PROVEN_NOT_COMMITTED',
      'INDETERMINATE',
      'NOT_ASSESSED',
    ] as const;
    const effectRelations = [
      'OBSERVED_AS_REQUESTED',
      'DIVERGED',
      'INDETERMINATE',
      'NOT_ASSESSED',
    ] as const;

    for (const providerOutcome of providerOutcomes) {
      for (const effectRelation of effectRelations) {
        const result = evaluateReferee(evaluation(runnerOutput({
          provider_outcome: providerOutcome,
          effect_relation: effectRelation,
        })));
        assert.equal(result.dimensions.provider_outcome.value, providerOutcome);
        assert.equal(result.dimensions.effect_relation.value, effectRelation);
      }
    }
  });

  it('reports federated scope while always refusing a remote atomicity claim', () => {
    const request = runnerRequest({ execution_scope: 'federated' });
    const output = runnerOutput({ execution_scope: 'federated' });
    const result = evaluateReferee(evaluation(output, { request }));

    assert.equal(result.status, 'CONFORMANT');
    assert.equal(result.execution_scope, 'federated');
    assert.equal(result.remote_atomicity_claimed, false);
  });

  it('uses fixed NON_CONFORMANT precedence for definite failures', () => {
    const result = evaluateReferee(evaluation(runnerOutput({
      native_verification: 'INDETERMINATE',
      rp_acceptance: 'REJECTED',
      caid: `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}`,
      aec_satisfaction: 'NOT_SATISFIED',
      provider_outcome: 'INDETERMINATE',
      effect_relation: 'DIVERGED',
    })));

    assert.equal(result.status, 'NON_CONFORMANT');
    assert.deepEqual(result.reason_codes, [
      'native_verification_indeterminate',
      'rp_acceptance_rejected',
      'caid_action_mismatch',
      'aec_not_satisfied',
      'provider_outcome_indeterminate',
      'effect_diverged',
    ]);
  });

  it('uses INDETERMINATE when evidence is unknown and no definite failure exists', () => {
    const result = evaluateReferee(evaluation(runnerOutput({
      native_verification: 'INDETERMINATE',
      caid: null,
      action_digest: null,
      aec_satisfaction: 'INDETERMINATE',
      provider_outcome: 'NOT_ASSESSED',
      effect_relation: 'INDETERMINATE',
    })));

    assert.equal(result.status, 'INDETERMINATE');
    assert.equal(result.dimensions.caid_action_match.value, 'INDETERMINATE');
    assert.deepEqual(result.reason_codes, [
      'native_verification_indeterminate',
      'caid_action_indeterminate',
      'aec_indeterminate',
      'effect_indeterminate',
    ]);
  });

  it('requires AEC only when pinned by the relying party', () => {
    const required = evaluateReferee(evaluation(runnerOutput({
      aec_satisfaction: 'NOT_ASSESSED',
    })));
    assert.equal(required.status, 'NON_CONFORMANT');
    assert.deepEqual(required.reason_codes, ['aec_not_assessed']);

    const request = runnerRequest({ aec_required: false });
    const optional = evaluateReferee(evaluation(runnerOutput({
      aec_satisfaction: 'NOT_ASSESSED',
    }), { request }));
    assert.equal(optional.status, 'CONFORMANT');
    assert.deepEqual(optional.reason_codes, []);
  });

  it('detects case, protocol, and scope substitution without trusting output metadata', () => {
    const result = evaluateReferee(evaluation(runnerOutput({
      case_id: 'case:substituted',
      protocol_id: 'protocol:substituted',
      execution_scope: 'federated',
    })));

    assert.equal(result.status, 'NON_CONFORMANT');
    assert.equal(result.case_id, 'case:valid-payment-release');
    assert.equal(result.protocol_id, 'protocol:example-v1');
    assert.equal(result.execution_scope, 'local_atomic');
    assert.deepEqual(result.reason_codes, [
      'case_id_mismatch',
      'protocol_id_mismatch',
      'execution_scope_mismatch',
    ]);
  });

  it('refuses unknown keys at every closed schema boundary', () => {
    assert.throws(
      () => evaluateReferee({ ...evaluation(), ambient_trust: true }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'unknown_key',
    );
    assert.throws(
      () => evaluateReferee({
        ...evaluation(),
        runner_pin: { ...runnerPin(), shell: true },
      }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'unknown_key',
    );
    assert.throws(
      () => evaluateReferee({
        ...evaluation(),
        request: { ...runnerRequest(), trust_store: 'ambient' },
      }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'unknown_key',
    );
    assert.throws(
      () => evaluateReferee(evaluation({
        ...runnerOutput(),
        authorized: true,
      } as RefereeRunnerOutputV1)),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'unknown_key',
    );
  });

  it('refuses accessor-backed schemas and JSON deeper than 64 containers', () => {
    const accessorBacked = evaluation() as unknown as Record<string, unknown>;
    Object.defineProperty(accessorBacked, 'version', {
      enumerable: true,
      get: () => { throw new Error('accessor must not run'); },
    });
    assert.throws(
      () => evaluateReferee(accessorBacked),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_schema',
    );

    const nested = (containers: number): RefereeRunnerRequestV1['input'] => {
      let value: RefereeRunnerRequestV1['input'] = null;
      for (let index = 0; index < containers; index += 1) value = [value];
      return value;
    };
    assert.equal(evaluateReferee(evaluation(runnerOutput(), {
      request: runnerRequest({ input: nested(64) }),
    })).status, 'CONFORMANT');
    assert.throws(
      () => evaluateReferee(evaluation(runnerOutput(), {
        request: runnerRequest({ input: nested(65) }),
      })),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_json',
    );
  });

  it('refuses invalid executable pins, lossy JSON, and invalid verification enums', () => {
    assert.throws(
      () => evaluateReferee({
        ...evaluation(),
        runner_pin: {
          executable: 'node',
          executable_sha256: NODE_EXECUTABLE_SHA256,
          args: [],
        },
      }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_executable',
    );
    assert.throws(
      () => evaluateReferee({
        ...evaluation(),
        runner_pin: {
          ...runnerPin(),
          executable_sha256: 'sha256:ABC',
        },
      }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_executable_digest',
    );
    assert.throws(
      () => evaluateReferee({
        ...evaluation(),
        request: runnerRequest({ input: { omitted: undefined } as never }),
      }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_json',
    );
    assert.throws(
      () => evaluateReferee(evaluation(runnerOutput({
        native_verification: 'AUTHORIZED' as never,
      }))),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_native_verification',
    );
    assert.throws(
      () => evaluateReferee(evaluation(runnerOutput({
        rp_acceptance: 'AUTHORIZED' as never,
      }))),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'invalid_rp_acceptance',
    );
  });
});

describe('pinned JSON subprocess protocol runner', () => {
  it('writes one bounded request and accepts one exact closed output', async () => {
    const pin = runnerPin();
    const request = runnerRequest();
    const execution = await runPinnedProtocolRunner({
      runner_pin: pin,
      request,
      timeout_ms: 1_000,
    });

    assert.deepEqual(execution, {
      ok: true,
      output: runnerOutput(),
    });
    assert.ok(Object.isFrozen(execution));
    assert.ok(execution.ok && Object.isFrozen(execution.output));
  });

  it('counts but does not mix bounded stderr into the JSON stdout document', async () => {
    const script = [
      "process.stdin.resume();",
      `process.stdin.on('end', () => { process.stderr.write('diagnostic'); process.stdout.write(${JSON.stringify(JSON.stringify(runnerOutput()))}); });`,
    ].join('\n');
    const execution = await runPinnedProtocolRunner({
      runner_pin: runnerPin(script),
      request: runnerRequest(),
      timeout_ms: 1_000,
    });

    assert.deepEqual(execution, { ok: true, output: runnerOutput() });
  });

  it('does not inherit environment or invoke a shell for pinned arguments', async () => {
    const script = [
      "process.stdin.resume();",
      "process.stdin.on('end', () => {",
      "  if (process.env.HOME !== undefined || process.argv[1] !== '$HOME') process.exit(8);",
      `  process.stdout.write(${JSON.stringify(JSON.stringify(runnerOutput()))});`,
      "});",
    ].join('\n');
    const execution = await runPinnedProtocolRunner({
      runner_pin: {
        executable: process.execPath,
        executable_sha256: NODE_EXECUTABLE_SHA256,
        args: ['-e', script, '$HOME'],
      },
      request: runnerRequest(),
      timeout_ms: 1_000,
    });

    assert.deepEqual(execution, { ok: true, output: runnerOutput() });
  });

  it('maps malformed, duplicate-key, and schema-invalid output deterministically', async () => {
    const outputs = [
      ['MALFORMED_OUTPUT', "process.stdin.resume(); process.stdin.on('end', () => process.stdout.write('{'));"],
      ['MALFORMED_OUTPUT', "process.stdin.resume(); process.stdin.on('end', () => process.stdout.write('{\"version\":1,\"version\":2}'));"],
      ['INVALID_OUTPUT_SCHEMA', successfulRunnerScript({
        ...runnerOutput(),
        ambient_trust: true,
      } as RefereeRunnerOutputV1)],
    ] as const;

    for (const [code, script] of outputs) {
      const execution = await runPinnedProtocolRunner({
        runner_pin: runnerPin(script),
        request: runnerRequest(),
        timeout_ms: 1_000,
      });
      assert.deepEqual(execution, { ok: false, code });
    }
  });

  it('maps a nonzero exit without accepting otherwise valid stdout', async () => {
    const script = [
      "process.stdin.resume();",
      `process.stdin.on('end', () => { process.stdout.write(${JSON.stringify(JSON.stringify(runnerOutput()))}); process.exit(7); });`,
    ].join('\n');
    const execution = await runPinnedProtocolRunner({
      runner_pin: runnerPin(script),
      request: runnerRequest(),
      timeout_ms: 1_000,
    });

    assert.deepEqual(execution, { ok: false, code: 'NONZERO_EXIT' });
  });

  it('times out and kills a runner that never closes', async () => {
    const execution = await runPinnedProtocolRunner({
      runner_pin: runnerPin("process.stdin.resume(); setInterval(() => {}, 1000);"),
      request: runnerRequest(),
      timeout_ms: 25,
    });

    assert.deepEqual(execution, { ok: false, code: 'TIMEOUT' });
  });

  it('honors caller abort and kills the subprocess', async () => {
    const controller = new AbortController();
    const pending = runPinnedProtocolRunner({
      runner_pin: runnerPin("process.stdin.resume(); setInterval(() => {}, 1000);"),
      request: runnerRequest(),
      timeout_ms: 1_000,
    }, { signal: controller.signal });
    setTimeout(() => controller.abort(), 10);

    assert.deepEqual(await pending, { ok: false, code: 'ABORTED' });
  });

  it('enforces the 8 MiB serialized input ceiling before spawn', async () => {
    const result = await runPinnedProtocolRunner({
      runner_pin: {
        executable: '/definitely/not/an/emilia-referee-runner',
        executable_sha256: `sha256:${'0'.repeat(64)}`,
        args: [],
      },
      request: runnerRequest({
        input: {
          payload: 'x'.repeat(REFEREE_RUNNER_MAX_INPUT_BYTES),
        },
      }),
      timeout_ms: 1_000,
    });

    assert.deepEqual(result, { ok: false, code: 'INPUT_TOO_LARGE' });
  });

  it('enforces one combined 8 MiB stdout/stderr ceiling and kills the runner', async () => {
    const script = [
      'process.stdin.resume();',
      `process.stdin.on('end', () => { process.stdout.write('x'.repeat(${REFEREE_RUNNER_MAX_OUTPUT_BYTES})); process.stderr.write('y'); });`,
    ].join('\n');
    const execution = await runPinnedProtocolRunner({
      runner_pin: runnerPin(script),
      request: runnerRequest(),
      timeout_ms: 2_000,
    });

    assert.deepEqual(execution, { ok: false, code: 'OUTPUT_TOO_LARGE' });
  });

  it('maps an unspawnable caller-pinned executable without path lookup', async () => {
    const execution = await runPinnedProtocolRunner({
      runner_pin: {
        executable: '/definitely/not/an/emilia-referee-runner',
        executable_sha256: `sha256:${'0'.repeat(64)}`,
        args: [],
      },
      request: runnerRequest(),
      timeout_ms: 1_000,
    });

    assert.deepEqual(execution, { ok: false, code: 'SPAWN_FAILED' });
  });

  it('refuses an executable whose bytes do not match the caller pin', async () => {
    const invocation = {
      runner_pin: {
        executable: process.execPath,
        executable_sha256: `sha256:${'0'.repeat(64)}`,
        args: ['-e', successfulRunnerScript()],
      },
      request: runnerRequest(),
      timeout_ms: 1_000,
    } as const;
    const execution = await runPinnedProtocolRunner(invocation);

    assert.deepEqual(execution, {
      ok: false,
      code: 'EXECUTABLE_DIGEST_MISMATCH',
    });
    const result = await runReferee(invocation);
    assert.equal(result.status, 'INDETERMINATE');
    assert.equal(result.execution_authorizing, false);
    assert.deepEqual(result.reason_codes, [
      'runner_executable_digest_mismatch',
    ]);
  });

  it('detects executable-byte mutation made after pinning and before invocation', async () => {
    const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'emilia-referee-'));
    const executable = path.join(temporaryDirectory, 'runner');
    try {
      await copyFile(process.execPath, executable);
      await chmod(executable, 0o700);
      const executableSha256 = executableDigest(executable);
      await appendFile(executable, Buffer.from([0]));

      const execution = await runPinnedProtocolRunner({
        runner_pin: {
          executable,
          executable_sha256: executableSha256,
          args: ['-e', successfulRunnerScript()],
        },
        request: runnerRequest(),
        timeout_ms: 1_000,
      });

      assert.deepEqual(execution, {
        ok: false,
        code: 'EXECUTABLE_DIGEST_MISMATCH',
      });
    } finally {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });

  it('refuses unknown invocation and option keys', async () => {
    await assert.rejects(
      runPinnedProtocolRunner({
        runner_pin: runnerPin(),
        request: runnerRequest(),
        timeout_ms: 1_000,
        env: process.env,
      }),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'unknown_key',
    );
    await assert.rejects(
      runPinnedProtocolRunner({
        runner_pin: runnerPin(),
        request: runnerRequest(),
        timeout_ms: 1_000,
      }, { signal: undefined, shell: true } as never),
      (error: unknown) => error instanceof RefereeValidationError
        && error.code === 'unknown_key',
    );
  });

  it('maps all runner failures into a non-authorizing INDETERMINATE referee result', async () => {
    const result = await runReferee({
      runner_pin: runnerPin("process.stdin.resume(); process.stdin.on('end', () => process.exit(9));"),
      request: runnerRequest(),
      timeout_ms: 1_000,
    });

    assert.equal(result.version, REFEREE_RESULT_VERSION);
    assert.equal(result.status, 'INDETERMINATE');
    assert.equal(result.claim_scope, 'SELF_TEST');
    assert.equal(result.execution_authorizing, false);
    assert.equal(result.remote_atomicity_claimed, false);
    assert.deepEqual(result.reason_codes, ['runner_nonzero_exit']);
    assert.equal(result.dimensions.native_verification.value, 'INDETERMINATE');
    assert.equal(result.dimensions.rp_acceptance.value, 'INDETERMINATE');
    assert.equal(result.dimensions.caid_action_match.value, 'INDETERMINATE');
    assert.equal(result.dimensions.aec_satisfaction.value, 'INDETERMINATE');
    assert.equal(result.dimensions.provider_outcome.value, 'NOT_ASSESSED');
    assert.equal(result.dimensions.effect_relation.value, 'NOT_ASSESSED');
    assert.doesNotMatch(JSON.stringify(result), /"(?:AUTHORIZED|EXECUTED)"/);
  });
});
