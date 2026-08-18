#!/usr/bin/env -S npx tsx
// SPDX-License-Identifier: Apache-2.0
// Generated from signing-consult-demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP FIPS operation-policy consult -- signing demonstration.
 *
 * WHAT THIS PROGRAM IS. posture-check.mjs (in this same directory) reports a
 * posture and evaluates checkOperationPolicy() against it, but it never signs
 * anything. This script does: it drives the ACTUAL custody signing path --
 * bindExecution() in lib/execution/integrity.ts, one of the three call sites
 * documented in "Consult points in the custody signing path"
 * (docs/deployment/FIPS-MODE.md) -- under a configured FIPS posture, once
 * where the policy PERMITS the signature and once where it REFUSES it.
 *
 * THE CONFIG SURFACE. The consult is opt-in on the same flag as every other
 * call site: EP_FIPS_REQUIRED=true (read through getKeyCustodyConfig() in
 * lib/env.ts). With that flag unset, bindExecution() never calls
 * getFipsPosture() or checkOperationPolicy() at all -- signing is
 * byte-identical to the path that existed before this consult was wired in.
 * This script sets the flag in-process (not for you to imitate in a real
 * deployment -- there it belongs in the runtime environment, not code -- but
 * so the demo is self-contained) and then injects two different FIPS
 * postures through bindExecution()'s test-only `fipsPosture` parameter, so
 * the refusal is deterministic and does not depend on this host actually
 * running under an active FIPS mode.
 *
 * WHAT A GREEN RUN PROVES, AND NOTHING MORE. The REFUSED case proves the
 * consult runs BEFORE the provider-side signing effect (the executor's
 * signer.sign() callback is never invoked -- watch the counter) and names
 * both the general refusal and the fips-mode module's own reason. Neither
 * outcome is a FIPS validation or compliance claim; see
 * docs/deployment/FIPS-MODE.md for the ceiling this earns.
 *
 * Usage:  npx tsx examples/fips-deployment/signing-consult-demo.mts
 */
import crypto from 'node:crypto';
import { bindExecution, verifyExecutionIntegrity, } from '../../lib/execution/integrity.js';
import { actionHash } from '../../packages/issue/index.js';
const out = [];
const say = (line = '') => out.push(line);
const rule = () => say('-'.repeat(78));
say('EP FIPS operation-policy consult -- signing demonstration');
rule();
// ---------------------------------------------------------------------------
// A minimal executor fixture: an Ed25519 signing callback, exactly the shape
// bindExecution() requires (executorId, publicKeyB64u, sign). EP never holds
// executor keys itself; this mirrors that boundary.
// ---------------------------------------------------------------------------
const executorKeyPair = crypto.generateKeyPairSync('ed25519');
const EXECUTOR_ID = 'ep:executor:fips-demo';
const EXECUTOR_PUBLIC_KEY_B64U = executorKeyPair.publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
let signCallCount = 0;
function makeExecutorSigner() {
    return {
        executorId: EXECUTOR_ID,
        publicKeyB64u: EXECUTOR_PUBLIC_KEY_B64U,
        sign: (bytes) => {
            signCallCount += 1;
            return crypto.sign(null, bytes, executorKeyPair.privateKey).toString('base64url');
        },
    };
}
const APPROVED_ACTION = {
    action_type: 'payment.release',
    policy_id: 'policy.wires',
    initiator: 'ep:agent:worker',
    target_resource_id: 'wire/fips-demo-1',
    amount: 500,
    currency: 'USD',
};
const APPROVED_HASH = actionHash(APPROVED_ACTION);
// ---------------------------------------------------------------------------
// Two FIPS postures, fed through the REAL checkOperationPolicy() -- nothing
// about fips-mode.ts is mocked or reimplemented here.
// ---------------------------------------------------------------------------
const PERMIT_POSTURE = {
    version: 'EP-FIPS-MODE-v1',
    fips_status: 'active',
    fips_mode_active: true,
    openssl_version: 'demo-3.x',
    node_version: process.version,
    openssl_operational: true,
    ed25519_operational: true,
    // Declared INSIDE the certificate -- the operator's own statement, read off
    // their CMVP security policy, never a runtime guess. See "Trap 2" in
    // docs/deployment/FIPS-MODE.md for why this cannot be probed.
    ed25519_in_validated_boundary: true,
    mldsa_backend: '@noble/post-quantum (pure JavaScript, FIPS 204 ML-DSA-65)',
    mldsa_validated_module: false,
};
const REFUSE_POSTURE = {
    ...PERMIT_POSTURE,
    // Same live, working FIPS provider -- but the operator has declared Ed25519
    // OUTSIDE the certificate (the OpenSSL 3.0.x trap: the operation would
    // still succeed if attempted, which is exactly why this must refuse).
    ed25519_in_validated_boundary: false,
};
process.env.EP_FIPS_REQUIRED = 'true';
// ---------------------------------------------------------------------------
// Run 1: PERMITTED. Posture declares Ed25519 inside the validated boundary --
// the consult runs and passes; signing proceeds.
// ---------------------------------------------------------------------------
say('RUN 1: EP_FIPS_REQUIRED=true, Ed25519 declared INSIDE the validated boundary');
say('  -> expect the consult to PERMIT and the signature to be produced.');
say();
const countBeforeRun1 = signCallCount;
const permitted = bindExecution({
    approvedActionHash: APPROVED_HASH,
    executedAction: APPROVED_ACTION,
    irreversible: false,
    signer: makeExecutorSigner(),
    fipsPosture: PERMIT_POSTURE,
});
const signCallsRun1 = signCallCount - countBeforeRun1;
const verified = verifyExecutionIntegrity(permitted, { action_hash: APPROVED_HASH }, {
    executorKeys: { [EXECUTOR_ID]: { public_key: EXECUTOR_PUBLIC_KEY_B64U } },
});
say(`  signer.sign() call count during this run: ${signCallsRun1} (expected 1)`);
say(`  binding_status: ${permitted.binding_status}`);
say(`  attestation independently verifies: ${verified.valid}`);
rule();
// ---------------------------------------------------------------------------
// Run 2: REFUSED. Same flag, same live provider -- but the boundary is
// declared OUTSIDE the certificate. The consult must refuse BEFORE
// signer.sign() runs, naming both the general refusal and fips-mode's own
// reason.
// ---------------------------------------------------------------------------
say('RUN 2: EP_FIPS_REQUIRED=true, Ed25519 declared OUTSIDE the validated boundary');
say('  -> expect the consult to REFUSE BEFORE any signing call.');
say();
const countBeforeRun2 = signCallCount;
let refusalMessage = null;
try {
    bindExecution({
        approvedActionHash: APPROVED_HASH,
        executedAction: APPROVED_ACTION,
        irreversible: false,
        signer: makeExecutorSigner(),
        fipsPosture: REFUSE_POSTURE,
    });
}
catch (e) {
    refusalMessage = e.message;
}
const signCallsRun2 = signCallCount - countBeforeRun2;
say(`  refused: ${refusalMessage !== null}`);
say(`  reason:  ${refusalMessage ?? '(none -- this would be a failure of the demo, not the module)'}`);
say(`  signer.sign() call count during this run: ${signCallsRun2} (expected 0 -- refused BEFORE the provider-side effect)`);
rule();
say('WHAT THIS DOES AND DOES NOT PROVE');
say('  PERMITTED means the DECLARED posture allows the operation to proceed; it is');
say('  not a FIPS validation or compliance claim. REFUSED means the same kind of');
say('  declared posture said no, by name, before any signing occurred -- never a');
say('  crash and never a silent pass. See docs/deployment/FIPS-MODE.md, "Consult');
say('  points in the custody signing path" and "The honest boundary."');
process.stdout.write(out.join('\n') + '\n');
const ok = signCallsRun1 === 1
    && verified.valid === true
    && refusalMessage !== null
    && refusalMessage.includes('fips_policy_denied')
    && signCallsRun2 === 0;
process.exit(ok ? 0 : 1);
