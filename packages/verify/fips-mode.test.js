// SPDX-License-Identifier: Apache-2.0
// Generated from fips-mode.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Tests for EP-FIPS-MODE-v1 (src/fips-mode.ts).
 *
 * Two halves, deliberately separated:
 *
 *   1. LIVE-PROCESS tests assert only what is true of ANY machine: that the
 *      posture reporter never throws, that it answers with one of the three
 *      named statuses, and that it never claims a validated ML-DSA module.
 *      They do NOT assert "fips is off", because CI could one day run on a
 *      FIPS-mode host and a test that breaks there would be testing the host,
 *      not the code. The one FIPS-inactive-specific assertion is guarded on
 *      the observed status.
 *
 *   2. MATRIX tests inject synthetic posture objects, so the full
 *      {algorithm} x {fips on/off/unavailable} x {flag on/off} grid is
 *      deterministic on every machine, FIPS-capable or not.
 *
 * Run: npx tsx --test packages/verify/fips-mode.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { FIPS_MODE_VERSION, FIPS_POLICY_ALGORITHMS, FIPS_REASONS, readFipsStatus, probeEd25519, probeOpensslOperational, resetFipsProbeCache, getFipsPosture, formatFipsPosture, assertClassicalFips, mldsaPolicy, checkOperationPolicy, } from './src/fips-mode.js';
// ---------------------------------------------------------------------------
// Synthetic postures (the deterministic half)
// ---------------------------------------------------------------------------
function posture(fips_status, ed25519_operational = true, openssl_operational = true, ed25519_in_validated_boundary = true) {
    return {
        version: FIPS_MODE_VERSION,
        fips_status,
        fips_mode_active: fips_status === 'active',
        openssl_version: '3.0.9',
        node_version: '20.0.0',
        openssl_operational,
        ed25519_operational,
        ed25519_in_validated_boundary,
        mldsa_backend: 'synthetic',
        mldsa_validated_module: false,
    };
}
const FIPS_ON = posture('active');
const FIPS_OFF = posture('inactive');
const FIPS_UNKNOWN = posture('unavailable');
// ---------------------------------------------------------------------------
// 1. Live-process posture reporting
// ---------------------------------------------------------------------------
test('getFipsPosture reports without throwing on this machine', () => {
    const p = getFipsPosture();
    assert.equal(p.version, FIPS_MODE_VERSION);
    assert.ok(p.fips_status === 'active' || p.fips_status === 'inactive' || p.fips_status === 'unavailable', `unexpected fips_status ${p.fips_status}`);
    assert.equal(p.fips_mode_active, p.fips_status === 'active');
    assert.equal(typeof p.openssl_version, 'string');
    assert.equal(typeof p.node_version, 'string');
    assert.equal(typeof p.openssl_operational, 'boolean');
    assert.equal(typeof p.ed25519_operational, 'boolean');
});
test('this dev/CI process is not running FIPS mode, and says so by name', () => {
    const status = readFipsStatus();
    if (status !== 'inactive') {
        // A FIPS-capable host is a legitimate environment; do not fail on it.
        return;
    }
    const result = assertClassicalFips();
    assert.equal(result.ok, false);
    assert.equal(result.reason, FIPS_REASONS.FIPS_MODE_INACTIVE);
    assert.equal(result.posture.fips_mode_active, false);
});
test('readFipsStatus and the probes never throw', () => {
    assert.doesNotThrow(() => readFipsStatus());
    assert.doesNotThrow(() => probeEd25519());
    assert.doesNotThrow(() => probeOpensslOperational());
    assert.doesNotThrow(() => resetFipsProbeCache());
});
test('on a working non-FIPS host both probes report true', () => {
    if (readFipsStatus() !== 'inactive')
        return;
    assert.equal(probeOpensslOperational(), true);
    assert.equal(probeEd25519(), true);
});
test('posture never claims a validated ML-DSA module, and never can', () => {
    assert.equal(getFipsPosture().mldsa_validated_module, false);
    assert.equal(getFipsPosture({ probe: false }).mldsa_validated_module, false);
    // The truth is not a probe result: no option flips it.
    assert.equal(mldsaPolicy({ allow_unvalidated_mldsa: true }).validated_module, false);
});
test('probe:false skips both probes and leaves the fields indeterminate', () => {
    const p = getFipsPosture({ probe: false });
    assert.equal(p.ed25519_operational, null);
    assert.equal(p.openssl_operational, null);
});
test('getFipsPosture is deterministic across calls (no timestamps, no nonces)', () => {
    const a = getFipsPosture();
    const b = getFipsPosture();
    assert.deepEqual(a, b);
});
test('formatFipsPosture renders a one-line summary and tolerates junk', () => {
    const line = formatFipsPosture(getFipsPosture());
    assert.ok(line.startsWith(FIPS_MODE_VERSION));
    assert.ok(line.includes('mldsa_validated_module=false'));
    assert.ok(line.includes('openssl_operational='));
    assert.ok(formatFipsPosture(getFipsPosture({ probe: false })).includes('openssl_operational=unprobed'));
    assert.ok(!line.includes('\n'));
    assert.ok(formatFipsPosture(null).includes('malformed'));
});
// ---------------------------------------------------------------------------
// 2. assertClassicalFips over injected postures
// ---------------------------------------------------------------------------
test('assertClassicalFips: ok only when FIPS mode is verifiably active', () => {
    assert.equal(assertClassicalFips({ posture: FIPS_ON }).ok, true);
    assert.equal(assertClassicalFips({ posture: FIPS_ON }).reason, null);
    const off = assertClassicalFips({ posture: FIPS_OFF });
    assert.equal(off.ok, false);
    assert.equal(off.reason, FIPS_REASONS.FIPS_MODE_INACTIVE);
    const unknown = assertClassicalFips({ posture: FIPS_UNKNOWN });
    assert.equal(unknown.ok, false);
    assert.equal(unknown.reason, FIPS_REASONS.FIPS_STATUS_UNAVAILABLE);
});
test('assertClassicalFips refuses a set flag with a dead provider', () => {
    // The measured real-world case: setFips(true) succeeds on a build with no
    // FIPS provider, getFips() returns 1, and every EVP call then fails with
    // ERR_OSSL_EVP_UNSUPPORTED. The flag alone must never read as ok.
    const flagOnly = posture('active', false, false);
    const r = assertClassicalFips({ posture: flagOnly });
    assert.equal(r.ok, false);
    assert.equal(r.reason, FIPS_REASONS.OPENSSL_PROVIDER_NOT_OPERATIONAL);
});
test('assertClassicalFips refuses an unprobed provider under an active flag', () => {
    const r = assertClassicalFips({ posture: posture('active', null, null) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, FIPS_REASONS.OPENSSL_PROVIDER_UNPROBED);
});
test('assertClassicalFips refuses a posture-shaped impostor, never throws', () => {
    for (const junk of [null, 'active', 42, [], {}, { fips_status: 'yes' }, { fips_status: 'active' }]) {
        const r = assertClassicalFips({ posture: junk });
        assert.equal(r.ok, false, `junk posture ${JSON.stringify(junk)} must refuse`);
        assert.equal(r.reason, FIPS_REASONS.MALFORMED_POSTURE);
    }
});
// ---------------------------------------------------------------------------
// 3. mldsaPolicy: the explicit acknowledgment flag
// ---------------------------------------------------------------------------
test('mldsaPolicy refuses under active FIPS without the flag', () => {
    const r = mldsaPolicy({ posture: FIPS_ON });
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.MLDSA_IMPLEMENTATION_UNVALIDATED);
    assert.equal(r.acknowledgment_required, true);
    assert.equal(r.acknowledged, false);
});
test('mldsaPolicy permits under active FIPS with the explicit flag', () => {
    const r = mldsaPolicy({ posture: FIPS_ON, allow_unvalidated_mldsa: true });
    assert.equal(r.permitted, true);
    assert.equal(r.reason, null);
    assert.equal(r.acknowledged, true);
    // Permission is never a validation claim.
    assert.equal(r.validated_module, false);
});
test('mldsaPolicy arms the acknowledgment when the FIPS status is indeterminate', () => {
    const r = mldsaPolicy({ posture: FIPS_UNKNOWN });
    assert.equal(r.acknowledgment_required, true);
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.MLDSA_IMPLEMENTATION_UNVALIDATED);
    assert.equal(mldsaPolicy({ posture: FIPS_UNKNOWN, allow_unvalidated_mldsa: true }).permitted, true);
});
test('mldsaPolicy does not require the flag on a plainly non-FIPS deployment', () => {
    const r = mldsaPolicy({ posture: FIPS_OFF });
    assert.equal(r.acknowledgment_required, false);
    assert.equal(r.permitted, true);
    assert.equal(r.reason, null);
});
test('only the literal true acknowledges', () => {
    for (const truthy of ['true', 1, {}, [], 'yes']) {
        const r = mldsaPolicy({
            posture: FIPS_ON,
            allow_unvalidated_mldsa: truthy,
        });
        assert.equal(r.acknowledged, false, `${JSON.stringify(truthy)} must not acknowledge`);
        assert.equal(r.permitted, false);
        assert.equal(r.reason, FIPS_REASONS.MLDSA_IMPLEMENTATION_UNVALIDATED);
    }
});
test('mldsaPolicy refuses a malformed posture', () => {
    const r = mldsaPolicy({ posture: { nope: true } });
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.MALFORMED_POSTURE);
});
// ---------------------------------------------------------------------------
// 4. checkOperationPolicy matrix
// ---------------------------------------------------------------------------
test('matrix: {Ed25519, ML-DSA-65} x {fips on, off} x {flag on, off}', () => {
    const rows = [
        // Ed25519 is OpenSSL-backed. With a provider that carries it (probe true)
        // it is permitted in both directions; the flag is irrelevant to it.
        { alg: 'Ed25519', fips: FIPS_ON, flag: false, permitted: true, reason: null },
        { alg: 'Ed25519', fips: FIPS_ON, flag: true, permitted: true, reason: null },
        { alg: 'Ed25519', fips: FIPS_OFF, flag: false, permitted: true, reason: null },
        { alg: 'Ed25519', fips: FIPS_OFF, flag: true, permitted: true, reason: null },
        // ML-DSA-65 is JavaScript. Under active FIPS the flag is load-bearing.
        {
            alg: 'ML-DSA-65',
            fips: FIPS_ON,
            flag: false,
            permitted: false,
            reason: FIPS_REASONS.MLDSA_IMPLEMENTATION_UNVALIDATED,
        },
        { alg: 'ML-DSA-65', fips: FIPS_ON, flag: true, permitted: true, reason: null },
        { alg: 'ML-DSA-65', fips: FIPS_OFF, flag: false, permitted: true, reason: null },
        { alg: 'ML-DSA-65', fips: FIPS_OFF, flag: true, permitted: true, reason: null },
    ];
    for (const row of rows) {
        const r = checkOperationPolicy(row.alg, row.fips, { allow_unvalidated_mldsa: row.flag });
        const label = `${row.alg} fips=${row.fips.fips_status} flag=${row.flag}`;
        assert.equal(r.permitted, row.permitted, `${label}: permitted`);
        assert.equal(r.reason, row.reason, `${label}: reason`);
        assert.equal(r.alg, row.alg, `${label}: alg echoed`);
        assert.equal(r.fips_status, row.fips.fips_status, `${label}: status echoed`);
    }
});
test('matrix: the boundary field never calls JavaScript ML-DSA an OpenSSL operation', () => {
    for (const p of [FIPS_ON, FIPS_OFF, FIPS_UNKNOWN]) {
        assert.equal(checkOperationPolicy('ML-DSA-65', p, { allow_unvalidated_mldsa: true }).boundary, 'javascript_outside_any_validated_module');
        assert.equal(checkOperationPolicy('Ed25519', p).boundary, 'openssl_provider');
        assert.equal(checkOperationPolicy('ES256', p).boundary, 'openssl_provider');
        assert.equal(checkOperationPolicy('SHA-256', p).boundary, 'openssl_provider');
    }
});
test('a set flag with a dead provider refuses every OpenSSL-backed algorithm', () => {
    const dead = posture('active', false, false);
    for (const alg of ['Ed25519', 'ES256', 'SHA-256']) {
        const r = checkOperationPolicy(alg, dead);
        assert.equal(r.permitted, false, alg);
        assert.equal(r.reason, FIPS_REASONS.OPENSSL_PROVIDER_NOT_OPERATIONAL, alg);
    }
    // ML-DSA is JavaScript, so a dead OpenSSL provider is not its gate; the
    // acknowledgment is. Keeping these reasons distinct is the point.
    assert.equal(checkOperationPolicy('ML-DSA-65', dead).reason, FIPS_REASONS.MLDSA_IMPLEMENTATION_UNVALIDATED);
    assert.equal(checkOperationPolicy('ML-DSA-65', dead, { allow_unvalidated_mldsa: true }).permitted, true);
});
test('an unprobed provider under an active flag refuses OpenSSL-backed algorithms', () => {
    const unprobed = posture('active', null, null);
    for (const alg of ['Ed25519', 'ES256', 'SHA-256']) {
        const r = checkOperationPolicy(alg, unprobed);
        assert.equal(r.permitted, false, alg);
        assert.equal(r.reason, FIPS_REASONS.OPENSSL_PROVIDER_UNPROBED, alg);
    }
});
test('Ed25519 under active FIPS refuses when the provider has no Ed25519', () => {
    // Provider is alive (SHA-256 works) but carries no Ed25519: the exact shape
    // of an OpenSSL 3.0/3.1-era FIPS provider.
    const noEd = posture('active', false, true);
    const r = checkOperationPolicy('Ed25519', noEd);
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.ED25519_UNAVAILABLE_IN_PROVIDER);
    assert.equal(r.boundary, 'openssl_provider');
    // The acknowledgment flag is for ML-DSA and must not unlock this.
    assert.equal(checkOperationPolicy('Ed25519', noEd, { allow_unvalidated_mldsa: true }).permitted, false);
});
test('Ed25519 under active FIPS refuses when Ed25519 support was never probed', () => {
    // Provider alive, Ed25519 support unknown: indeterminate never authorizes.
    const r = checkOperationPolicy('Ed25519', posture('active', null, true));
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.ED25519_PROVIDER_SUPPORT_UNKNOWN);
});
test('the OpenSSL 3.0.x trap: Ed25519 works, and the certificate still says no', () => {
    // OpenSSL 3.0.x registers Ed25519 with fips=yes, so the probe passes, while
    // CMVP #4282 (OpenSSL 3.0.8/3.0.9) lists Ed25519 as non-Approved. A module
    // that trusted the probe alone would authorize signing outside the boundary.
    const trap = posture('active', /* ed25519 works */ true, true, /* declared outside */ false);
    const r = checkOperationPolicy('Ed25519', trap);
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.ED25519_OUTSIDE_VALIDATED_BOUNDARY);
    // Neither acknowledgment flag unlocks it: this one is a certificate fact.
    assert.equal(checkOperationPolicy('Ed25519', trap, { allow_unvalidated_mldsa: true }).permitted, false);
});
test('Ed25519 under active FIPS refuses while the boundary is undeclared', () => {
    const undeclared = posture('active', true, true, null);
    const r = checkOperationPolicy('Ed25519', undeclared);
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.ED25519_BOUNDARY_UNDECLARED);
    // Declaring it in the boundary is what permits it, and only that.
    assert.equal(checkOperationPolicy('Ed25519', posture('active', true, true, true)).permitted, true);
});
test('the boundary declaration only gates Ed25519, and only under active FIPS', () => {
    // ES256 and SHA-256 are Approved in every certificate documented, so an
    // undeclared Ed25519 boundary must not block them.
    for (const alg of ['ES256', 'SHA-256']) {
        assert.equal(checkOperationPolicy(alg, posture('active', true, true, null)).permitted, true, alg);
    }
    // And a non-FIPS deployment is untouched by any of it.
    assert.equal(checkOperationPolicy('Ed25519', posture('inactive', true, true, null)).permitted, true);
});
test('getFipsPosture leaves the boundary undeclared unless the operator declares it', () => {
    assert.equal(getFipsPosture().ed25519_in_validated_boundary, null);
    assert.equal(getFipsPosture({ ed25519InValidatedBoundary: true }).ed25519_in_validated_boundary, true);
    assert.equal(getFipsPosture({ ed25519InValidatedBoundary: false }).ed25519_in_validated_boundary, false);
});
test('an unprobed posture does not block anything when FIPS mode is not active', () => {
    for (const status of ['inactive', 'unavailable']) {
        for (const alg of ['Ed25519', 'ES256', 'SHA-256']) {
            assert.equal(checkOperationPolicy(alg, posture(status, null, null)).permitted, true, `${alg} under ${status}`);
        }
    }
});
test('ES256 and SHA-256 are permitted whenever the OpenSSL path is alive', () => {
    for (const alg of ['ES256', 'SHA-256']) {
        for (const p of [FIPS_ON, FIPS_OFF, FIPS_UNKNOWN, posture('active', false, true)]) {
            const r = checkOperationPolicy(alg, p);
            assert.equal(r.permitted, true, `${alg} under ${p.fips_status}`);
            assert.equal(r.reason, null);
        }
    }
});
test('an algorithm outside the closed registry never authorizes', () => {
    for (const alg of ['Ed448', 'RSA', 'ml-dsa-65', 'ed25519', '', null, undefined, 7, {}]) {
        const r = checkOperationPolicy(alg, FIPS_OFF);
        assert.equal(r.permitted, false, `${JSON.stringify(alg)} must refuse`);
        assert.equal(r.reason, FIPS_REASONS.UNKNOWN_ALGORITHM);
        assert.equal(r.boundary, null);
    }
});
test('checkOperationPolicy refuses a malformed posture for a known algorithm', () => {
    const r = checkOperationPolicy('Ed25519', { fips_status: 'active' });
    assert.equal(r.permitted, false);
    assert.equal(r.reason, FIPS_REASONS.MALFORMED_POSTURE);
});
test('checkOperationPolicy with no posture reads the live process and never throws', () => {
    for (const alg of FIPS_POLICY_ALGORITHMS) {
        assert.doesNotThrow(() => checkOperationPolicy(alg));
    }
    // On a non-FIPS host every registry algorithm is permitted with no flag.
    if (readFipsStatus() === 'inactive') {
        for (const alg of FIPS_POLICY_ALGORITHMS) {
            assert.equal(checkOperationPolicy(alg).permitted, true, `${alg} on a non-FIPS host`);
        }
    }
});
// ---------------------------------------------------------------------------
// 5. The real failure mode, observed in a child process
// ---------------------------------------------------------------------------
test('the flag-set-but-provider-dead state is real, and maps to the named refusal', () => {
    // Turn FIPS mode on in a CHILD process (never this one, which would poison
    // every later test) and record what the runtime actually does. On a Node
    // built without a configured FIPS provider, setFips(true) succeeds and
    // getFips() returns 1 while SHA-256 fails with ERR_OSSL_EVP_UNSUPPORTED.
    const script = [
        'const c=require("crypto");',
        'let set=true; try{c.setFips(true);}catch{set=false;}',
        'let fips=null; try{fips=c.getFips();}catch{}',
        'let sha=false; try{sha=c.createHash("sha256").update("x").digest("hex").length===64;}catch{}',
        'process.stdout.write(JSON.stringify({set,fips,sha}));',
    ].join('');
    let observed;
    try {
        observed = JSON.parse(execFileSync(process.execPath, ['-e', script], { encoding: 'utf8' }));
    }
    catch {
        return; // cannot spawn here; nothing to assert about the host
    }
    if (!observed.set || observed.fips !== 1) {
        return; // this host refuses to enter FIPS mode at all; nothing to observe
    }
    const observedPosture = posture('active', false, observed.sha);
    if (observed.sha === false) {
        // The dangerous state: flag on, cryptography dead. Must never read as ok.
        const r = assertClassicalFips({ posture: observedPosture });
        assert.equal(r.ok, false);
        assert.equal(r.reason, FIPS_REASONS.OPENSSL_PROVIDER_NOT_OPERATIONAL);
        assert.equal(checkOperationPolicy('SHA-256', observedPosture).permitted, false);
    }
    else {
        // A host with a live FIPS provider: SHA-256 is permitted, and Ed25519 is
        // decided by its own probe rather than by the flag.
        assert.equal(assertClassicalFips({ posture: observedPosture }).ok, true);
        assert.equal(checkOperationPolicy('SHA-256', observedPosture).permitted, true);
        assert.equal(checkOperationPolicy('Ed25519', observedPosture).reason, FIPS_REASONS.ED25519_UNAVAILABLE_IN_PROVIDER);
    }
});
test('probe results are memoized per FIPS status and can be reset', () => {
    resetFipsProbeCache();
    const a = getFipsPosture();
    const b = getFipsPosture();
    assert.deepEqual(a, b);
    resetFipsProbeCache();
    assert.deepEqual(getFipsPosture(), a);
});
test('every refusal reason is a named, stable string', () => {
    for (const [key, value] of Object.entries(FIPS_REASONS)) {
        assert.equal(typeof value, 'string', `${key} must be a string`);
        assert.match(value, /^[a-z0-9_]+$/, `${key} must be snake_case`);
    }
    assert.equal(Object.isFrozen(FIPS_REASONS), true);
    assert.equal(Object.isFrozen(FIPS_POLICY_ALGORITHMS), true);
});
