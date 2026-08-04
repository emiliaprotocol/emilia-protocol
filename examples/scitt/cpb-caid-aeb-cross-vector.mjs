// SPDX-License-Identifier: Apache-2.0
// Generated from cpb-caid-aeb-cross-vector.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Candidate CPB -> CAID -> AEB cross-vector.
//
// CPB typed-reference verification establishes only content binding under a
// resolved digest context. CAID independently establishes that the material
// action recomputes to the claimed identifier. AEB evidence satisfaction and
// Gate authorization remain separate decisions.
import crypto from 'node:crypto';
import { canonicalize, computeCaid, verifyCaid, } from '../../caid/impl/js/caid.mjs';
const ACTION_DEFINITION = {
    action_type: 'payment.release.1',
    required_fields: [
        { name: 'amount', type: 'amount-string' },
        { name: 'currency', type: 'enum', values: ['USD'] },
        { name: 'beneficiary_account', type: 'digest' },
        { name: 'payment_instruction_id', type: 'string' },
    ],
    optional_fields: [{ name: 'memo', type: 'string' }],
};
export const CPB_CAID_CONTEXT = Object.freeze({
    digest_alg: 'SHA-256',
    canonicalization: 'jcs-sha256',
    preimage: 'full-material-action-object',
    representation: 'lowercase-hex',
    reference: 'draft-schrock-canonical-action-identifier',
    status: 'candidate-cpb-artifact-type-entry',
});
function isPlainObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function sameDigestContext(actual) {
    return isPlainObject(actual)
        && actual.digest_alg === CPB_CAID_CONTEXT.digest_alg
        && actual.canonicalization === CPB_CAID_CONTEXT.canonicalization
        && actual.preimage === CPB_CAID_CONTEXT.preimage
        && actual.representation === CPB_CAID_CONTEXT.representation;
}
function verifyCpbTypedReference({ reference, artifact, registry }) {
    if (!isPlainObject(reference) || typeof reference.type !== 'string') {
        return { binding: 'INDETERMINATE', reasons: ['typed_reference_required'] };
    }
    const context = isPlainObject(registry) ? registry[reference.type] : null;
    if (!sameDigestContext(context) || reference.digest_alg !== context.digest_alg) {
        return { binding: 'INDETERMINATE', reasons: ['digest_context_unresolved'] };
    }
    if (typeof reference.digest !== 'string' || !/^[0-9a-f]{64}$/.test(reference.digest)) {
        return { binding: 'FAILED', reasons: ['invalid_digest_representation'] };
    }
    const encoded = canonicalize(artifact);
    if (!encoded.ok)
        return { binding: 'FAILED', reasons: ['artifact_not_canonicalizable'] };
    const recomputed = crypto.createHash('sha256')
        .update(Buffer.from(encoded.canonical, 'utf8'))
        .digest('hex');
    return recomputed === reference.digest
        ? { binding: 'VERIFIED', reasons: [] }
        : { binding: 'FAILED', reasons: ['digest_mismatch'] };
}
export function buildCpbCaidAebVector() {
    const artifact = {
        action_type: 'payment.release.1',
        amount: '75000.00',
        currency: 'USD',
        beneficiary_account: `sha256:${'4a'.repeat(32)}`,
        payment_instruction_id: 'pi_scitt_cpb_001',
        memo: 'approved supplier invoice',
    };
    const computed = computeCaid(artifact, {
        suite: 'jcs-sha256',
        definitions: [ACTION_DEFINITION],
    });
    if (!('caid' in computed) || typeof computed.digest !== 'string') {
        const reasons = 'refusals' in computed ? computed.refusals.join(',') : 'missing_digest';
        throw new Error(`candidate_vector_invalid:${reasons}`);
    }
    return {
        '@version': 'EP-CPB-CAID-AEB-CROSS-VECTOR-v1',
        status: 'candidate-emilia-owned-composition-vector',
        artifact,
        caid: computed.caid,
        reference: {
            type: 'caid-action-object',
            digest_alg: 'SHA-256',
            digest: computed.digest.slice('sha256:'.length),
        },
        registry: {
            'caid-action-object': { ...CPB_CAID_CONTEXT },
        },
        aeb_native_result: 'SATISFIED',
    };
}
export function evaluateCpbCaidAebComposition(vector) {
    const cpb = verifyCpbTypedReference(vector);
    const caid = verifyCaid(vector.artifact, vector.caid, {
        definitions: [ACTION_DEFINITION],
    });
    const caidMatch = caid.valid ? 'MATCH' : 'MISMATCH';
    let satisfaction = 'INDETERMINATE';
    if (cpb.binding === 'FAILED' || caidMatch === 'MISMATCH')
        satisfaction = 'UNSATISFIED';
    else if (cpb.binding === 'VERIFIED' && caidMatch === 'MATCH') {
        satisfaction = vector.aeb_native_result === 'SATISFIED'
            ? 'SATISFIED'
            : 'INDETERMINATE';
    }
    return {
        '@version': 'EP-CPB-CAID-AEB-CROSS-RESULT-v1',
        cpb_binding: cpb.binding,
        caid_match: caidMatch,
        aeb_evidence_satisfaction: satisfaction,
        execution_authorization: 'NOT_EVALUATED',
        reasons: [...cpb.reasons, ...caid.reasons],
        nonclaims: [
            'CPB content binding is not issuer authority or authorization.',
            'CAID matching is not native artifact verification or authorization.',
            'AEB evidence satisfaction is not Gate authorization or execution.',
        ],
    };
}
function main() {
    const result = evaluateCpbCaidAebComposition(buildCpbCaidAebVector());
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.cpb_binding !== 'VERIFIED'
        || result.caid_match !== 'MATCH'
        || result.aeb_evidence_satisfaction !== 'SATISFIED')
        process.exit(1);
}
if (import.meta.url === `file://${process.argv[1]}`)
    main();
export { verifyCpbTypedReference };
