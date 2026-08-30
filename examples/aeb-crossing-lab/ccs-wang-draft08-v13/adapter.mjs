// SPDX-License-Identifier: Apache-2.0
/**
 * Independent CCS draft-08 v1.3 adapter for the AEB Crossing Lab.
 *
 * This one-file bundle deliberately has no package or network dependency. It
 * verifies the exact 22-field receipt under a relying-party-pinned Ed25519
 * key, keeps CCS allow/deny/escalate semantics intact, and maps only the
 * signed tool plus full parameter digest to one executor-owned CAID action.
 */
import crypto from 'node:crypto';

const ADAPTER_ID = 'native:ccs-draft08-v1.3-ed25519';
const ADAPTER_VERSION = '1.0.0';
const CONFIG_VERSION = 'AEB-CCS-DRAFT08-V1.3-CONFIG-v1';
const ROOT_VERSION = 'AEB-CCS-DRAFT08-V1.3-ROOT-v1';
const MAPPING_VERSION = 'AEB-CCS-DRAFT08-V1.3-TOOL-ACTION-MAPPING-v1';
const MAPPER_ID = 'mapper:ccs-draft08-v1.3-tool-action-v1';
const SOURCE_LOCK = 'draft-correctover-ccs-08-v1.3-fbac2a025f11baec';
const ACTION_TYPE = 'agent.tool-invocation.1';
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const RECEIPT_KEYS = [
  'trace_id', 'verdict', 'timestamp', 'tool', 'params_hash', 'rule_summary',
  'receipt', 'verified_at', 'block_reason', 'request_hash', 'response_hash',
  'runtime_context_hash', 'action', 'config_hash', 'issuer', 'audience',
  'nonce', 'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
];
const CONFIG_KEYS = [
  '@version', 'evidence_role', 'subject', 'issuer', 'audience', 'action_type',
  'allowed_tools', 'max_receipt_age_seconds', 'max_clock_skew_seconds',
  'deployment_scope',
];
const ROOT_KEYS = [
  '@version', 'issuer', 'key_id', 'algorithm', 'public_key_raw_base64',
  'public_key_fingerprint_sha256_16',
];
const OMITTED_NONMATERIAL_FIELDS = [
  'trace_id', 'verdict', 'timestamp', 'params_hash', 'rule_summary', 'receipt',
  'verified_at', 'block_reason', 'request_hash', 'response_hash',
  'runtime_context_hash', 'config_hash', 'issuer', 'audience', 'nonce',
  'sequence', 'issued_at', 'expires_at', 'max_clock_skew', 'signature',
];
const EXPECTED_DEFINITION = Object.freeze({
  '@version': MAPPING_VERSION,
  source: SOURCE_LOCK,
  source_media_type: 'application/x-ccs-receipt+json',
  projection: 'ccs-v13-signed-tool-and-full-params-digest-v1',
  action_type: ACTION_TYPE,
  suite: 'jcs-sha256',
  definitions: [{
    action_type: ACTION_TYPE,
    required_fields: [
      { name: 'action_type', type: 'string' },
      { name: 'parameters', type: 'object' },
    ],
    optional_fields: [],
  }],
});

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  if (!isObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (isObject(value)) {
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new TypeError('symbol member refused');
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new TypeError('non-JSON value');
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(jcs(value), 'utf8').digest('hex')}`;
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizedStatus(status) {
  return {
    checked_at: status?.checked_at,
    expires_at: status?.expires_at,
    revocation_checked: status?.revocation_checked,
    revoked: status?.revoked,
    consumed: status?.consumed,
    unavailable: status?.unavailable === true,
  };
}

function fallback(input, config, reason) {
  return {
    native_verification: 'FAILED',
    acceptance: 'REJECTED',
    evidence_digest: digest(input?.artifact ?? null),
    status_digest: digest(normalizedStatus(input?.status)),
    evidence_role: config?.evidence_role ?? 'machine-policy-decision',
    subject: isObject(config?.subject)
      ? { id: String(config.subject.id), kind: String(config.subject.kind) }
      : { id: 'system:ccs-draft08-unresolved', kind: 'system' },
    replay_unit: digest({ protocol: SOURCE_LOCK, malformed_artifact: input?.artifact ?? null }),
    reasons: [reason],
  };
}

function validHttpsUri(value) {
  if (typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' && parsed.hash === '';
  } catch {
    return false;
  }
}

function parseConfig(value) {
  if (!exactKeys(value, CONFIG_KEYS)
      || value['@version'] !== CONFIG_VERSION
      || value.evidence_role !== 'machine-policy-decision'
      || !exactKeys(value.subject, ['id', 'kind'])
      || typeof value.subject.id !== 'string' || value.subject.kind !== 'system'
      || !validHttpsUri(value.issuer) || !validHttpsUri(value.audience)
      || value.action_type !== ACTION_TYPE
      || !Array.isArray(value.allowed_tools) || value.allowed_tools.length === 0
      || value.allowed_tools.some((tool, index) => typeof tool !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/.test(tool)
        || (index > 0 && value.allowed_tools[index - 1] >= tool))
      || !Number.isSafeInteger(value.max_receipt_age_seconds) || value.max_receipt_age_seconds <= 0
      || !Number.isSafeInteger(value.max_clock_skew_seconds) || value.max_clock_skew_seconds < 0
      || value.deployment_scope !== 'pinned-ed25519-issuer') return null;
  return value;
}

function decodeCanonicalBase64(value, length) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== length || decoded.toString('base64') !== value) return null;
  return decoded;
}

function parseRoot(value, config) {
  if (!exactKeys(value, ROOT_KEYS)
      || value['@version'] !== ROOT_VERSION
      || value.issuer !== config.issuer
      || typeof value.key_id !== 'string' || value.key_id.length === 0
      || value.algorithm !== 'Ed25519'
      || typeof value.public_key_fingerprint_sha256_16 !== 'string'
      || !/^[0-9a-f]{16}$/.test(value.public_key_fingerprint_sha256_16)) return null;
  const raw = decodeCanonicalBase64(value.public_key_raw_base64, 32);
  if (!raw || sha256Hex(raw).slice(0, 16) !== value.public_key_fingerprint_sha256_16) return null;
  return raw;
}

function validDigest(value, optional = false) {
  return (optional && value === '')
    || (typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value));
}

function parseReceipt(value) {
  if (!exactKeys(value, RECEIPT_KEYS)
      || typeof value.trace_id !== 'string' || !/^[0-9a-f]{16}$/.test(value.trace_id)
      || !['allow', 'deny', 'escalate'].includes(value.verdict)
      || !Number.isFinite(value.timestamp) || value.timestamp < 0
      || typeof value.tool !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/.test(value.tool)
      || typeof value.params_hash !== 'string' || !/^[0-9a-f]{16}$/.test(value.params_hash)
      || typeof value.rule_summary !== 'string' || value.rule_summary.length === 0
      || typeof value.receipt !== 'string' || !/^[0-9a-f]{32}$/.test(value.receipt)
      || !Number.isFinite(value.verified_at) || value.verified_at < 0
      || typeof value.block_reason !== 'string'
      || !validDigest(value.request_hash) || !validDigest(value.response_hash, true)
      || !validDigest(value.runtime_context_hash, true) || !validDigest(value.config_hash)
      || !validHttpsUri(value.issuer) || !validHttpsUri(value.audience)
      || typeof value.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(value.nonce)
      || !Number.isSafeInteger(value.sequence) || value.sequence < 0
      || !Number.isFinite(value.issued_at) || value.issued_at < 0
      || !Number.isFinite(value.expires_at) || value.expires_at < 0
      || !Number.isFinite(value.max_clock_skew) || value.max_clock_skew < 0
      || typeof value.signature !== 'string' || !/^[0-9a-f]{128}$/.test(value.signature)
      || (value.verdict === 'allow' ? value.block_reason !== '' : value.block_reason.length === 0)) return null;
  const action = new RegExp(`^ccs:tool-invoke:${value.tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:([0-9a-f]{64})$`).exec(value.action);
  if (!action || action[1].slice(0, 16) !== value.params_hash) return null;
  return value;
}

function verifySignature(receipt, rawPublicKey) {
  try {
    const signature = Buffer.from(receipt.signature, 'hex');
    if (signature.length !== 64) return false;
    const body = { ...receipt };
    delete body.signature;
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
      format: 'der',
      type: 'spki',
    });
    return key.asymmetricKeyType === 'ed25519'
      && crypto.verify(null, Buffer.from(jcs(body), 'utf8'), key, signature);
  } catch {
    return false;
  }
}

function verifyNative(input) {
  const config = parseConfig(input?.adapter_config);
  let result;
  try {
    result = fallback(input, config, 'ccs:draft08_unverified');
  } catch {
    result = {
      native_verification: 'FAILED', acceptance: 'REJECTED',
      evidence_digest: digest(null), status_digest: digest(normalizedStatus(null)),
      evidence_role: 'machine-policy-decision',
      subject: { id: 'system:ccs-draft08-unresolved', kind: 'system' },
      replay_unit: digest({ protocol: SOURCE_LOCK, malformed_artifact: null }),
      reasons: ['ccs:draft08_malformed_input'],
    };
  }
  if (!config) {
    result.reasons = ['ccs:draft08_config_invalid'];
    return result;
  }
  if (!Array.isArray(input?.trust_roots) || input.trust_roots.length !== 1) {
    result.reasons = ['ccs:draft08_trust_root_invalid'];
    return result;
  }
  const rawPublicKey = parseRoot(input.trust_roots[0], config);
  if (!rawPublicKey) {
    result.reasons = ['ccs:draft08_trust_root_invalid'];
    return result;
  }
  const receipt = parseReceipt(input.artifact);
  if (!receipt) {
    result.reasons = ['ccs:draft08_artifact_malformed'];
    return result;
  }
  result.replay_unit = digest({ protocol: SOURCE_LOCK, issuer: receipt.issuer, nonce: receipt.nonce });
  if (!verifySignature(receipt, rawPublicKey)) {
    result.reasons = ['ccs:draft08_signature_invalid'];
    return result;
  }
  result.native_verification = 'VERIFIED';
  if (receipt.issuer !== config.issuer) {
    result.reasons = ['ccs:draft08_untrusted_issuer'];
    return result;
  }
  if (receipt.audience !== config.audience) {
    result.reasons = ['ccs:draft08_audience_mismatch'];
    return result;
  }
  if (!config.allowed_tools.includes(receipt.tool)) {
    result.reasons = ['ccs:draft08_tool_not_pinned'];
    return result;
  }
  if (receipt.max_clock_skew > config.max_clock_skew_seconds
      || receipt.expires_at <= receipt.issued_at
      || receipt.timestamp < receipt.issued_at
      || receipt.verified_at < receipt.issued_at
      || receipt.timestamp > receipt.expires_at + receipt.max_clock_skew
      || receipt.verified_at > receipt.expires_at + receipt.max_clock_skew) {
    result.reasons = ['ccs:draft08_time_bounds_invalid'];
    return result;
  }
  const nowSeconds = Date.parse(input.now) / 1000;
  if (!Number.isFinite(nowSeconds)) {
    result.acceptance = 'INDETERMINATE';
    result.reasons = ['ccs:draft08_current_time_invalid'];
    return result;
  }
  if (nowSeconds > receipt.expires_at + receipt.max_clock_skew
      || nowSeconds < receipt.issued_at - receipt.max_clock_skew
      || nowSeconds - receipt.issued_at > config.max_receipt_age_seconds) {
    result.reasons = ['ccs:draft08_receipt_not_fresh'];
    return result;
  }
  const status = normalizedStatus(input.status);
  if (status.unavailable || status.revocation_checked !== true) {
    result.acceptance = 'INDETERMINATE';
    result.reasons = [status.unavailable ? 'status_unavailable' : 'status_not_authenticated'];
    return result;
  }
  if (status.revoked || status.consumed) {
    result.reasons = [status.revoked ? 'evidence_revoked' : 'evidence_consumed'];
    return result;
  }
  result.acceptance = receipt.verdict === 'allow'
    ? 'ACCEPTED' : receipt.verdict === 'deny' ? 'REJECTED' : 'INDETERMINATE';
  result.reasons = receipt.verdict === 'allow' ? [] : [`ccs:${receipt.verdict}`];
  return result;
}

function profileIsPinned(profile) {
  return isObject(profile)
    && profile.version === MAPPING_VERSION
    && profile.registry_entry_ref === 'mapping:ccs-draft08-v13-tool-action'
    && profile.mapper_id === MAPPER_ID
    && exactKeys(profile.resolver, ['id', 'version', 'implementation_digest'])
    && profile.resolver.id === MAPPER_ID
    && profile.resolver.version === '1.0.0'
    && profile.resolver.implementation_digest === digest({ implementation: MAPPER_ID, version: '1.0.0' })
    && isObject(profile.semantic_equivalence)
    && profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
    && profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
    && Array.isArray(profile.semantic_equivalence.omitted_material_fields)
    && profile.semantic_equivalence.omitted_material_fields.length === 0
    && jcs(profile.semantic_equivalence.omitted_nonmaterial_fields) === jcs(OMITTED_NONMATERIAL_FIELDS)
    && jcs(profile.definition) === jcs(EXPECTED_DEFINITION);
}

function canonicalAction(value) {
  if (!exactKeys(value, ['action_type', 'parameters']) || value.action_type !== ACTION_TYPE
      || !exactKeys(value.parameters, ['arguments', 'tool'])
      || typeof value.parameters.tool !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/.test(value.parameters.tool)
      || !isObject(value.parameters.arguments)) return null;
  jcs(value.parameters.arguments);
  return value;
}

function computeCaid(action) {
  const canonical = jcs(action);
  const bytes = crypto.createHash('sha256').update(canonical, 'utf8').digest();
  return {
    caid: `caid:1:${ACTION_TYPE}:jcs-sha256:${bytes.toString('base64url')}`,
    digest: `sha256:${bytes.toString('hex')}`,
  };
}

function mapAction(input) {
  try {
    if (!profileIsPinned(input?.profile)) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
    }
    const native = verifyNative(input);
    if (native.native_verification !== 'VERIFIED') {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_verification_required'] };
    }
    // Mapping and relying-party acceptance are independent AEB axes. A fresh
    // allow may still map while authenticated status is temporarily
    // unavailable; the evaluator then preserves an INDETERMINATE result.
    // Native deny and escalate dispositions never become mappable admission.
    if (input.artifact.verdict !== 'allow') {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['accepted_allow_statement_required'] };
    }
    const action = canonicalAction(input.expected_action);
    if (!action) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
    }
    const fullParamsHash = sha256Hex(jcs(action.parameters.arguments));
    const expectedNativeAction = `ccs:tool-invoke:${action.parameters.tool}:${fullParamsHash}`;
    const actionDigest = digest(action);
    if (input.artifact.tool !== action.parameters.tool
        || input.artifact.params_hash !== fullParamsHash.slice(0, 16)
        || input.artifact.action !== expectedNativeAction) {
      return {
        mapping: 'MISMATCH', caid: null, action_digest: actionDigest,
        reasons: ['ccs:draft08_exact_action_projection_mismatch'],
      };
    }
    const computed = computeCaid(action);
    return { mapping: 'MATCH', caid: computed.caid, action_digest: computed.digest, reasons: [] };
  } catch {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ccs:draft08_mapping_error'] };
  }
}

export default Object.freeze({
  id: ADAPTER_ID,
  version: ADAPTER_VERSION,
  verifyNative,
  mapAction,
});
