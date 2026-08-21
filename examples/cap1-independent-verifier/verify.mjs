import { createHash } from 'node:crypto';

const ROOT_KEYS = new Set([
  'profile', 'subject', 'strata', 'integrity', 'absence_assertions',
  'producer', 'as_of',
]);
const SUBJECT_KEYS = new Set(['kind', 'ref', 'digest']);
const DIGEST_KEYS = new Set(['algorithm', 'value']);
const STRATUM_KEYS = new Set([
  'id', 'population', 'basis', 'eligible', 'examined', 'unexamined',
  'supports',
]);
const BASIS_KEYS = new Set([
  'kind', 'catalogue_digest', 'catalogue_version',
  'enumeration_method', 'note',
]);
const UNEXAMINED_KEYS = new Set([
  'unit', 'disposition', 'detail', 'withheld_digest',
]);
const ABSENCE_KEYS = new Set(['assertion', 'stratum', 'qualifier']);
const INTEGRITY_KEYS = new Set([
  'complete', 'statement', 'uncapped_verdict', 'capped_to', 'unaccounted',
]);
const PRODUCER_KEYS = new Set(['name', 'version', 'policy']);

const BASIS_KINDS = new Set(['catalogue', 'enumeration', 'declared']);
const DISPOSITIONS = new Set([
  'not_applicable',
  'disabled_by_policy',
  'unsupported_input',
  'resource_exhausted',
  'failed',
  'unavailable',
  'out_of_scope',
  'withheld',
]);
const INCOMPLETE_DISPOSITIONS = new Set([
  'failed', 'resource_exhausted', 'unavailable',
]);
const HEX_DIGEST = /^[0-9a-f]{32,128}$/;
const STRATUM_ID = /^[a-z0-9][a-z0-9._-]*$/;
const RULE_PRIORITY = [
  'R0-shape',
  'R5-counts-well-formed',
  'R1-no-silent-remainder',
  'R2-closed-disposition',
  'R3-withholding-digest-bound',
  'R4-denominator-basis',
  'R6-absence-is-scoped',
  'R7-incomplete-not-clean',
  'R8-supports-bounds-citation',
];

export const CAP1_SOURCE_LOCK = Object.freeze({
  specification: 'draft-hillier-coverage-attestation-00',
  source_repository: 'https://github.com/Certisyn-Inc/certisyn-drafts',
  source_commit: '0980d3201aa2caab3cbad5c6e9bc99b422370b43',
  specification_sha256: '7a9eeb1fbdb1fee95697622546d2ae7efba762fff193d6ee34765233539ac353',
  schema_sha256: '4453f216089543780bfecc4295cc4a61462fdc585b88d1e35b7d1aba79716b4a',
  observed_vector_manifest_sha256: '170aa81efc74c5278a2fb6e3bcc22bc91fb1706e9fb8faf1ce6d575e5ce3d965',
});

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function onlyKeys(value, keys) {
  return object(value) && Object.keys(value).every((key) => keys.has(key));
}

function stringOrNull(value) {
  return value === null || typeof value === 'string';
}

function stringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function push(problemMap, rule, path, detail) {
  const entries = problemMap.get(rule) ?? [];
  entries.push({ path, detail });
  problemMap.set(rule, entries);
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (object(value)) {
    const entries = Object.keys(value).sort().map((key) => {
      if (value[key] === undefined) throw new TypeError('undefined property');
      return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
    });
    return `{${entries.join(',')}}`;
  }
  throw new TypeError('value is not JSON-compatible');
}

export function cap1ObjectDigest(document) {
  return `sha256:${createHash('sha256').update(canonicalJson(document), 'utf8').digest('hex')}`;
}

function checkDigestObject(value, problems, path) {
  if (!object(value)
      || !onlyKeys(value, DIGEST_KEYS)
      || typeof value.algorithm !== 'string'
      || typeof value.value !== 'string'
      || !HEX_DIGEST.test(value.value)) {
    push(problems, 'R0-shape', path, 'digest must match the normative schema');
  }
}

function checkShape(document, problems) {
  if (!object(document)) {
    push(problems, 'R0-shape', '$', 'document must be an object');
    return;
  }
  if (!onlyKeys(document, ROOT_KEYS)) {
    push(problems, 'R0-shape', '$', 'unknown top-level property');
  }
  if (document.profile !== 'cap/1') {
    push(problems, 'R0-shape', '$.profile', 'profile must be cap/1');
  }

  const subject = document.subject;
  if (!object(subject)
      || !onlyKeys(subject, SUBJECT_KEYS)
      || typeof subject.kind !== 'string'
      || typeof subject.ref !== 'string') {
    push(problems, 'R0-shape', '$.subject', 'subject must contain only string kind and ref, plus an optional digest');
  } else if ('digest' in subject) {
    checkDigestObject(subject.digest, problems, '$.subject.digest');
  }

  if (!Array.isArray(document.strata) || document.strata.length === 0) {
    push(problems, 'R0-shape', '$.strata', 'strata must be a non-empty array');
  } else {
    const ids = new Set();
    for (const [index, stratum] of document.strata.entries()) {
      const path = `$.strata[${index}]`;
      if (!object(stratum) || !onlyKeys(stratum, STRATUM_KEYS)) {
        push(problems, 'R0-shape', path, 'stratum contains an unknown property or is not an object');
        continue;
      }
      if (typeof stratum.id !== 'string' || !STRATUM_ID.test(stratum.id)) {
        push(problems, 'R0-shape', `${path}.id`, 'stratum id does not match the normative schema');
      } else if (ids.has(stratum.id)) {
        push(problems, 'R0-shape', `${path}.id`, 'stratum ids must be unique');
      } else {
        ids.add(stratum.id);
      }
      if (typeof stratum.population !== 'string') {
        push(problems, 'R0-shape', `${path}.population`, 'population is required and must be a string');
      }
      if (!object(stratum.basis) || !onlyKeys(stratum.basis, BASIS_KEYS)) {
        push(problems, 'R0-shape', `${path}.basis`, 'basis must be an object containing only schema properties');
      } else {
        for (const key of ['catalogue_digest', 'catalogue_version', 'enumeration_method', 'note']) {
          if (key in stratum.basis && typeof stratum.basis[key] !== 'string') {
            push(problems, 'R0-shape', `${path}.basis.${key}`, `${key} must be a string`);
          }
        }
      }
      if (!Array.isArray(stratum.unexamined)) {
        push(problems, 'R0-shape', `${path}.unexamined`, 'unexamined is required and must be an array');
      } else {
        for (const [unitIndex, entry] of stratum.unexamined.entries()) {
          const unitPath = `${path}.unexamined[${unitIndex}]`;
          if (!object(entry) || !onlyKeys(entry, UNEXAMINED_KEYS)) {
            push(problems, 'R0-shape', unitPath, 'unexamined entry contains an unknown property or is not an object');
            continue;
          }
          if ('detail' in entry && typeof entry.detail !== 'string') {
            push(problems, 'R0-shape', `${unitPath}.detail`, 'detail must be a string');
          }
          if ('withheld_digest' in entry
              && (typeof entry.withheld_digest !== 'string'
                || !HEX_DIGEST.test(entry.withheld_digest))) {
            push(problems, 'R3-withholding-digest-bound', `${unitPath}.withheld_digest`, 'withheld digest must be 32 to 128 lowercase hexadecimal characters');
          }
        }
      }
      if ('supports' in stratum && !stringArray(stratum.supports)) {
        push(problems, 'R0-shape', `${path}.supports`, 'supports must be an array of strings');
      }
    }
  }

  if ('absence_assertions' in document) {
    if (!Array.isArray(document.absence_assertions)) {
      push(problems, 'R0-shape', '$.absence_assertions', 'absence_assertions must be an array');
    } else {
      for (const [index, assertion] of document.absence_assertions.entries()) {
        const path = `$.absence_assertions[${index}]`;
        if (!object(assertion) || !onlyKeys(assertion, ABSENCE_KEYS)) {
          push(problems, 'R0-shape', path, 'absence assertion contains an unknown property or is not an object');
          continue;
        }
        if (typeof assertion.assertion !== 'string') {
          push(problems, 'R0-shape', `${path}.assertion`, 'assertion is required and must be a string');
        }
        if ('qualifier' in assertion && typeof assertion.qualifier !== 'string') {
          push(problems, 'R0-shape', `${path}.qualifier`, 'qualifier must be a string');
        }
      }
    }
  }

  const integrity = document.integrity;
  if (!object(integrity)
      || !onlyKeys(integrity, INTEGRITY_KEYS)
      || typeof integrity.complete !== 'boolean'
      || typeof integrity.statement !== 'string') {
    push(problems, 'R0-shape', '$.integrity', 'integrity must contain only schema properties and must include boolean complete and string statement');
  } else {
    for (const key of ['uncapped_verdict', 'capped_to']) {
      if (key in integrity && !stringOrNull(integrity[key])) {
        push(problems, 'R0-shape', `$.integrity.${key}`, `${key} must be a string or null`);
      }
    }
    if ('unaccounted' in integrity && !stringArray(integrity.unaccounted)) {
      push(problems, 'R0-shape', '$.integrity.unaccounted', 'unaccounted must be an array of strings');
    }
  }

  if ('producer' in document) {
    if (!object(document.producer) || !onlyKeys(document.producer, PRODUCER_KEYS)) {
      push(problems, 'R0-shape', '$.producer', 'producer contains an unknown property or is not an object');
    } else {
      for (const key of Object.keys(document.producer)) {
        if (typeof document.producer[key] !== 'string') {
          push(problems, 'R0-shape', `$.producer.${key}`, `${key} must be a string`);
        }
      }
    }
  }
  if ('as_of' in document && typeof document.as_of !== 'string') {
    push(problems, 'R0-shape', '$.as_of', 'as_of must be a string');
  }
}

function checkRules(document, problems) {
  if (!object(document) || !Array.isArray(document.strata)) return;

  const stratumById = new Map();
  for (const [index, stratum] of document.strata.entries()) {
    if (!object(stratum)) continue;
    const path = `$.strata[${index}]`;
    if (typeof stratum.id === 'string') stratumById.set(stratum.id, stratum);

    const eligibleOk = Number.isInteger(stratum.eligible) && stratum.eligible >= 0;
    const examinedOk = Number.isInteger(stratum.examined) && stratum.examined >= 0;
    if (!eligibleOk) {
      push(problems, 'R5-counts-well-formed', `${path}.eligible`, 'eligible must be a non-negative integer');
    }
    if (!examinedOk) {
      push(problems, 'R5-counts-well-formed', `${path}.examined`, 'examined must be a non-negative integer');
    }
    if (eligibleOk && examinedOk && stratum.examined > stratum.eligible) {
      push(problems, 'R5-counts-well-formed', `${path}.examined`, 'examined must not exceed eligible');
    }

    if (eligibleOk && examinedOk && Array.isArray(stratum.unexamined)
        && stratum.eligible !== stratum.examined + stratum.unexamined.length) {
      push(problems, 'R1-no-silent-remainder', path, 'eligible must equal examined plus the number of individually accounted unexamined entries');
    }

    if (Array.isArray(stratum.unexamined)) {
      for (const [unitIndex, entry] of stratum.unexamined.entries()) {
        const unitPath = `${path}.unexamined[${unitIndex}]`;
        if (!object(entry)) continue;
        if (typeof entry.unit !== 'string' || typeof entry.disposition !== 'string'
            || !DISPOSITIONS.has(entry.disposition)) {
          push(problems, 'R2-closed-disposition', unitPath, 'entry must name a string unit and a closed disposition');
        }
        if (entry.disposition === 'withheld'
            && (typeof entry.withheld_digest !== 'string'
              || !HEX_DIGEST.test(entry.withheld_digest))) {
          push(problems, 'R3-withholding-digest-bound', unitPath, 'withheld entry must carry a valid withheld_digest');
        }
      }
    }

    if (!object(stratum.basis) || !BASIS_KINDS.has(stratum.basis.kind)) {
      push(problems, 'R4-denominator-basis', `${path}.basis`, 'basis.kind must be catalogue, enumeration, or declared');
    } else if (stratum.basis.kind === 'catalogue'
        && (typeof stratum.basis.catalogue_digest !== 'string'
          || !HEX_DIGEST.test(stratum.basis.catalogue_digest))) {
      push(problems, 'R4-denominator-basis', `${path}.basis.catalogue_digest`, 'catalogue basis must carry a valid catalogue_digest');
    } else if (stratum.basis.kind === 'enumeration'
        && typeof stratum.basis.enumeration_method !== 'string') {
      push(problems, 'R4-denominator-basis', `${path}.basis.enumeration_method`, 'enumeration basis must state its method');
    }
  }

  if (Array.isArray(document.absence_assertions)) {
    for (const [index, assertion] of document.absence_assertions.entries()) {
      const path = `$.absence_assertions[${index}]`;
      if (!object(assertion) || typeof assertion.stratum !== 'string'
          || !stratumById.has(assertion.stratum)) {
        push(problems, 'R6-absence-is-scoped', `${path}.stratum`, 'absence assertion must name an existing stratum');
        continue;
      }
      const supports = stratumById.get(assertion.stratum).supports;
      if (!Array.isArray(supports) || supports.length === 0) {
        push(problems, 'R8-supports-bounds-citation', `$.strata[id=${assertion.stratum}].supports`, 'cited stratum must state at least one supported claim class');
      }
    }
  }

  if (object(document.integrity) && typeof document.integrity.complete === 'boolean') {
    const dirtyUnit = document.strata.some((stratum) => object(stratum)
      && Array.isArray(stratum.unexamined)
      && stratum.unexamined.some((entry) => object(entry)
        && INCOMPLETE_DISPOSITIONS.has(entry.disposition)));
    if (dirtyUnit && document.integrity.complete) {
      push(problems, 'R7-incomplete-not-clean', '$.integrity.complete', 'failed, resource_exhausted, or unavailable units forbid complete=true');
    }
    if (!document.integrity.complete
        && (typeof document.integrity.capped_to !== 'string'
          || document.integrity.capped_to.trim() === '')) {
      push(problems, 'R7-incomplete-not-clean', '$.integrity.capped_to', 'an incomplete run must state a non-empty capped verdict');
    }
  }
}

/**
 * Independent CAP-1 verifier derived from draft-hillier-coverage-attestation-00
 * and its normative JSON Schema. It does not import or invoke Certisyn code.
 */
export function verifyCap1(document) {
  const problems = new Map();
  let documentDigest = null;
  try {
    documentDigest = cap1ObjectDigest(document);
    checkShape(document, problems);
    checkRules(document, problems);
  } catch (error) {
    return {
      verdict: 'REFUSES',
      primary_rule: 'R0-shape',
      source: CAP1_SOURCE_LOCK,
      document_digest: documentDigest,
      violations: [{
        rule: 'R0-shape',
        problems: [{ path: '$', detail: `verifier refused safely: ${error instanceof Error ? error.message : 'unknown error'}` }],
      }],
    };
  }

  const violations = RULE_PRIORITY
    .filter((rule) => problems.has(rule))
    .map((rule) => ({ rule, problems: problems.get(rule) }));
  if (violations.length === 0) {
    return {
      verdict: 'CONFORMS',
      primary_rule: null,
      source: CAP1_SOURCE_LOCK,
      document_digest: documentDigest,
      violations: [],
    };
  }
  return {
    verdict: 'REFUSES',
    primary_rule: violations[0].rule,
    source: CAP1_SOURCE_LOCK,
    document_digest: documentDigest,
    violations,
  };
}

export function canonicalUnitSetDigest(unitIds) {
  if (!stringArray(unitIds) || new Set(unitIds).size !== unitIds.length) {
    throw new TypeError('unit set must be an array of unique strings');
  }
  const canonical = JSON.stringify([...unitIds].sort());
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function sameStringSet(left, right) {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return left.every((item) => rightSet.has(item));
}

/**
 * Optional relying-party control for evidence CAP-1 does not carry: canonical
 * eligible/examined-set commitments and one result binding per examined unit.
 * This is not CAP-1 conformance and must not be described as such.
 */
export function verifyExaminedSetEvidence(document, evidence) {
  const cap1 = verifyCap1(document);
  if (cap1.verdict !== 'CONFORMS') {
    return { verdict: 'REFUSES', reason: 'cap1_nonconforming', cap1 };
  }
  if (!object(evidence)
      || evidence.profile !== 'EMILIA-CAP1-EXAMINED-SET-v1'
      || !Array.isArray(evidence.strata)) {
    return { verdict: 'REFUSES', reason: 'examined_set_evidence_malformed' };
  }

  const evidenceByStratum = new Map();
  for (const entry of evidence.strata) {
    if (!object(entry) || typeof entry.stratum !== 'string'
        || evidenceByStratum.has(entry.stratum)) {
      return { verdict: 'REFUSES', reason: 'examined_set_evidence_malformed' };
    }
    evidenceByStratum.set(entry.stratum, entry);
  }
  if (evidenceByStratum.size !== document.strata.length) {
    return { verdict: 'REFUSES', reason: 'examined_set_stratum_coverage_mismatch' };
  }

  const verified = [];
  for (const stratum of document.strata) {
    const entry = evidenceByStratum.get(stratum.id);
    if (!entry
        || !stringArray(entry.eligible_units)
        || !Array.isArray(entry.results)
        || typeof entry.eligible_set_digest !== 'string'
        || typeof entry.examined_set_digest !== 'string') {
      return { verdict: 'REFUSES', reason: 'examined_set_evidence_malformed', stratum: stratum.id };
    }
    if (new Set(entry.eligible_units).size !== entry.eligible_units.length) {
      return { verdict: 'REFUSES', reason: 'eligible_unit_duplicate', stratum: stratum.id };
    }
    if (entry.eligible_units.length !== stratum.eligible) {
      return { verdict: 'REFUSES', reason: 'eligible_set_count_mismatch', stratum: stratum.id };
    }
    if (entry.eligible_set_digest !== canonicalUnitSetDigest(entry.eligible_units)) {
      return { verdict: 'REFUSES', reason: 'eligible_set_digest_mismatch', stratum: stratum.id };
    }

    const resultUnits = [];
    for (const result of entry.results) {
      if (!object(result)
          || typeof result.unit !== 'string'
          || typeof result.result_digest !== 'string'
          || !/^sha256:[0-9a-f]{64}$/.test(result.result_digest)) {
        return { verdict: 'REFUSES', reason: 'result_binding_malformed', stratum: stratum.id };
      }
      resultUnits.push(result.unit);
    }
    if (new Set(resultUnits).size !== resultUnits.length) {
      return { verdict: 'REFUSES', reason: 'examined_unit_duplicate', stratum: stratum.id };
    }
    if (resultUnits.length !== stratum.examined) {
      return { verdict: 'REFUSES', reason: 'examined_set_count_mismatch', stratum: stratum.id };
    }
    if (resultUnits.some((unit) => !entry.eligible_units.includes(unit))) {
      return { verdict: 'REFUSES', reason: 'examined_unit_not_eligible', stratum: stratum.id };
    }
    if (entry.examined_set_digest !== canonicalUnitSetDigest(resultUnits)) {
      return { verdict: 'REFUSES', reason: 'examined_set_digest_mismatch', stratum: stratum.id };
    }

    const unexaminedUnits = stratum.unexamined.map((item) => item.unit);
    if (new Set(unexaminedUnits).size !== unexaminedUnits.length) {
      return { verdict: 'REFUSES', reason: 'unexamined_unit_duplicate', stratum: stratum.id };
    }
    if (stratum.unexamined.some((item) => item.disposition === 'withheld')) {
      return { verdict: 'REFUSES', reason: 'withheld_examined_semantics_ambiguous', stratum: stratum.id };
    }
    if (unexaminedUnits.some((unit) => !entry.eligible_units.includes(unit))) {
      return { verdict: 'REFUSES', reason: 'unexamined_unit_not_eligible', stratum: stratum.id };
    }
    if (unexaminedUnits.some((unit) => resultUnits.includes(unit))) {
      return { verdict: 'REFUSES', reason: 'examined_unexamined_overlap', stratum: stratum.id };
    }
    if (!sameStringSet([...resultUnits, ...unexaminedUnits], entry.eligible_units)) {
      return { verdict: 'REFUSES', reason: 'eligible_set_membership_mismatch', stratum: stratum.id };
    }
    verified.push({
      stratum: stratum.id,
      eligible_set_digest: entry.eligible_set_digest,
      examined_set_digest: entry.examined_set_digest,
      result_bindings: entry.results.length,
    });
  }

  return { verdict: 'SATISFIED', verified };
}

export const CAP1_RULES = Object.freeze([...RULE_PRIORITY]);
