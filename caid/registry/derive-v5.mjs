#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Derives registry v5 (action-types.json and its four new value-set files)
// from the frozen v4 registry (history/action-types.v4.json) and the
// upstream files it pins, so every v5 change is reproducible.
//
//   node caid/registry/derive-v5.mjs --sources DIR --write
//   node caid/registry/derive-v5.mjs --sources DIR --check
//
// DIR holds the upstream files fetched unchanged from their URLs:
//   dns-parameters.xml        https://www.iana.org/assignments/dns-parameters/dns-parameters.xml
//   jose.xml                  https://www.iana.org/assignments/jose/jose.xml
//   language-subtag-registry  https://www.iana.org/assignments/language-subtag-registry/language-subtag-registry
// Each file's SHA-256 must equal the value pinned below; a changed upstream
// file is a new registry version, never a silent regeneration.
//
// Dev-time provenance tooling. CI does not run it (it needs the upstream
// files); caid/registry/check.mjs checks the derived registry itself.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../impl/js/caid.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RETRIEVED = '2026-09-26';
const UPDATED = '2026-09-26';
const IANA_LICENSE = 'CC0-1.0: Joint Statement of IANA and IETF Concerning Copyright Rights in the Protocol Registries, 2021-11-10, https://www.iana.org/help/licensing-terms';
const SOURCES = {
  'dns-parameters.xml': 'sha256:dbddd85b4f05fe41f1a200ead5441d769041dc6f92d12561ea14ee996fa2a27c',
  'jose.xml': 'sha256:989bf4152905fd28051886f36a3b4a54c99bba6f6a97e2ae13213e817488b859',
  'language-subtag-registry': 'sha256:755fad43283be7b41ebe3c89ad054b6eaf928f404f9c0edb74799e0eab74beb1',
};
const ISO4217 = {
  values_ref: 'ISO 4217 alpha-3',
  values_snapshot: 'SIX ISO 4217 List One published 2026-09-17',
  values_sha256: 'sha256:27f824317e9f271b956123fb77608daece5106e1ee8253a17769390855ade270',
};

const sha = (buf) => 'sha256:' + createHash('sha256').update(buf).digest('hex');
/** The first capture group of re in text; throws when re does not match. */
const capture = (re, text) => {
  const m = re.exec(text);
  if (!m) throw new Error(`upstream file does not match ${re}`);
  return m[1];
};
const jcs = (value) => {
  const c = canonicalize(value);
  if (!c.ok) throw new Error('value is not canonicalizable');
  return sha(Buffer.from(c.canonical, 'utf8'));
};

/**
 * Builds registry v5 from the v4 registry and the upstream source files.
 *
 * @param {string} sourcesDir
 * @returns {{registry: any, valueSets: Map<string, any>}}
 */
export function deriveV5(sourcesDir) {
  const sources = {};
  for (const [name, digest] of Object.entries(SOURCES)) {
    const bytes = readFileSync(path.join(sourcesDir, name));
    if (sha(bytes) !== digest) throw new Error(`${name} is ${sha(bytes)}, not the pinned ${digest}`);
    sources[name] = bytes;
  }
  const v4 = JSON.parse(readFileSync(path.join(HERE, 'history/action-types.v4.json'), 'utf8'));
  if (v4.meta.registry_version !== 4) throw new Error('history/action-types.v4.json is not registry v4');

  const valueSets = new Map();
  const pins = {};
  const valueSet = (id, file, meta, values) => {
    if (new Set(values).size !== values.length) throw new Error(`${id}: duplicate values`);
    if (!values.every((v) => typeof v === 'string' && v.length > 0)) throw new Error(`${id}: empty value`);
    const snapshot = {
      '@version': 'CAID-ENUM-SNAPSHOT-v1',
      id,
      values_ref: meta.values_ref,
      values_snapshot: meta.values_snapshot,
      values_sha256: jcs(values),
      hash_input: 'RFC 8785 canonical JSON encoding of the values array',
      source: meta.source,
      derivation: meta.derivation,
      values,
    };
    const rel = `value-sets/${file}`;
    valueSets.set(rel, snapshot);
    pins[id] = {
      values_ref: snapshot.values_ref,
      values_snapshot: snapshot.values_snapshot,
      values_sha256: snapshot.values_sha256,
      path: rel,
      snapshot_sha256: jcs(snapshot),
      source_url: meta.source.url,
      retrieved: meta.source.retrieved,
      license: meta.source.license,
    };
  };
  const ianaRecords = (xml, registryId) => {
    const start = xml.indexOf(`<registry id="${registryId}">`);
    if (start < 0) throw new Error(`registry ${registryId} missing`);
    const segment = xml.slice(start, xml.indexOf('</registry>', start));
    return [...segment.matchAll(/<record[^>]*>([\s\S]*?)<\/record>/g)].map((m) => m[1]);
  };
  const tag = (rec, name) => (new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(rec) || [])[1];

  // IANA DNS RR TYPEs: first pin of dns.record.delete.1 record_type.
  {
    const xml = sources['dns-parameters.xml'].toString('utf8');
    const updated = capture(/<updated>([^<]+)<\/updated>/, xml);
    const values = ianaRecords(xml, 'dns-parameters-4').map((r) => tag(r, 'type'))
      .filter((t) => t && !['Reserved', 'Unassigned', 'Private use'].includes(t));
    valueSet('iana-dns-rr-types', `iana-dns-rr-types.${updated}.json`, {
      values_ref: 'IANA DNS Resource Record TYPEs (RFC 1035 and successors)',
      values_snapshot: `IANA Domain Name System (DNS) Parameters, Resource Record (RR) TYPEs, file updated ${updated}`,
      source: {
        authority: 'Internet Assigned Numbers Authority (IANA)',
        url: 'https://www.iana.org/assignments/dns-parameters/dns-parameters.xml',
        registry_id: 'dns-parameters-4',
        published: updated,
        retrieved: RETRIEVED,
        source_sha256: SOURCES['dns-parameters.xml'],
        license: IANA_LICENSE,
      },
      derivation: 'Every <type> of registry dns-parameters-4 in document order, verbatim, omitting the range rows whose type is Reserved, Unassigned, or Private use. QTYPEs and meta-TYPEs (OPT, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, *) and obsolete TYPEs are kept exactly as the registry lists them.',
    }, values);
  }

  // IANA JOSE algorithms and elliptic curves: key.create.2 and key.rotate.2.
  {
    const xml = sources['jose.xml'].toString('utf8');
    const updated = capture(/<updated>([^<]+)<\/updated>/, xml);
    const source = (id) => ({
      authority: 'Internet Assigned Numbers Authority (IANA)',
      url: 'https://www.iana.org/assignments/jose/jose.xml',
      registry_id: id,
      published: updated,
      retrieved: RETRIEVED,
      source_sha256: SOURCES['jose.xml'],
      license: IANA_LICENSE,
    });
    valueSet('iana-jose-algorithms', `iana-jose-algorithms.${updated}.json`, {
      values_ref: 'IANA JSON Web Signature and Encryption Algorithms',
      values_snapshot: `IANA JSON Object Signing and Encryption (JOSE) registries, file updated ${updated}`,
      source: source('web-signature-encryption-algorithms'),
      derivation: 'Every Algorithm Name (<value>) of registry web-signature-encryption-algorithms in document order, verbatim, whatever its usage location or implementation requirement, including none, dir, and deprecated entries.',
    }, ianaRecords(xml, 'web-signature-encryption-algorithms').map((r) => tag(r, 'value')).filter(Boolean));
    valueSet('iana-jose-elliptic-curves', `iana-jose-elliptic-curves.${updated}.json`, {
      values_ref: 'IANA JSON Web Key Elliptic Curve',
      values_snapshot: `IANA JSON Object Signing and Encryption (JOSE) registries, file updated ${updated}`,
      source: source('web-key-elliptic-curve'),
      derivation: 'Every Curve Name (<value>) of registry web-key-elliptic-curve in document order, verbatim.',
    }, ianaRecords(xml, 'web-key-elliptic-curve').map((r) => tag(r, 'value')).filter(Boolean));
  }

  // ISO 3166-1 alpha-2 officially assigned codes via the IANA Language
  // Subtag Registry: first pin of vendor.onboard.1 jurisdiction.
  {
    const raw = sources['language-subtag-registry'].toString('utf8');
    const fileDate = capture(/^File-Date: (\S+)/, raw);
    const EXCEPTIONALLY_RESERVED = new Set(['AC', 'CP', 'CQ', 'DG', 'EA', 'EU', 'EZ', 'FX', 'IC', 'SU', 'TA', 'UK', 'UN']);
    const codes = [];
    for (const rec of raw.split('\n%%\n').slice(1)) {
      const r = rec.replace(/\n  /g, ' ');
      const get = (k) => [...r.matchAll(new RegExp(`^${k}: (.*)$`, 'gm'))].map((m) => m[1]);
      if (get('Type')[0] !== 'region') continue;
      const subtag = get('Subtag')[0];
      if (!/^[A-Z]{2}$/.test(subtag ?? '')) continue;
      if (get('Deprecated').length) continue;
      if (get('Description').some((d) => d === 'Private use')) continue;
      if (EXCEPTIONALLY_RESERVED.has(subtag)) continue;
      codes.push(subtag);
    }
    codes.sort();
    if (codes.length !== 249) throw new Error(`expected 249 officially assigned codes, got ${codes.length}`);
    valueSet('iso-3166-1-alpha-2', `iso-3166-1-alpha-2.${fileDate}.json`, {
      values_ref: 'ISO 3166-1 alpha-2',
      values_snapshot: `ISO 3166-1 alpha-2 officially assigned codes as carried by the IANA Language Subtag Registry, File-Date ${fileDate}`,
      source: {
        authority: 'Internet Assigned Numbers Authority (IANA), Language Subtag Registry (BCP 47 region subtags from ISO 3166-1)',
        url: 'https://www.iana.org/assignments/language-subtag-registry/language-subtag-registry',
        published: fileDate,
        retrieved: RETRIEVED,
        source_sha256: SOURCES['language-subtag-registry'],
        license: `${IANA_LICENSE}. The dedication covers IANA and IETF rights only; ISO asserts copyright in the ISO 3166 code lists, and no list was taken from ISO.`,
      },
      derivation: 'Every record with Type region and a two-letter Subtag that carries no Deprecated field and whose Description is not Private use, excluding the ISO 3166-1 exceptionally reserved codes AC, CP, CQ, DG, EA, EU, EZ, FX, IC, SU, TA, UK and UN; sorted by code point. The result has 249 codes, the count of officially assigned ISO 3166-1 alpha-2 codes.',
    }, codes);
  }

  const CODE_SYSTEMS = codeSystems();
  const systemUri = (id) => {
    const system = CODE_SYSTEMS.find((c) => c.id === id);
    if (!system) throw new Error(`no code system ${id}`);
    return system.code_system;
  };
  const r = structuredClone(v4);
  const find = (name) => r.types.find((t) => t.action_type === name);
  const fields = (t) => [...t.required_fields, ...t.optional_fields];
  const pin = (id) => ({ values_ref: pins[id].values_ref, values_snapshot: pins[id].values_snapshot, values_sha256: pins[id].values_sha256 });
  const code = (name, system, format, notes) => ({ name, type: 'code', code_system: systemUri(system), format, notes });
  const replaceField = (t, name, def) => {
    for (const key of ['required_fields', 'optional_fields']) {
      const i = t[key].findIndex((f) => f.name === name);
      if (i >= 0) { t[key][i] = def; return; }
    }
    throw new Error(`${t.action_type} has no ${name}`);
  };

  r.meta.registry_version = 5;
  r.meta.updated = UPDATED;
  r.meta.entry_schema_note = 'Each entry in types conforms to the type definition schema of draft-schrock-canonical-action-identifier-04 (Section 4.2; caid/spec/core.json holds the same rules as data). Local (private) definition files MUST use the same schema; there is no reserved private-use syntax. Field types: string, amount-string, digest, enum, code, timestamp, integer, boolean, object, array. An enum is closed by a non-empty inline values array, an inline pipe-separated values_ref prefixed inline:, or an external values_ref with values_snapshot and values_sha256 metadata plus an exactly matching locally supplied snapshot; a bare or unresolved external values_ref fails closed. A code field carries code_system (a URI naming the code system) and format (a code format registered in Appendix A of the draft) and holds a JSON string that the format matches as a whole; CAID checks syntax, never membership in any edition of the code system, and code_systems records each system a field names. Each enum_snapshot_files entry pins the value-set file\'s labels and snapshot_sha256, the SHA-256 of the RFC 8785 canonical JSON of the whole file, so its provenance members are bound to this registry. unresolved_external_enums lists every field, of either status, whose external values_ref has no pinned snapshot in this registry version; such a field refuses whenever it is present, and no active type may have one. Date-only values use type string with an ISO 8601 date note; type timestamp is always full RFC 3339 UTC with Z. digests.json lists every type\'s definition_sha256.';
  r.meta.lifecycle_note = 'status is active or deprecated. A deprecated type still resolves, computes and verifies wherever its fields resolve; deprecation only tells issuers to use its successor. supersedes (on the successor) and superseded_by (on the predecessor) are informative and outside definition_sha256. A registry version changes a published type only by deprecating it or by advancing an enum pin in place to a later edition that contains every previous member (the first pin of a field that resolved no set is such an advance); any other change is a new type version. Every published registry version is kept byte-identical under history/.';

  // First pins: the v4 values_ref already names exactly the pinned set, and
  // the v4 field refused every value.
  Object.assign(fields(find('dns.record.delete.1')).find((f) => f.name === 'record_type'), pin('iana-dns-rr-types'));
  Object.assign(fields(find('vendor.onboard.1')).find((f) => f.name === 'jurisdiction'), pin('iso-3166-1-alpha-2'));

  const added = [];
  const successor = (oldName, mutate) => {
    const old = find(oldName);
    const next = structuredClone(old);
    next.action_type = oldName.replace(/\.1$/, '.2');
    next.supersedes = oldName;
    mutate(next);
    old.status = 'deprecated';
    old.superseded_by = next.action_type;
    added.push([oldName, next]);
  };

  successor('payment.refund.1', (t) => replaceField(t, 'reason_code', code('reason_code', 'iso20022', 'iso20022-external-code',
    'ISO 20022 ExternalReturnReason1Code value, for example AC04 (ClosedAccountNumber) or MD06 (RefundRequestByEndCustomer); the code, never its name; syntax only')));
  successor('ach.debit.originate.1', (t) => replaceField(t, 'sec_code', code('sec_code', 'nacha', 'nacha-sec',
    'Standard Entry Class code the entry is originated under, as in the batch header; whether that code permits a debit is a Nacha rule, not a CAID check')));
  const keyFields = (t, prefix) => {
    const alg = prefix ? 'new_algorithm' : 'algorithm';
    replaceField(t, alg, {
      name: alg,
      type: 'enum',
      ...pin('iana-jose-algorithms'),
      notes: (prefix ? 'JOSE alg of the new key version' : 'JOSE alg (RFC 7517 section 4.4) the key is created for') + '; the issuer maps a store-native key spec to exactly one registered alg and uses Ed25519 or Ed448 rather than EdDSA',
    });
    t.optional_fields.push(
      { name: `${prefix}key_size_bits`, type: 'integer', notes: 'Present exactly when the key is an RSA or symmetric key (JWK kty RSA or oct): the RSA modulus length or the secret key length in bits. Absent for every other key.' },
      { name: `${prefix}curve`, type: 'enum', ...pin('iana-jose-elliptic-curves'), notes: 'Present exactly when the key is an elliptic-curve key (JWK kty EC or OKP), even when the algorithm fixes the curve. Absent for every other key.' },
    );
  };
  successor('key.create.1', (t) => {
    keyFields(t, '');
    t.required_fields.find((f) => f.name === 'key_ops').notes = 'permitted operations, from RFC 7517 section 4.3 key_ops values, without duplicates, sorted in code point order';
  });
  successor('key.rotate.1', (t) => keyFields(t, 'new_'));
  successor('firewall.rule.open.1', (t) => {
    replaceField(t, 'protocol', {
      name: 'protocol',
      type: 'enum',
      values: ['any', ...Array.from({ length: 256 }, (_, i) => String(i))],
      notes: 'IPv4 Protocol or IPv6 Next Header value in decimal without leading zeros (tcp 6, udp 17, icmp 1, ipv6-icmp 58), or any for every protocol. IANA keywords are not used: they are mixed case and seven assigned numbers have none.',
    });
    replaceField(t, 'port_range', { name: 'port_range', type: 'string', notes: "single port '443', range '1024-65535', or 'any'; 'any' for a protocol without ports; a one-port range is written as the single port" });
    replaceField(t, 'remote_cidr', { name: 'remote_cidr', type: 'string', notes: 'CIDR the rule permits, no host bits set; IPv6 in RFC 5952 canonical text form; the source for ingress, the destination for egress' });
  });
  successor('pii.export.1', (t) => replaceField(t, 'legal_basis', {
    name: 'legal_basis',
    type: 'enum',
    values: ['consent', 'contract', 'legal-obligation', 'vital-interests', 'public-task', 'legitimate-interests', 'not-subject-to-gdpr'],
    notes: 'the first six are points (a) to (f) of Article 6(1) of Regulation (EU) 2016/679, in that order, which the UK GDPR repeats; not-subject-to-gdpr means Article 6(1) does not apply to the export',
  }));
  successor('rx.dispense.1', (t) => replaceField(t, 'ndc_code', code('ndc_code', 'ndc', 'ndc-11',
    'HIPAA 11-digit NDC, 5-4-2 without hyphens; identifies the exact product and package. A 10-digit NDC is converted by left-padding its short segment with one 0; a 12-digit NDC (FDA rule effective 2033-03-07) needs a new type version')));
  successor('prior.auth.approve.1', (t) => {
    t.summary = 'Approval of a prior authorization request for a procedure or service identified by an HCPCS code.';
    replaceField(t, 'service_code', code('service_code', 'hcpcs', 'hcpcs',
      'authorized procedure or service, the 5-character HCPCS Level I (CPT) or Level II base code without modifiers; drug authorizations under a pharmacy benefit and inpatient ICD-10-PCS authorizations are separate action types'));
    replaceField(t, 'diagnosis_code', code('diagnosis_code', 'icd-10-cm', 'icd-10-cm', 'principal diagnosis supporting the request, uppercase, with the period after the third character when there are more than three'));
  });
  const PHI_PURPOSES = ['individual', 'treatment', 'payment', 'health-care-operations', 'authorization', 'facility-directory',
    'care-involvement-notification', 'required-by-law', 'public-health', 'abuse-neglect-violence', 'health-oversight',
    'judicial-administrative', 'law-enforcement', 'decedents', 'organ-tissue-donation', 'research', 'serious-threat',
    'specialized-government', 'workers-compensation', 'limited-data-set', 'fundraising', 'underwriting', 'secretary-compliance'];
  successor('phi.disclose.1', (t) => {
    replaceField(t, 'purpose', {
      name: 'purpose',
      type: 'enum',
      values: PHI_PURPOSES,
      notes: '45 CFR (eCFR, title 45 as of 2026-09-24): individual 164.502(a)(1)(i) and (a)(2)(i); treatment, payment, health-care-operations 164.506(c); authorization 164.508; facility-directory 164.510(a); care-involvement-notification 164.510(b); required-by-law through workers-compensation 164.512(a) to (l) in order; limited-data-set 164.514(e); fundraising 164.514(f); underwriting 164.514(g); secretary-compliance 164.502(a)(2)(ii)',
    });
    t.references = ['45 CFR 164.502', '45 CFR 164.506', '45 CFR 164.508', '45 CFR 164.510', '45 CFR 164.512', '45 CFR 164.514', '45 CFR 164.528'];
  });

  // contract.execute.2 sits beside contract.execute.1, which stays active
  // for contracts that state no monetary value.
  {
    const base = find('contract.execute.1');
    const currency = base.optional_fields.find((f) => f.name === 'currency');
    const value = base.optional_fields.find((f) => f.name === 'contract_value');
    const next = {
      action_type: 'contract.execute.2',
      status: 'active',
      risk_class: base.risk_class,
      summary: 'Execution (signing) of a contract that states a single total monetary value, binding the executing party. A contract that states no monetary value uses contract.execute.1.',
      required_fields: [
        ...structuredClone(base.required_fields),
        { ...structuredClone(value), notes: 'total contract value, in currency' },
        { ...structuredClone(currency), notes: 'currency of contract_value' },
      ],
      optional_fields: base.optional_fields.filter((f) => f.name === 'term_months').map((f) => structuredClone(f)),
      digest_notes: `${base.digest_notes}; contract_value and currency are material together, so the same value in another currency is a different CAID`,
      references: [],
    };
    if (JSON.stringify(currency && { values_ref: currency.values_ref, values_snapshot: currency.values_snapshot, values_sha256: currency.values_sha256 }) !== JSON.stringify(ISO4217)) {
      throw new Error('contract.execute.1 currency is not the pinned ISO 4217 set');
    }
    added.push(['contract.execute.1', next]);
  }

  for (const [after, entry] of added) r.types.splice(r.types.findIndex((t) => t.action_type === after) + 1, 0, entry);

  r.enum_snapshot_files = [
    {
      ...v4.enum_snapshot_files[0],
      source_url: 'https://www.six-group.com/dam/download/financial-information/data-center/iso-currrency/lists/list-one.xml',
      retrieved: '2026-09-24',
      license: 'No licence terms accompany the file. SIX, as ISO 4217 Maintenance Agency, states that it makes the code lists available online and free of charge (https://www.six-group.com/en/products-services/financial-information/data-standards.html, retrieved 2026-09-26); that statement is not a licence grant, and no other terms were found.',
    },
    ...['iana-dns-rr-types', 'iana-jose-algorithms', 'iana-jose-elliptic-curves', 'iso-3166-1-alpha-2'].map((id) => pins[id]),
  ];

  const pinned = new Set(r.enum_snapshot_files.map((e) => JSON.stringify([e.values_ref, e.values_snapshot, e.values_sha256])));
  r.unresolved_external_enums = [];
  for (const t of r.types) {
    for (const [required, list] of [[true, t.required_fields], [false, t.optional_fields]]) {
      for (const f of list) {
        if (f.type !== 'enum') continue;
        const inline = Array.isArray(f.values) && !('values_ref' in f);
        const compact = typeof f.values_ref === 'string' && f.values_ref.startsWith('inline:');
        if (!inline && !compact && !pinned.has(JSON.stringify([f.values_ref, f.values_snapshot, f.values_sha256]))) {
          r.unresolved_external_enums.push({ action_type: t.action_type, status: t.status, field: f.name, required });
        }
      }
    }
  }

  const registry = {
    meta: r.meta,
    code_systems: CODE_SYSTEMS.map(({ id, ...rest }) => rest),
    enum_snapshot_files: r.enum_snapshot_files,
    unresolved_external_enums: r.unresolved_external_enums,
    types: r.types,
  };
  return { registry, valueSets };
}

function codeSystems() {
  return [
    {
      id: 'icd-10-cm',
      code_system: 'http://hl7.org/fhir/sid/icd-10-cm',
      title: 'ICD-10-CM (International Classification of Diseases, 10th Revision, Clinical Modification)',
      authority: 'U.S. National Center for Health Statistics',
      formats: ['icd-10-cm'],
      identifier_source: { url: 'https://terminology.hl7.org/en/NamingSystem-icd10CM.html', retrieved: RETRIEVED, statement: 'HL7 THO 7.4.0 NamingSystem icd10CM: preferred URI http://hl7.org/fhir/sid/icd-10-cm, "the URL as specified by the terminology owner"' },
      syntax_sources: [
        { url: 'https://www.cms.gov/files/document/fy-2026-icd-10-cm-coding-guidelines.pdf', retrieved: RETRIEVED, statement: 'ICD-10-CM Official Guidelines FY 2026, Section I.A.2: categories are 3 characters, codes 3 to 7; characters may be a letter or a number' },
        { url: 'https://terminology.hl7.org/en/ICD.html', retrieved: RETRIEVED, statement: 'ICD codes SHALL be represented with the period included' },
      ],
      license_note: 'CAID carries no ICD-10-CM code list; the format fixes syntax only.',
    },
    {
      id: 'ndc',
      code_system: 'http://hl7.org/fhir/sid/ndc',
      title: 'National Drug Code',
      authority: 'U.S. Food and Drug Administration',
      formats: ['ndc-11', 'ndc-10-hyphenated'],
      identifier_source: { url: 'https://terminology.hl7.org/en/NamingSystem-v3-ndc.html', retrieved: RETRIEVED, statement: 'HL7 THO 7.4.0 NamingSystem v3-ndc: preferred URI http://hl7.org/fhir/sid/ndc' },
      syntax_sources: [
        { url: 'https://terminology.hl7.org/en/NDC.html', retrieved: RETRIEVED, statement: 'the 10-digit code with "-": 1234-5678-90, 12345-6789-0, or 12345-678-90' },
        { url: 'https://www.fda.gov/drugs/electronic-drug-registration-and-listing-system-edrls/national-drug-code-format', retrieved: RETRIEVED, statement: 'the HIPAA standard 11-digit format used for reimbursement; FDA-assigned NDCs become 12 digits on 2033-03-07' },
      ],
      license_note: 'HL7 THO 7.4.0: "NDC codes have no copyright acknowledgment or license requirements." CAID carries no NDC list.',
    },
    {
      id: 'hcpcs',
      code_system: 'https://www.cms.gov/medicare/coding-billing/healthcare-common-procedure-system',
      title: 'Healthcare Common Procedure Coding System (HCPCS), Levels I and II',
      authority: 'American Medical Association (Level I, CPT) and U.S. Centers for Medicare & Medicaid Services (Level II)',
      formats: ['hcpcs'],
      identifier_source: { url: 'https://www.cms.gov/medicare/coding-billing/healthcare-common-procedure-system', retrieved: RETRIEVED, statement: 'CMS: "HCPCS is divided into 2 main subsystems - Level I and Level II". No authority-assigned URI names both levels together: HL7 THO 7.4.0 assigns http://www.ama-assn.org/go/cpt (NamingSystem CPT) to Level I and http://www.cms.gov/Medicare/Coding/HCPCSReleaseCodeSets (NamingSystem hcpcs-Level-II) to Level II. This URI is the CMS page that defines the two levels.' },
      syntax_sources: [
        { url: 'https://www.cms.gov/medicare/coding-billing/healthcare-common-procedure-system', retrieved: RETRIEVED, statement: 'HCPCS Level II codes consist of a single alphabetical letter followed by 4 numeric digits' },
        { url: 'https://www.ama-assn.org/practice-management/cpt/category-ii-codes', retrieved: RETRIEVED, statement: 'All CPT codes are five-digits and can be either numeric or alphanumeric, depending on the category; Category II codes are 4 digits followed by the letter F' },
      ],
      license_note: 'The AMA holds the copyright in CPT and a license is required for use (HL7 THO 7.4.0, Using CPT). CAID MUST NOT publish CPT codes, descriptors, or value sets: this registry and its vectors carry syntax and synthetic examples only.',
    },
    {
      id: 'iso20022',
      code_system: 'urn:iso:std:iso:20022:tech:xsd:externalcodeset',
      title: 'ISO 20022 external code sets (ExternalReturnReason1Code for payment returns)',
      authority: 'ISO 20022 Registration Authority',
      formats: ['iso20022-external-code'],
      identifier_source: { url: 'https://www.iso20022.org/sites/default/files/media/file/ExternalCodeSets_XSD.zip', retrieved: RETRIEVED, statement: 'targetNamespace urn:iso:std:iso:20022:tech:xsd:externalcodeset of the ISO 20022 External Code Sets XSD (2Q2026_externalcodesets_v3.xsd in the archive served at this URL on 2026-09-26). The namespace names every external code set; the field notes name the set.' },
      syntax_sources: [
        { url: 'https://www.iso20022.org/sites/default/files/media/file/ExternalCodeSets_XSD.zip', retrieved: RETRIEVED, statement: 'ExternalReturnReason1Code: xs:string, minLength 1, maxLength 4; all 104 codes of 2Q2026 v3 are four uppercase letters or digits' },
      ],
      license_note: 'The ISO 20022 terms of use page (https://www.iso20022.org/terms-use) answered HTTP 403 on 2026-09-26, so no licence was read. CAID carries no code list.',
    },
    {
      id: 'nacha',
      code_system: 'https://www.nacha.org/rules',
      title: 'Nacha Standard Entry Class codes',
      authority: 'Nacha',
      formats: ['nacha-sec'],
      identifier_source: { url: 'https://www.nacha.org/rules', retrieved: RETRIEVED, statement: 'No authority-assigned identifier for SEC codes is known. This URI is the Nacha Operating Rules page; the Rules define the codes.' },
      syntax_sources: [
        { url: 'https://achdevguide.nacha.org/ach-file-details', retrieved: RETRIEVED, statement: 'Batch header field 6, Standard Entry Class Code, positions 51-53, length 3, alphanumeric' },
      ],
      license_note: 'The complete SEC code list is in the licensed Nacha Operating Rules; the public guide lists commonly used codes only. CAID carries no SEC code list.',
    },
  ];
}

function main(argv) {
  let sourcesDir = null;
  let mode = null;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--sources') sourcesDir = argv[++i];
    else if (argv[i] === '--write' || argv[i] === '--check') mode = argv[i];
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (!sourcesDir || !mode) throw new Error('usage: derive-v5.mjs --sources DIR (--write | --check)');
  const { registry, valueSets } = deriveV5(path.resolve(sourcesDir));
  const outputs = new Map([['action-types.json', JSON.stringify(registry, null, 2) + '\n']]);
  for (const [rel, snapshot] of valueSets) outputs.set(rel, JSON.stringify(snapshot, null, 2) + '\n');
  const problems = [];
  for (const [rel, text] of outputs) {
    const file = path.join(HERE, rel);
    if (mode === '--write') writeFileSync(file, text);
    else {
      let current = null;
      try { current = readFileSync(file, 'utf8'); } catch { /* missing */ }
      if (current !== text) problems.push(rel);
    }
  }
  if (problems.length) {
    process.stderr.write(`derive-v5 --check: differs from a regeneration: ${problems.join(', ')}\n`);
    process.exit(1);
  }
  console.log(`derive-v5 ${mode}: ${outputs.size} files; ${registry.types.length} types, ${registry.types.filter((t) => t.status === 'active').length} active`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.message}\n`); process.exit(1); }
}
