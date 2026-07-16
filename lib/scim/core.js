/**
 * SCIM 2.0 core — pure resource mapping, filtering, and PATCH.
 *
 * RFC 7643 (Core Schema) + RFC 7644 (Protocol). Framework-agnostic: no Next.js,
 * no database — just transforms between EP rows and SCIM resources, parses the
 * filter subset real IdPs send, and applies PATCH operations. The route layer
 * (app/api/scim/v2/*) wires these to storage and HTTP.
 *
 * Scope is deliberately the intersection that Okta, Azure AD, and Ping actually
 * exercise for User/Group provisioning + deprovisioning — not the entire SCIM
 * surface. Unsupported filters return a 400 with a precise scimType rather than
 * a wrong answer.
 *
 * @license Apache-2.0
 */

import { z } from 'zod';

export const SCIM = {
  USER: 'urn:ietf:params:scim:schemas:core:2.0:User',
  GROUP: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  ENTERPRISE_USER: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
  LIST: 'urn:ietf:params:scim:api:messages:2.0:ListResponse',
  PATCH_OP: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  ERROR: 'urn:ietf:params:scim:api:messages:2.0:Error',
  SPC: 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig',
  RESOURCE_TYPE: 'urn:ietf:params:scim:schemas:core:2.0:ResourceType',
  SCHEMA: 'urn:ietf:params:scim:schemas:core:2.0:Schema',
};

export const SCIM_LIMITS = Object.freeze({
  userName: 320,
  namePart: 256,
  formattedName: 512,
  displayName: 512,
  title: 256,
  externalId: 256,
  emailValue: 320,
  phoneValue: 128,
  multiValueType: 64,
  multiValueDisplay: 512,
  reference: 2048,
  emails: 100,
  phoneNumbers: 100,
  groupMembers: 5000,
  patchOperations: 1000,
  patchPath: 1024,
  schemas: 32,
  schemaUrn: 512,
  rawDepth: 10,
  rawNodes: 30000,
  rawArrayItems: 10000,
  rawObjectKeys: 256,
  rawKey: 512,
  rawString: 16384,
  rawTotalString: 512 * 1024,
  extensionCount: 32,
  extensionDepth: 6,
  extensionNodes: 5000,
  extensionArrayItems: 1000,
  extensionObjectKeys: 128,
  extensionString: 4096,
  extensionTotalString: 64 * 1024,
});

const optionalString = (max) => z.string().max(max).nullable().optional();
const schemasSchema = z.array(z.string().min(1).max(SCIM_LIMITS.schemaUrn))
  .max(SCIM_LIMITS.schemas)
  .optional();
const nameSchema = z.object({
  formatted: optionalString(SCIM_LIMITS.formattedName),
  familyName: optionalString(SCIM_LIMITS.namePart),
  givenName: optionalString(SCIM_LIMITS.namePart),
  middleName: optionalString(SCIM_LIMITS.namePart),
  honorificPrefix: optionalString(SCIM_LIMITS.namePart),
  honorificSuffix: optionalString(SCIM_LIMITS.namePart),
}).passthrough().nullable().optional();
const multiValueMetadata = {
  display: optionalString(SCIM_LIMITS.multiValueDisplay),
  type: optionalString(SCIM_LIMITS.multiValueType),
  primary: z.boolean().optional(),
  $ref: optionalString(SCIM_LIMITS.reference),
};
const emailSchema = z.object({
  ...multiValueMetadata,
  value: z.string().min(1).max(SCIM_LIMITS.emailValue),
}).passthrough();
const phoneNumberSchema = z.object({
  ...multiValueMetadata,
  value: z.string().min(1).max(SCIM_LIMITS.phoneValue),
}).passthrough();
const groupMemberSchema = z.object({
  ...multiValueMetadata,
  value: z.string().min(1).max(SCIM_LIMITS.externalId),
}).passthrough();
const userResourceSchema = z.object({
  schemas: schemasSchema,
  userName: z.string().trim().min(1).max(SCIM_LIMITS.userName).optional(),
  externalId: optionalString(SCIM_LIMITS.externalId),
  name: nameSchema,
  displayName: optionalString(SCIM_LIMITS.displayName),
  nickName: optionalString(SCIM_LIMITS.namePart),
  title: optionalString(SCIM_LIMITS.title),
  active: z.boolean().optional(),
  emails: z.array(emailSchema).max(SCIM_LIMITS.emails).nullable().optional(),
  phoneNumbers: z.array(phoneNumberSchema).max(SCIM_LIMITS.phoneNumbers).nullable().optional(),
}).passthrough();
const groupResourceSchema = z.object({
  schemas: schemasSchema,
  displayName: z.string().trim().min(1).max(SCIM_LIMITS.displayName).optional(),
  externalId: optionalString(SCIM_LIMITS.externalId),
  members: z.array(groupMemberSchema).max(SCIM_LIMITS.groupMembers).nullable().optional(),
}).passthrough();
const patchOperationSchema = z.object({
  op: z.string().min(1).max(16),
  path: z.string().min(1).max(SCIM_LIMITS.patchPath).optional(),
  value: z.unknown().optional(),
}).passthrough();
const patchBodySchema = z.object({
  schemas: schemasSchema,
  Operations: z.array(patchOperationSchema).min(1).max(SCIM_LIMITS.patchOperations),
}).passthrough();

const RAW_BOUNDS = Object.freeze({
  maxDepth: SCIM_LIMITS.rawDepth,
  maxNodes: SCIM_LIMITS.rawNodes,
  maxArrayItems: SCIM_LIMITS.rawArrayItems,
  maxObjectKeys: SCIM_LIMITS.rawObjectKeys,
  maxKey: SCIM_LIMITS.rawKey,
  maxString: SCIM_LIMITS.rawString,
  maxTotalString: SCIM_LIMITS.rawTotalString,
});
const EXTENSION_BOUNDS = Object.freeze({
  maxDepth: SCIM_LIMITS.extensionDepth + 1,
  maxNodes: SCIM_LIMITS.extensionNodes,
  maxArrayItems: SCIM_LIMITS.extensionArrayItems,
  maxObjectKeys: SCIM_LIMITS.extensionObjectKeys,
  maxKey: SCIM_LIMITS.rawKey,
  maxString: SCIM_LIMITS.extensionString,
  maxTotalString: SCIM_LIMITS.extensionTotalString,
});
const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const NAME_SUB_ATTRIBUTES = new Set([
  'formatted', 'familyName', 'givenName', 'middleName',
  'honorificPrefix', 'honorificSuffix',
]);

function validationFailure(detail, scimType = 'invalidValue') {
  return { ok: false, error: { status: 400, detail, scimType } };
}

function schemaFailure(label, error) {
  const issue = error.issues?.[0];
  const path = issue?.path?.length ? issue.path.join('.') : label;
  const scimType = issue?.code === 'too_big' && path === 'Operations' ? 'tooMany' : 'invalidValue';
  return validationFailure(`${path} is malformed or exceeds the supported limit`, scimType);
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Iterative JSON-shape validation avoids recursive traversal on hostile depth. */
function validateJsonBounds(root, limits) {
  const seen = new WeakSet();
  const stack = [{ value: root, depth: 0 }];
  let nodes = 0;
  let totalString = 0;

  while (stack.length) {
    const { value, depth } = stack.pop();
    nodes += 1;
    if (nodes > limits.maxNodes) return `payload exceeds ${limits.maxNodes} JSON values`;
    if (depth > limits.maxDepth) return `payload exceeds maximum depth ${limits.maxDepth}`;

    if (typeof value === 'string') {
      if (value.length > limits.maxString) return `string exceeds ${limits.maxString} characters`;
      totalString += value.length;
      if (totalString > limits.maxTotalString) return `payload text exceeds ${limits.maxTotalString} characters`;
      continue;
    }
    if (value === null || typeof value === 'boolean') continue;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) return 'payload contains a non-finite number';
      continue;
    }
    if (typeof value !== 'object') return 'payload contains a non-JSON value';
    if (seen.has(value)) return 'payload contains a cycle';
    seen.add(value);

    if (Array.isArray(value)) {
      if (value.length > limits.maxArrayItems) return `array exceeds ${limits.maxArrayItems} items`;
      for (let i = value.length - 1; i >= 0; i -= 1) {
        stack.push({ value: value[i], depth: depth + 1 });
      }
      continue;
    }

    if (!isPlainObject(value)) return 'payload contains a non-JSON object';
    const keys = Object.keys(value);
    if (keys.length > limits.maxObjectKeys) return `object exceeds ${limits.maxObjectKeys} attributes`;
    for (let i = keys.length - 1; i >= 0; i -= 1) {
      const key = keys[i];
      if (key.length > limits.maxKey) return `attribute name exceeds ${limits.maxKey} characters`;
      if (DANGEROUS_KEYS.has(key)) return `attribute name ${key} is not accepted`;
      totalString += key.length;
      if (totalString > limits.maxTotalString) return `payload text exceeds ${limits.maxTotalString} characters`;
      stack.push({ value: value[key], depth: depth + 1 });
    }
  }
  return null;
}

function validateResourceEnvelope(body, label) {
  if (!isPlainObject(body)) return validationFailure(`${label} body must be a JSON object`, 'invalidSyntax');
  const boundsError = validateJsonBounds(body, RAW_BOUNDS);
  if (boundsError) return validationFailure(`${label} ${boundsError}`);
  return { ok: true };
}

function validateRawExtensions(body, label) {
  const extensions = Object.entries(body).filter(([key]) => key.startsWith('urn:'));
  if (extensions.length > SCIM_LIMITS.extensionCount) {
    return validationFailure(`${label} exceeds ${SCIM_LIMITS.extensionCount} schema extensions`, 'tooMany');
  }
  if (!extensions.length) return { ok: true };
  const boundsError = validateJsonBounds(Object.fromEntries(extensions), EXTENSION_BOUNDS);
  if (boundsError) return validationFailure(`${label} extension ${boundsError}`);
  return { ok: true };
}

function isBooleanPatchValue(value) {
  if (typeof value === 'boolean') return true;
  if (typeof value === 'string') return /^(true|false)$/i.test(value);
  if (!Array.isArray(value) || value.length !== 1) return false;
  const first = value[0];
  const nested = isPlainObject(first) && Object.prototype.hasOwnProperty.call(first, 'value')
    ? first.value
    : first;
  return typeof nested === 'boolean'
    || (typeof nested === 'string' && /^(true|false)$/i.test(nested));
}

function validatePatchTargetValue(path, value, index) {
  const normalized = normalizePath(path);
  if (normalized === 'active' && !isBooleanPatchValue(value)) {
    return validationFailure(`Operations.${index}.value must be a boolean`);
  }
  if (normalized === 'userName' && typeof value !== 'string') {
    return validationFailure(`Operations.${index}.value must be a string`);
  }
  if (['externalId', 'displayName', 'title'].includes(normalized)
      && value !== null && typeof value !== 'string') {
    return validationFailure(`Operations.${index}.value must be a string or null`);
  }
  if (normalized.startsWith('name.') && NAME_SUB_ATTRIBUTES.has(normalized.slice('name.'.length))
      && value !== null && typeof value !== 'string') {
    return validationFailure(`Operations.${index}.value must be a string or null`);
  }
  if (['emails', 'phoneNumbers', 'members'].includes(normalized)
      && !Array.isArray(value) && !isPlainObject(value)) {
    return validationFailure(`Operations.${index}.value must be a complex value or array`);
  }
  return null;
}

export function validateScimUser(body, { requireUserName = true } = {}) {
  const envelope = validateResourceEnvelope(body, 'User');
  if (!envelope.ok) return envelope;
  const parsed = userResourceSchema.safeParse(body);
  if (!parsed.success) return schemaFailure('User', parsed.error);
  if (requireUserName && (typeof body.userName !== 'string' || !body.userName.trim())) {
    return validationFailure('userName is required');
  }
  return validateRawExtensions(body, 'User');
}

export function validateScimGroup(body, { requireDisplayName = true } = {}) {
  const envelope = validateResourceEnvelope(body, 'Group');
  if (!envelope.ok) return envelope;
  const parsed = groupResourceSchema.safeParse(body);
  if (!parsed.success) return schemaFailure('Group', parsed.error);
  if (requireDisplayName && (typeof body.displayName !== 'string' || !body.displayName.trim())) {
    return validationFailure('displayName is required');
  }
  return validateRawExtensions(body, 'Group');
}

export function validateScimPatch(body) {
  const envelope = validateResourceEnvelope(body, 'PATCH');
  if (!envelope.ok) return envelope;
  if (Array.isArray(body.Operations) && body.Operations.length > SCIM_LIMITS.patchOperations) {
    return validationFailure(`Operations exceeds ${SCIM_LIMITS.patchOperations} entries`, 'tooMany');
  }
  const parsed = patchBodySchema.safeParse(body);
  if (!parsed.success) return schemaFailure('PATCH', parsed.error);

  const extensionValues = [];
  for (let index = 0; index < body.Operations.length; index += 1) {
    const operation = body.Operations[index];
    const verb = operation.op.toLowerCase();
    if (!['add', 'replace', 'remove'].includes(verb)) {
      return validationFailure(`Unsupported op at Operations.${index}`, 'invalidSyntax');
    }
    if (operation.path && /[\u0000-\u001f\u007f]/.test(operation.path)) {
      return validationFailure(`Operations.${index}.path is invalid`, 'invalidPath');
    }
    if (verb === 'remove' && !operation.path) {
      return validationFailure('remove requires a path', 'noTarget');
    }
    if (verb !== 'remove' && !Object.prototype.hasOwnProperty.call(operation, 'value')) {
      return validationFailure(`Operations.${index}.value is required`);
    }
    if (!operation.path && !isPlainObject(operation.value)) {
      return validationFailure(`Operations.${index}.value must be an attribute object`);
    }
    if (verb !== 'remove' && operation.path) {
      const targetError = validatePatchTargetValue(operation.path, operation.value, index);
      if (targetError) return targetError;
    }
    if (operation.path?.startsWith('urn:')) extensionValues.push(operation.value);
    if (!operation.path) {
      for (const [key, value] of Object.entries(operation.value)) {
        const targetError = validatePatchTargetValue(key, value, index);
        if (targetError) return targetError;
        if (key.startsWith('urn:')) extensionValues.push(value);
      }
    }
  }

  if (extensionValues.length > SCIM_LIMITS.extensionCount) {
    return validationFailure(`PATCH exceeds ${SCIM_LIMITS.extensionCount} schema extension values`, 'tooMany');
  }
  if (extensionValues.length) {
    const boundsError = validateJsonBounds(extensionValues, EXTENSION_BOUNDS);
    if (boundsError) return validationFailure(`PATCH extension ${boundsError}`);
  }
  return { ok: true };
}

// ── Errors ───────────────────────────────────────────────────────────────────

/** SCIM error envelope (RFC 7644 §3.12). */
export function scimError(status, detail, scimType) {
  const body = { schemas: [SCIM.ERROR], status: String(status), detail };
  if (scimType) body.scimType = scimType;
  return body;
}

// ── ETag ─────────────────────────────────────────────────────────────────────

export function etag(version) {
  return `W/"${version}"`;
}

// ── User mapping ─────────────────────────────────────────────────────────────

/** EP row → SCIM User resource. */
export function toScimUser(row, baseUrl = '') {
  const resource = {
    schemas: [SCIM.USER],
    id: row.id,
    userName: row.user_name,
    active: row.active !== false,
    meta: {
      resourceType: 'User',
      created: iso(row.created_at),
      lastModified: iso(row.updated_at),
      location: `${baseUrl}/Users/${row.id}`,
      version: etag(row.version ?? 1),
    },
  };
  if (row.external_id) resource.externalId = row.external_id;

  const name = {};
  if (row.formatted_name) name.formatted = row.formatted_name;
  if (row.given_name) name.givenName = row.given_name;
  if (row.family_name) name.familyName = row.family_name;
  if (Object.keys(name).length) resource.name = name;

  if (row.display_name) resource.displayName = row.display_name;
  if (row.title) resource.title = row.title;
  if (Array.isArray(row.emails) && row.emails.length) resource.emails = row.emails;
  if (Array.isArray(row.phone_numbers) && row.phone_numbers.length) resource.phoneNumbers = row.phone_numbers;
  return resource;
}

/** SCIM User resource (create/replace body, or patched resource) → EP row fields. */
export function fromScimUser(body) {
  const name = body.name || {};
  const emails = Array.isArray(body.emails) ? body.emails : [];
  return {
    user_name: normalizeUserName(body.userName),
    external_id: str(body.externalId) || null,
    active: body.active !== false,
    formatted_name: str(name.formatted) || null,
    given_name: str(name.givenName) || null,
    family_name: str(name.familyName) || null,
    display_name: str(body.displayName) || null,
    title: str(body.title) || null,
    emails,
    phone_numbers: Array.isArray(body.phoneNumbers) ? body.phoneNumbers : [],
    // Preserve the full inbound resource minus volatile/server-owned fields.
    raw: stripServerFields(body),
  };
}

// ── Group mapping ────────────────────────────────────────────────────────────

export function toScimGroup(row, baseUrl = '') {
  const resource = {
    schemas: [SCIM.GROUP],
    id: row.id,
    displayName: row.display_name,
    members: Array.isArray(row.members) ? row.members : [],
    meta: {
      resourceType: 'Group',
      created: iso(row.created_at),
      lastModified: iso(row.updated_at),
      location: `${baseUrl}/Groups/${row.id}`,
      version: etag(row.version ?? 1),
    },
  };
  if (row.external_id) resource.externalId = row.external_id;
  return resource;
}

export function fromScimGroup(body) {
  return {
    display_name: str(body.displayName),
    external_id: str(body.externalId) || null,
    members: Array.isArray(body.members) ? body.members : [],
    raw: stripServerFields(body),
  };
}

// ── List response ────────────────────────────────────────────────────────────

export function listResponse(resources, { totalResults, startIndex = 1, itemsPerPage } = {}) {
  return {
    schemas: [SCIM.LIST],
    totalResults: totalResults ?? resources.length,
    startIndex,
    itemsPerPage: itemsPerPage ?? resources.length,
    Resources: resources,
  };
}

// ── Filter parsing (RFC 7644 §3.4.2.2 — the IdP-used subset) ──────────────────

const FILTERABLE = new Set(['userName', 'externalId', 'active', 'displayName', 'id']);

/**
 * Parse a SCIM filter. Supports the single-term equality filters Okta/Azure/Ping
 * use for provisioning lookups: `attr eq "value"` (and `active eq true`).
 *
 * @returns {null | {attribute, operator:'eq', value} | {unsupported:true, raw}}
 *   null when no filter is present; an `unsupported` marker the route turns into
 *   a precise 400 for anything outside the supported subset.
 */
export function parseFilter(filter) {
  if (!filter || !String(filter).trim()) return null;
  const raw = String(filter).trim();

  // attr eq "value"  |  attr eq true/false
  const m = raw.match(/^(\w+)\s+(eq)\s+(?:"([^"]*)"|(true|false))$/i);
  if (!m) return { unsupported: true, raw };

  const attribute = m[1];
  if (!FILTERABLE.has(attribute)) return { unsupported: true, raw };

  let value = m[3];
  if (value === undefined) value = m[4].toLowerCase() === 'true';
  return { attribute, operator: 'eq', value };
}

// ── PATCH (RFC 7644 §3.5.2) ──────────────────────────────────────────────────

/**
 * Apply a PatchOp body to a SCIM resource, returning the patched resource.
 *
 * Supports add / replace / remove with the paths IdPs use for User and Group
 * provisioning, including the two shapes Azure AD sends for deprovision:
 *   { op:'replace', path:'active', value:false }
 *   { op:'replace', value:{ active:false } }   // no path → value is an attr map
 *
 * Unknown paths are ignored (a SCIM server may ignore attributes it does not
 * model) rather than failing the whole request.
 *
 * @returns {{ resource: object } | { error: {status, detail, scimType} }}
 */
export function applyPatch(resource, body) {
  const validation = validateScimPatch(body);
  if (!validation.ok) return { error: validation.error };
  const next = structuredCloneSafe(resource);

  for (const op of body.Operations) {
    const verb = String(op.op || '').toLowerCase();
    // No path: value is a map of attributes (replace/add each).
    if (!op.path) {
      for (const [k, v] of Object.entries(op.value)) setAttr(next, k, v, verb);
      continue;
    }

    const path = String(op.path);
    if (verb === 'remove') {
      removeAttr(next, path);
    } else {
      setAttr(next, path, op.value, verb);
    }
  }
  return { resource: next };
}

// Map a SCIM path to our resource shape. Handles dotted sub-attributes
// (name.givenName) and the common top-level attributes. `verb` distinguishes
// add (append to multi-valued attrs) from replace (overwrite).
function setAttr(resource, path, value, verb = 'replace') {
  const p = normalizePath(path);
  if (p === 'active') { resource.active = coerceBool(value); return; }
  if (p === 'userName') { resource.userName = value; return; }
  if (p === 'externalId') { resource.externalId = value; return; }
  if (p === 'displayName') { resource.displayName = value; return; }
  if (p === 'title') { resource.title = value; return; }
  if (p === 'emails') { resource.emails = mergeMultiValued(resource.emails, value, verb); return; }
  if (p === 'phoneNumbers') { resource.phoneNumbers = mergeMultiValued(resource.phoneNumbers, value, verb); return; }
  if (p === 'members') { resource.members = mergeMultiValued(resource.members, value, verb); return; }
  if (p.startsWith('name.') && NAME_SUB_ATTRIBUTES.has(p.slice('name.'.length))) {
    resource.name = resource.name || {};
    resource.name[p.slice('name.'.length)] = value;
    return;
  }
  // Unknown attribute — ignore (lenient server behavior).
}

function removeAttr(resource, path) {
  const p = normalizePath(path);
  // members[value eq "x"] — remove a single group member (Azure).
  const memberMatch = path.match(/^members\[value\s+eq\s+"?([^"\]]+)"?\]$/i);
  if (memberMatch) {
    const id = memberMatch[1];
    resource.members = (resource.members || []).filter((m) => String(m.value) !== id);
    return;
  }
  if (p === 'members') { resource.members = []; return; }
  if (p === 'emails') { resource.emails = []; return; }
  if (p === 'active') { resource.active = false; return; }
  if (p.startsWith('name.') && resource.name && NAME_SUB_ATTRIBUTES.has(p.slice('name.'.length))) {
    delete resource.name[p.slice('name.'.length)];
    return;
  }
  if (p in resource) delete resource[p];
}

// ── ServiceProviderConfig / ResourceTypes / Schemas ──────────────────────────

export function serviceProviderConfig(baseUrl = '') {
  return {
    schemas: [SCIM.SPC],
    documentationUri: 'https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/SCIM.md',
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: true },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'Authentication via the SCIM provisioning token issued by EP.',
        primary: true,
      },
    ],
    meta: { resourceType: 'ServiceProviderConfig', location: `${baseUrl}/ServiceProviderConfig` },
  };
}

export function resourceTypes(baseUrl = '') {
  const types = [
    {
      schemas: [SCIM.RESOURCE_TYPE], id: 'User', name: 'User', endpoint: '/Users',
      description: 'User Account', schema: SCIM.USER,
      meta: { resourceType: 'ResourceType', location: `${baseUrl}/ResourceTypes/User` },
    },
    {
      schemas: [SCIM.RESOURCE_TYPE], id: 'Group', name: 'Group', endpoint: '/Groups',
      description: 'Group', schema: SCIM.GROUP,
      meta: { resourceType: 'ResourceType', location: `${baseUrl}/ResourceTypes/Group` },
    },
  ];
  return listResponse(types, { totalResults: types.length });
}

// ── helpers ──────────────────────────────────────────────────────────────────

function normalizePath(path) {
  // Strip a schema-URN prefix if present (e.g. "urn:...:User:active" → "active").
  const idx = path.lastIndexOf(':');
  return idx >= 0 && path.slice(0, idx).startsWith('urn:') ? path.slice(idx + 1) : path;
}
// Multi-valued attribute merge. `add` appends new entries (deduped by `value`);
// `replace` overwrites the whole set. RFC 7644 §3.5.2.1/.3.
function mergeMultiValued(existing, value, verb) {
  const incoming = Array.isArray(value) ? value : [value];
  if (verb !== 'add') return incoming;
  const current = Array.isArray(existing) ? existing : [];
  const seen = new Set(current.map((e) => String(e?.value ?? e)));
  const appended = incoming.filter((e) => !seen.has(String(e?.value ?? e)));
  return [...current, ...appended];
}
function coerceBool(v) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.toLowerCase() === 'true';
  if (Array.isArray(v) && v.length) return coerceBool(v[0].value ?? v[0]);
  return Boolean(v);
}
function str(v) { return typeof v === 'string' ? v.trim() : (v == null ? '' : String(v)); }

/**
 * Canonical userName normalization — applied identically on the SCIM WRITE side
 * (provisioning) and the SSO READ side (SAML/OIDC directory lookup) so an IdP
 * that asserts `Alice@Example.COM` resolves to a `alice@example.com` provisioned
 * row. Lower-case + trim; both sides MUST use this exact function.
 */
export function normalizeUserName(v) {
  return str(v).toLowerCase();
}
function iso(t) {
  if (!t) return undefined;
  try { return new Date(t).toISOString(); } catch { return undefined; }
}
function stripServerFields(body) {
  const clone = structuredCloneSafe(body || {});
  delete clone.id;
  delete clone.meta;
  return clone;
}
function structuredCloneSafe(obj) {
  if (typeof structuredClone === 'function') return structuredClone(obj);
  return JSON.parse(JSON.stringify(obj));
}
