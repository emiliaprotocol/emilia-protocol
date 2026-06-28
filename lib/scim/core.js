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
  if (!body || !Array.isArray(body.Operations)) {
    return { error: { status: 400, detail: 'PATCH body must contain Operations', scimType: 'invalidValue' } };
  }
  const next = structuredCloneSafe(resource);

  for (const op of body.Operations) {
    const verb = String(op.op || '').toLowerCase();
    if (!['add', 'replace', 'remove'].includes(verb)) {
      return { error: { status: 400, detail: `Unsupported op: ${op.op}`, scimType: 'invalidSyntax' } };
    }

    // No path: value is a map of attributes (replace/add each).
    if (!op.path) {
      if (verb === 'remove') {
        return { error: { status: 400, detail: 'remove requires a path', scimType: 'noTarget' } };
      }
      if (op.value && typeof op.value === 'object') {
        for (const [k, v] of Object.entries(op.value)) setAttr(next, k, v, verb);
      }
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
  if (p.startsWith('name.')) {
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
  if (p.startsWith('name.') && resource.name) { delete resource.name[p.slice('name.'.length)]; return; }
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
