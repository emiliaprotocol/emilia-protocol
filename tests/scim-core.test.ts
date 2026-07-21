/**
 * SCIM 2.0 core — unit tests (RFC 7643 / RFC 7644).
 *
 * Proves the resource mapping, filter parsing, and PATCH application that the
 * /api/scim/v2/* routes depend on — fully deterministic, no database. These are
 * the cases real IdPs (Okta, Azure AD, Ping) actually send, including both
 * shapes Azure uses to deprovision a user.
 */

import { describe, it, expect } from 'vitest';
import {
  SCIM, scimError, toScimUser, fromScimUser, toScimGroup, fromScimGroup,
  listResponse, parseFilter, applyPatch, serviceProviderConfig, resourceTypes,
  SCIM_LIMITS, validateScimUser, validateScimGroup, validateScimPatch,
} from '../lib/scim/core.js';

const userRow = {
  id: '11111111-1111-1111-1111-111111111111',
  tenant_id: 'ep_entity_acme',
  external_id: '701984',
  user_name: 'bjensen@example.com',
  active: true,
  given_name: 'Barbara',
  family_name: 'Jensen',
  display_name: 'Barbara Jensen',
  emails: [{ value: 'bjensen@example.com', primary: true, type: 'work' }],
  title: 'Auditor',
  version: 3,
  created_at: '2026-06-01T00:00:00.000Z',
  updated_at: '2026-06-10T00:00:00.000Z',
};

describe('SCIM User mapping', () => {
  it('toScimUser produces an RFC 7643 User resource', () => {
    const u = toScimUser(userRow, 'https://x/api/scim/v2');
    expect(u.schemas).toEqual([SCIM.USER]);
    expect(u.id).toBe(userRow.id);
    expect(u.userName).toBe('bjensen@example.com');
    expect(u.externalId).toBe('701984');
    expect(u.active).toBe(true);
    expect(u.name).toEqual({ givenName: 'Barbara', familyName: 'Jensen' });
    expect(u.displayName).toBe('Barbara Jensen');
    expect(u.meta.resourceType).toBe('User');
    expect(u.meta.location).toBe('https://x/api/scim/v2/Users/' + userRow.id);
    expect(u.meta.version).toBe('W/"3"');
  });

  it('fromScimUser maps a create body to columns', () => {
    const fields = fromScimUser({
      schemas: [SCIM.USER],
      userName: 'newuser@example.com',
      externalId: 'abc',
      name: { givenName: 'New', familyName: 'User', formatted: 'New User' },
      displayName: 'New User',
      active: true,
      emails: [{ value: 'newuser@example.com' }],
    });
    expect(fields.user_name).toBe('newuser@example.com');
    expect(fields.external_id).toBe('abc');
    expect(fields.given_name).toBe('New');
    expect(fields.family_name).toBe('User');
    expect(fields.formatted_name).toBe('New User');
    expect(fields.active).toBe(true);
    expect(fields.emails).toHaveLength(1);
  });

  it('defaults active to true when absent and false when explicitly false', () => {
    expect(fromScimUser({ userName: 'a' }).active).toBe(true);
    expect(fromScimUser({ userName: 'a', active: false }).active).toBe(false);
  });

  it('round-trips userName + name through to/from', () => {
    const back = fromScimUser(toScimUser(userRow));
    expect(back.user_name).toBe(userRow.user_name);
    expect(back.given_name).toBe('Barbara');
    expect(back.family_name).toBe('Jensen');
  });
});

describe('SCIM Group mapping', () => {
  const groupRow = {
    id: 'g1', tenant_id: 't', display_name: 'Approvers',
    members: [{ value: 'u1', display: 'bjensen' }], version: 1,
    created_at: '2026-06-01T00:00:00Z', updated_at: '2026-06-01T00:00:00Z',
  };
  it('toScimGroup produces a Group resource', () => {
    const g = toScimGroup(groupRow, 'https://x/api/scim/v2');
    expect(g.schemas).toEqual([SCIM.GROUP]);
    expect(g.displayName).toBe('Approvers');
    expect(g.members).toHaveLength(1);
    expect(g.meta.location).toBe('https://x/api/scim/v2/Groups/g1');
  });
  it('fromScimGroup maps displayName + members', () => {
    const f = fromScimGroup({ displayName: 'Auditors', members: [{ value: 'u2' }] });
    expect(f.display_name).toBe('Auditors');
    expect(f.members).toHaveLength(1);
  });
});

describe('SCIM filter parsing', () => {
  it('parses userName eq', () => {
    expect(parseFilter('userName eq "bjensen@example.com"')).toEqual({
      attribute: 'userName', operator: 'eq', value: 'bjensen@example.com',
    });
  });
  it('parses externalId eq', () => {
    expect(parseFilter('externalId eq "701984"')).toEqual({
      attribute: 'externalId', operator: 'eq', value: '701984',
    });
  });
  it('parses active eq true as a boolean', () => {
    expect(parseFilter('active eq true')).toEqual({ attribute: 'active', operator: 'eq', value: true });
  });
  it('returns null for no filter', () => {
    expect(parseFilter('')).toBeNull();
    expect(parseFilter(undefined)).toBeNull();
  });
  it('marks unsupported operators and attributes', () => {
    expect(parseFilter('userName co "jen"').unsupported).toBe(true);
    expect(parseFilter('displayName sw "A"').unsupported).toBe(true);
    expect(parseFilter('emails.value eq "x"').unsupported).toBe(true); // sub-attr not supported
  });
});

describe('SCIM PATCH (RFC 7644 §3.5.2)', () => {
  const base = () => toScimUser(userRow);

  it('Azure deprovision shape A: replace path=active value=false', () => {
    const { resource } = applyPatch(base(), {
      schemas: [SCIM.PATCH_OP],
      Operations: [{ op: 'replace', path: 'active', value: false }],
    });
    expect(resource.active).toBe(false);
  });

  it('Azure deprovision shape B: replace no-path value={active:false}', () => {
    const { resource } = applyPatch(base(), {
      schemas: [SCIM.PATCH_OP],
      Operations: [{ op: 'Replace', value: { active: false } }],
    });
    expect(resource.active).toBe(false);
  });

  it('coerces string "False" to boolean', () => {
    const { resource } = applyPatch(base(), {
      Operations: [{ op: 'replace', path: 'active', value: 'False' }],
    });
    expect(resource.active).toBe(false);
  });

  it('replaces a nested name sub-attribute', () => {
    const { resource } = applyPatch(base(), {
      Operations: [{ op: 'replace', path: 'name.givenName', value: 'Barb' }],
    });
    expect(resource.name.givenName).toBe('Barb');
    expect(resource.name.familyName).toBe('Jensen'); // untouched
  });

  it('add appends a group member; replace overwrites; remove drops one', () => {
    const group = toScimGroup({ id: 'g', display_name: 'Approvers', members: [{ value: 'u1' }], version: 1 });
    // add → append (dedupe by value)
    const added = applyPatch(group, { Operations: [{ op: 'add', path: 'members', value: [{ value: 'u2' }] }] }).resource;
    expect(added.members).toEqual([{ value: 'u1' }, { value: 'u2' }]);
    // adding an existing member is idempotent
    const again = applyPatch(added, { Operations: [{ op: 'add', path: 'members', value: [{ value: 'u2' }] }] }).resource;
    expect(again.members).toHaveLength(2);
    // replace → overwrite the set
    const replaced = applyPatch(added, { Operations: [{ op: 'replace', path: 'members', value: [{ value: 'u9' }] }] }).resource;
    expect(replaced.members).toEqual([{ value: 'u9' }]);
    // remove a single member by filter
    const removed = applyPatch(
      { ...group, members: [{ value: 'u1' }, { value: 'u2' }] },
      { Operations: [{ op: 'remove', path: 'members[value eq "u1"]' }] },
    ).resource;
    expect(removed.members).toEqual([{ value: 'u2' }]);
  });

  it('ignores unknown paths instead of failing', () => {
    const { resource, error } = applyPatch(base(), {
      Operations: [{ op: 'replace', path: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department', value: 'Audit' }],
    });
    expect(error).toBeUndefined();
    expect(resource.userName).toBe('bjensen@example.com'); // unchanged
  });

  it('rejects an unsupported op', () => {
    const { error } = applyPatch(base(), { Operations: [{ op: 'merge', path: 'active', value: false }] });
    expect(error.status).toBe(400);
    expect(error.scimType).toBe('invalidSyntax');
  });

  it('rejects remove without a path', () => {
    const { error } = applyPatch(base(), { Operations: [{ op: 'remove' }] });
    expect(error.status).toBe(400);
    expect(error.scimType).toBe('noTarget');
  });

  it('rejects a body without Operations', () => {
    const { error } = applyPatch(base(), { foo: 'bar' });
    expect(error.status).toBe(400);
  });
});

describe('SCIM bounded validation', () => {
  const enterprise = SCIM.ENTERPRISE_USER;

  function nested(depth) {
    let value = 'leaf';
    for (let i = 0; i < depth; i += 1) value = { next: value };
    return value;
  }

  it('accepts bounded RFC extensions verbatim without storage-time HTML escaping', () => {
    const body = {
      schemas: [SCIM.USER, enterprise],
      userName: 'bounded@example.com',
      name: { formatted: 'Bounded User', givenName: 'Bounded', familyName: 'User' },
      title: 'Auditor',
      externalId: 'idp-123',
      emails: [{ value: 'bounded@example.com', type: 'work', primary: true }],
      phoneNumbers: [{ value: '+1-555-0100', type: 'work' }],
      [enterprise]: { department: '<script>literal extension data</script>' },
    };
    expect(validateScimUser(body).ok).toBe(true);
    expect(fromScimUser(body).raw[enterprise].department).toBe('<script>literal extension data</script>');
  });

  it.each([
    ['userName', { userName: 'u'.repeat(SCIM_LIMITS.userName + 1) }],
    ['name.givenName', { userName: 'u', name: { givenName: 'n'.repeat(SCIM_LIMITS.namePart + 1) } }],
    ['title', { userName: 'u', title: 't'.repeat(SCIM_LIMITS.title + 1) }],
    ['externalId', { userName: 'u', externalId: 'e'.repeat(SCIM_LIMITS.externalId + 1) }],
    ['email value', { userName: 'u', emails: [{ value: 'e'.repeat(SCIM_LIMITS.emailValue + 1) }] }],
    ['phone value', { userName: 'u', phoneNumbers: [{ value: 'p'.repeat(SCIM_LIMITS.phoneValue + 1) }] }],
    ['malformed email', { userName: 'u', emails: [42] }],
    ['malformed phone', { userName: 'u', phoneNumbers: [{ value: { nested: true } }] }],
  ])('rejects an invalid or oversized user %s', (_label, body) => {
    const result = validateScimUser(body);
    expect(result.ok).toBe(false);
    expect(result.error).toMatchObject({ status: 400, scimType: 'invalidValue' });
  });

  it('caps email and phone entry counts', () => {
    const emails = Array.from({ length: SCIM_LIMITS.emails + 1 }, (_, i) => ({ value: `u${i}@example.com` }));
    const phoneNumbers = Array.from({ length: SCIM_LIMITS.phoneNumbers + 1 }, (_, i) => ({ value: `+1555${i}` }));
    expect(validateScimUser({ userName: 'u', emails }).ok).toBe(false);
    expect(validateScimUser({ userName: 'u', phoneNumbers }).ok).toBe(false);
  });

  it('rejects deep and oversized raw extensions', () => {
    const deep = validateScimUser({ userName: 'u', [enterprise]: nested(SCIM_LIMITS.extensionDepth + 2) });
    const long = validateScimUser({
      userName: 'u',
      [enterprise]: { department: 'x'.repeat(SCIM_LIMITS.extensionString + 1) },
    });
    expect(deep.ok).toBe(false);
    expect(long.ok).toBe(false);
    expect(deep.error.scimType).toBe('invalidValue');
    expect(long.error.scimType).toBe('invalidValue');
  });

  it('bounds group names and member payloads', () => {
    const tooManyMembers = Array.from(
      { length: SCIM_LIMITS.groupMembers + 1 },
      (_, i) => ({ value: `user-${i}` }),
    );
    expect(validateScimGroup({ displayName: 'g'.repeat(SCIM_LIMITS.displayName + 1) }).ok).toBe(false);
    expect(validateScimGroup({ displayName: 'Approvers', members: [{ value: { id: 'u1' } }] }).ok).toBe(false);
    expect(validateScimGroup({ displayName: 'Approvers', members: tooManyMembers }).ok).toBe(false);
  });

  it('bounds PATCH count, path length, nesting, and operation shape', () => {
    const tooMany = {
      Operations: Array.from(
        { length: SCIM_LIMITS.patchOperations + 1 },
        () => ({ op: 'replace', path: 'active', value: false }),
      ),
    };
    const longPath = {
      Operations: [{ op: 'replace', path: 'x'.repeat(SCIM_LIMITS.patchPath + 1), value: true }],
    };
    const deepValue = {
      Operations: [{ op: 'replace', path: enterprise, value: nested(SCIM_LIMITS.rawDepth + 1) }],
    };
    expect(validateScimPatch(tooMany).error.scimType).toBe('tooMany');
    expect(validateScimPatch(longPath).ok).toBe(false);
    expect(validateScimPatch(deepValue).ok).toBe(false);
    expect(validateScimPatch({ Operations: [null] }).ok).toBe(false);
    expect(validateScimPatch({ Operations: [{ op: 'replace', path: 'active' }] }).ok).toBe(false);
    expect(validateScimPatch({
      Operations: [{ op: 'replace', path: 'active', value: { truthy: true } }],
    }).ok).toBe(false);
    expect(validateScimPatch({
      Operations: [{ op: 'replace', value: { active: 'not-a-boolean' } }],
    }).ok).toBe(false);
  });

  it('fails closed on prototype-oriented PATCH paths', () => {
    const original = baseUser();
    const result = applyPatch(original, {
      Operations: [{ op: 'replace', path: 'name.__proto__', value: { polluted: true } }],
    });
    expect(result.error).toBeUndefined();
    expect(result.resource.name.polluted).toBeUndefined();
    expect(Object.prototype.polluted).toBeUndefined();
  });

  function baseUser() {
    return toScimUser(userRow);
  }
});

describe('SCIM envelopes', () => {
  it('listResponse wraps resources', () => {
    const r = listResponse([{ id: '1' }], { totalResults: 5, startIndex: 1, itemsPerPage: 1 });
    expect(r.schemas).toEqual([SCIM.LIST]);
    expect(r.totalResults).toBe(5);
    expect(r.Resources).toHaveLength(1);
  });
  it('scimError is an RFC 7644 error envelope', () => {
    const e = scimError(409, 'exists', 'uniqueness');
    expect(e.schemas).toEqual([SCIM.ERROR]);
    expect(e.status).toBe('409');
    expect(e.scimType).toBe('uniqueness');
  });
  it('serviceProviderConfig advertises patch + filter + bearer auth', () => {
    const spc = serviceProviderConfig('https://x');
    expect(spc.patch.supported).toBe(true);
    expect(spc.filter.supported).toBe(true);
    expect(spc.authenticationSchemes[0].type).toBe('oauthbearertoken');
  });
  it('resourceTypes lists User and Group', () => {
    const rt = resourceTypes('https://x');
    const ids = rt.Resources.map((r) => r.id);
    expect(ids).toEqual(['User', 'Group']);
  });
});
