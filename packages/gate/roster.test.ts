/**
 * @emilia-protocol/gate roster tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { importRoster, diffRoster, applyRosterToRegistry, ROSTER_VERSION } from './roster.js';
import { createKeyRegistry } from './key-registry.js';

const AT = '2026-07-04T00:00:00.000Z';
const AT2 = '2026-07-05T00:00:00.000Z';
const SRC = 'scim:okta:acme';

function u(id, userName, active, keys = []) { return { id, userName, active, keys }; }
function k(kid, publicKey = `pk_${kid}`) { return { kid, publicKey }; }

test('imports SCIM users into a versioned, sorted roster', () => {
  const roster = importRoster([
    u('u2', 'bob@acme.com', true, [k('kb1')]),
    u('u1', 'alice@acme.com', true, [k('ka2'), k('ka1')]),
  ], { source: SRC, importedAt: AT });
  assert.equal(roster.version, ROSTER_VERSION);
  assert.equal(roster.version, 'EP-GATE-ROSTER-v1');
  assert.equal(roster.source, SRC);
  assert.equal(roster.imported_at, AT);
  assert.deepEqual(roster.integrity_warnings, []);
  assert.deepEqual(roster.signers, [
    { principal: 'alice@acme.com', kid: 'ka1', publicKey: 'pk_ka1', active: true },
    { principal: 'alice@acme.com', kid: 'ka2', publicKey: 'pk_ka2', active: true },
    { principal: 'bob@acme.com', kid: 'kb1', publicKey: 'pk_kb1', active: true },
  ]);
});

test('inactive user is carried active:false and their key is never pinned', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u2', 'mallory', false, [k('km')]),
  ], { source: SRC, importedAt: AT });
  assert.deepEqual(roster.signers.find((s) => s.principal === 'mallory'),
    { principal: 'mallory', kid: 'km', publicKey: 'pk_km', active: false });
  const reg = createKeyRegistry();
  const res = applyRosterToRegistry(roster, reg);
  assert.deepEqual(res.pinned, [{ principal: 'alice', kid: 'ka' }]);
  const keys = reg.keysValidAt(AT);
  assert.ok(keys.includes('pk_ka'));
  assert.ok(!keys.includes('pk_km'));
});

test('non-boolean active is treated as inactive (fail closed)', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u2', 'bob', 'yes', [k('kb')]), // truthy but not boolean true
  ], { source: SRC, importedAt: AT });
  assert.equal(roster.signers.find((s) => s.principal === 'bob').active, false);
  const reg = createKeyRegistry();
  applyRosterToRegistry(roster, reg);
  assert.ok(!reg.keysValidAt(AT).includes('pk_kb'));
});

test('empty import is refused without allowEmpty (mass-deprovision guard)', () => {
  assert.throws(() => importRoster([], { source: SRC, importedAt: AT }), /mass-deprovision/);
  const roster = importRoster([], { source: SRC, importedAt: AT, allowEmpty: true });
  assert.deepEqual(roster.signers, []);
});

test('an import with zero ACTIVE signers also trips the mass-deprovision guard', () => {
  const allInactive = [u('u1', 'alice', false, [k('ka')])];
  assert.throws(() => importRoster(allInactive, { source: SRC, importedAt: AT }), /mass-deprovision/);
  const roster = importRoster(allInactive, { source: SRC, importedAt: AT, allowEmpty: true });
  assert.equal(roster.signers.length, 1);
  assert.equal(roster.signers[0].active, false);
  // keyless-active-users-only is the same zero-approver hazard
  assert.throws(() => importRoster([u('u1', 'alice', true, [])], { source: SRC, importedAt: AT }), /mass-deprovision/);
});

test('import rejects bad arguments (non-array, missing source, invalid importedAt)', () => {
  assert.throws(() => importRoster('nope', { source: SRC, importedAt: AT }), /array/);
  assert.throws(() => importRoster([u('u1', 'alice', true, [k('ka')])], { importedAt: AT }), /source/);
  assert.throws(() => importRoster([u('u1', 'alice', true, [k('ka')])], { source: SRC, importedAt: 'garbage' }), /importedAt/);
});

test('malformed users and keys are excluded with integrity warnings', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    { id: 'u2', active: true, keys: [k('kb')] }, // no userName
    u('u3', 'carol', true, [{ kid: 'kc' }]),     // key missing publicKey
  ], { source: SRC, importedAt: AT });
  const codes = roster.integrity_warnings.map((w) => w.code);
  assert.ok(codes.includes('malformed_user'));
  assert.ok(codes.includes('malformed_key'));
  assert.deepEqual(roster.signers, [{ principal: 'alice', kid: 'ka', publicKey: 'pk_ka', active: true }]);
});

test('duplicate kid across two principals fails closed: warning recorded, neither pinned', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('shared', 'pk_a')]),
    u('u2', 'bob', true, [k('shared', 'pk_b')]),
    u('u3', 'carol', true, [k('kc')]),
  ], { source: SRC, importedAt: AT });
  const w = roster.integrity_warnings.find((x) => x.code === 'duplicate_kid');
  assert.ok(w);
  assert.equal(w.kid, 'shared');
  assert.deepEqual(w.principals, ['alice', 'bob']);
  assert.deepEqual(roster.signers.map((s) => s.kid), ['kc']);
  const reg = createKeyRegistry();
  applyRosterToRegistry(roster, reg);
  const keys = reg.keysValidAt(AT);
  assert.ok(!keys.includes('pk_a'));
  assert.ok(!keys.includes('pk_b'));
  assert.ok(keys.includes('pk_kc'));
});

test('one kid with two different key materials (same principal) is contested too', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('kx', 'pk_1'), k('kx', 'pk_2')]),
    u('u2', 'bob', true, [k('kb')]),
  ], { source: SRC, importedAt: AT });
  assert.ok(roster.integrity_warnings.some((w) => w.code === 'duplicate_kid' && w.kid === 'kx'));
  assert.deepEqual(roster.signers.map((s) => s.kid), ['kb']);
});

test('two IdP users claiming one principal are both excluded with a warning', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('k1')]),
    u('u2', 'alice', true, [k('k2')]),
    u('u3', 'bob', true, [k('kb')]),
  ], { source: SRC, importedAt: AT });
  assert.ok(roster.integrity_warnings.some((w) => w.code === 'duplicate_principal' && w.principal === 'alice'));
  assert.deepEqual(roster.signers.map((s) => s.principal), ['bob']);
});

test('diffRoster reports added, removed, deactivated', () => {
  const prev = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u2', 'bob', true, [k('kb')]),
    u('u3', 'carol', true, [k('kc')]),
  ], { source: SRC, importedAt: AT });
  const next = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u3', 'carol', false, [k('kc')]),
    u('u4', 'dave', true, [k('kd')]),
  ], { source: SRC, importedAt: AT2 });
  const d = diffRoster(prev, next);
  assert.deepEqual(d.added, [{ principal: 'dave', kids: ['kd'] }]);
  assert.deepEqual(d.removed, [{ principal: 'bob', kids: ['kb'] }]);
  assert.deepEqual(d.deactivated, [{ principal: 'carol', kids: ['kc'] }]);
});

test('diffRoster rejects non-roster inputs', () => {
  const roster = importRoster([u('u1', 'alice', true, [k('ka')])], { source: SRC, importedAt: AT });
  assert.throws(() => diffRoster({}, roster), /EP-GATE-ROSTER-v1/);
  assert.throws(() => diffRoster(roster, { version: 'EP-GATE-ROSTER-v2', signers: [] }), /EP-GATE-ROSTER-v1/);
  assert.throws(() => diffRoster(roster, { version: ROSTER_VERSION, signers: [{ principal: 'x' }] }), /malformed signer/);
});

test('disappeared and deactivated users land in the revocation list and stop verifying', () => {
  const prev = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u2', 'bob', true, [k('kb')]),
    u('u3', 'carol', true, [k('kc')]),
  ], { source: SRC, importedAt: AT });
  const next = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u3', 'carol', false, [k('kc')]), // deactivated
    u('u4', 'dave', true, [k('kd')]),   // bob disappeared entirely
  ], { source: SRC, importedAt: AT2 });
  const reg = createKeyRegistry();
  applyRosterToRegistry(prev, reg);
  assert.deepEqual(reg.keysValidAt(AT).sort(), ['pk_ka', 'pk_kb', 'pk_kc']);
  const res = applyRosterToRegistry(next, reg);
  assert.deepEqual(res.pinned, [{ principal: 'dave', kid: 'kd' }]);
  assert.deepEqual(res.revoked.map((r) => r.kid).sort(), ['kb', 'kc']);
  assert.ok(res.revoked.every((r) => r.reason === 'absent_or_inactive'));
  const keys = reg.keysValidAt(AT2);
  assert.deepEqual(keys.sort(), ['pk_ka', 'pk_kd']);
  // revocation timestamp defaults to the roster's imported_at
  assert.equal(reg.status().find((e) => e.kid === 'kb').revoked_at, Date.parse(AT2));
});

test('reapplying the same roster is idempotent', () => {
  const roster = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u2', 'bob', true, [k('kb')]),
  ], { source: SRC, importedAt: AT });
  const reg = createKeyRegistry();
  applyRosterToRegistry(roster, reg);
  const res = applyRosterToRegistry(roster, reg);
  assert.deepEqual(res.pinned, []);
  assert.deepEqual(res.already_pinned.sort(), ['ka', 'kb']);
  assert.deepEqual(res.revoked, []);
  assert.deepEqual(res.refused, []);
});

test('a previously revoked kid is never re-pinned (rehire gets a new key)', () => {
  const withBob = importRoster([
    u('u1', 'alice', true, [k('ka')]),
    u('u2', 'bob', true, [k('kb')]),
  ], { source: SRC, importedAt: AT });
  const withoutBob = importRoster([
    u('u1', 'alice', true, [k('ka')]),
  ], { source: SRC, importedAt: AT2 });
  const reg = createKeyRegistry();
  applyRosterToRegistry(withBob, reg);
  applyRosterToRegistry(withoutBob, reg); // kb revoked
  const res = applyRosterToRegistry(withBob, reg); // bob reappears
  assert.deepEqual(res.refused, [{ principal: 'bob', kid: 'kb', reason: 'kid_previously_revoked' }]);
  assert.deepEqual(res.revoked, []);
  assert.ok(!reg.keysValidAt(AT).includes('pk_kb'));
});

test('apply rejects a non-roster and a registry that cannot revoke', () => {
  const roster = importRoster([u('u1', 'alice', true, [k('ka')])], { source: SRC, importedAt: AT });
  const reg = createKeyRegistry();
  assert.throws(() => applyRosterToRegistry({}, reg), /EP-GATE-ROSTER-v1/);
  assert.throws(
    () => applyRosterToRegistry(roster, { add() {}, status() { return []; } }),
    /add\/revoke\/status/,
  );
  // a flat trustedKeys array is NOT accepted — coercing would detach the mutations
  assert.throws(() => applyRosterToRegistry(roster, ['pk_x']), /add\/revoke\/status/);
});

test('a hand-built roster with a contested kid pins nothing for it and revokes it if present', () => {
  const handBuilt = {
    version: ROSTER_VERSION,
    source: SRC,
    imported_at: AT,
    signers: [
      { principal: 'alice', kid: 'shared', publicKey: 'pk_a', active: true },
      { principal: 'bob', kid: 'shared', publicKey: 'pk_b', active: true },
      { principal: 'carol', kid: 'kc', publicKey: 'pk_kc', active: true },
    ],
    integrity_warnings: [],
  };
  const reg = createKeyRegistry([{ kid: 'shared', key: 'pk_a' }]);
  const res = applyRosterToRegistry(handBuilt, reg);
  assert.deepEqual(res.pinned, [{ principal: 'carol', kid: 'kc' }]);
  assert.deepEqual(res.refused.map((r) => r.reason), ['contested_kid', 'contested_kid']);
  assert.deepEqual(res.revoked, [{ kid: 'shared', revoked_at: AT, reason: 'contested_kid' }]);
  assert.deepEqual(reg.keysValidAt(AT), ['pk_kc']);
});
