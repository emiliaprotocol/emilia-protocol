// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';

import { strictJsonGate } from './strict-json.js';

test('strict mobile JSON gate rejects duplicate decoded names and unpaired surrogates', () => {
  assert.equal(strictJsonGate('{"origin":"safe","\\u006frigin":"attacker"}').ok, false);
  assert.equal(strictJsonGate('{"value":"\\ud800"}').ok, false);
  assert.equal(strictJsonGate('{"value":"\\udc00"}').ok, false);
});

test('strict mobile JSON gate bounds nesting and accepts ordinary client data', () => {
  assert.equal(strictJsonGate(`${'['.repeat(65)}0${']'.repeat(65)}`).ok, false);
  assert.equal(strictJsonGate('{"type":"webauthn.get","challenge":"abc","origin":"https://approve.example.gov"}').ok, true);
});
