// SPDX-License-Identifier: Apache-2.0
//
// Relying-party side: verify a received EP-EXTERNAL-VERIFICATION-STATEMENT-v1
// against a public key you pinned out of band.
//
//   node examples/external-verification/verify-statement.mjs <statement.json> \
//     --pin <base64url-SPKI-or-path-to-public.key> --verifier-id <id>
//
// Exit 0 only if the statement is accepted under the pinned key. Everything
// else (bad pin, tampered statement, unpinned key, bad signature) exits 1
// with the refusal reason.
//
// Acceptance means the signature is genuine, NOT that the run passed: always
// read result.status. A statement with result.status = 'divergent' is a
// validly signed report of a divergence.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { verifyExternalVerificationStatement } from '../../packages/gate/reports/external-verification.js';

/**
 * @returns {never} always exits the process; never returns to the caller.
 */
function refuse(reason, detail) {
  process.stderr.write(`REFUSED (${reason})${detail ? `: ${detail}` : ''}\n`);
  process.exit(1);
}

let values;
let positionals;
try {
  ({ values, positionals } = parseArgs({
    options: {
      pin: { type: 'string' },
      'verifier-id': { type: 'string' },
    },
    allowPositionals: true,
  }));
} catch (e) {
  refuse('bad_arguments', e.message);
}

if (positionals.length !== 1) {
  refuse('bad_arguments', 'usage: verify-statement.mjs <statement.json> --pin <public key or key file>');
}
if (!values.pin) {
  refuse('pin_missing', 'a relying party must pin the verifier public key out of band; pass --pin');
}
if (!values['verifier-id']) {
  refuse('verifier_id_missing', 'a pin vouches for an identity, not just a key; pass --verifier-id with the id you pinned (the statement verifier.id)');
}

let pin = values.pin;
if (fs.existsSync(pin)) {
  try {
    pin = fs.readFileSync(pin, 'utf8').trim();
  } catch (e) {
    refuse('pin_unreadable', e.message);
  }
} else {
  pin = pin.trim();
}
try {
  crypto.createPublicKey({ key: Buffer.from(pin, 'base64url'), type: 'spki', format: 'der' });
} catch {
  refuse('pin_not_valid_spki', 'the pin must be a base64url SPKI Ed25519 public key (the public.key file generate-key.mjs writes)');
}

let statement;
try {
  statement = JSON.parse(fs.readFileSync(positionals[0], 'utf8'));
} catch (e) {
  refuse('statement_unreadable', `${positionals[0]}: ${e.message}`);
}

const result = verifyExternalVerificationStatement(statement, {
  pinnedVerifierKeys: [{ public_key: pin, verifier_id: values['verifier-id'] }],
});

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (result.accepted === true) {
  process.stdout.write(`ACCEPTED under the pinned key (statement_digest ${result.statement_digest})\n`);
  process.stdout.write(`statement result.status: ${statement?.result?.status}\n`);
  process.stdout.write(`statement procedure: ${statement?.procedure?.id} (${statement?.procedure?.version})\n`);
  process.exit(0);
}
process.stderr.write(`REJECTED (${result.reason})\n`);
if (result.reason === 'statement_digest_mismatch') {
  process.stderr.write(
    '\nYour statement_digest is computed over different bytes than the spec defines.\n'
    + `  you declared: ${statement?.signature?.statement_digest}\n`
    + `  spec expects: ${result.statement_digest}\n`
    + 'Signed bytes = "EP-EXTERNAL-VERIFICATION-STATEMENT-v1" || 0x00 (ONE NUL byte) || JCS(statement),\n'
    + 'where the statement is canonicalized with its ENTIRE top-level "signature" member removed\n'
    + '(not just signature_b64u / statement_digest). Check your construction in isolation against the\n'
    + 'golden vector: examples/external-verification/digest-test-vector.json\n'
    + '(any correct implementation reproduces sha256:d771c82af5df2a0d70bd1b9d5998d1d11c668a3b1f6cab840751144393383234).\n'
    + 'Or sign with examples/external-verification/sign-statement.mjs, which builds these bytes by construction.\n',
  );
}
process.exit(1);
