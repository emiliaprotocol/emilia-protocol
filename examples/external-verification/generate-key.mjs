// SPDX-License-Identifier: Apache-2.0
// Generated from generate-key.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Mint an Ed25519 verifier keypair for EP-EXTERNAL-VERIFICATION-STATEMENT-v1.
//
//   node examples/external-verification/generate-key.mjs [--out <dir>] [--force]
//
// Writes into the gitignored out/ directory (or --out):
//   private-key.pem  PKCS8 PEM Ed25519 private key (file mode 0600). Keep it.
//   public.key       SPKI base64url public key, the exact format a relying
//                    party pins for verifyExternalVerificationStatement.
//
// Refuses to overwrite an existing key unless --force is passed.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
let values;
try {
    ({ values } = parseArgs({
        options: {
            out: { type: 'string' },
            force: { type: 'boolean', default: false },
        },
    }));
}
catch (e) {
    process.stderr.write(`REFUSED (bad_arguments): ${e.message}\n`);
    process.exit(1);
}
const outDir = path.resolve(values.out ?? path.join(HERE, 'out'));
const privatePath = path.join(outDir, 'private-key.pem');
const publicPath = path.join(outDir, 'public.key');
const existing = [privatePath, publicPath].filter((p) => fs.existsSync(p));
if (existing.length > 0 && !values.force) {
    process.stderr.write('REFUSED (key_exists): a key already exists at '
        + `${existing.join(' and ')}. `
        + 'Refusing to overwrite it. Re-run with --force only if you are certain '
        + 'you want to destroy the old key (statements signed with it stay valid, '
        + 'but you can never sign with it again).\n');
    process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
fs.writeFileSync(privatePath, privatePem, { mode: 0o600 });
fs.writeFileSync(publicPath, publicB64u + '\n');
const keyId = `ep:external-verifier-key:sha256:${crypto.createHash('sha256')
    .update(Buffer.from(publicB64u, 'base64url')).digest('hex').slice(0, 16)}`;
process.stdout.write(`private key: ${privatePath} (PKCS8 PEM, mode 0600, never share, never commit)\n`);
process.stdout.write(`public key:  ${publicPath} (SPKI base64url, share this one)\n`);
process.stdout.write(`key id:      ${keyId}\n`);
process.stdout.write(`public key value: ${publicB64u}\n`);
