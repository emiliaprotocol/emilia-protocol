// SPDX-License-Identifier: Apache-2.0
//
// EP-SCITT-STATEMENT-v1 registration client for the Markovian public
// transparency log.
//
//   npx tsx examples/scitt-registration/register.mjs              # dry run
//   npx tsx examples/scitt-registration/register.mjs --dry-run    # same
//
// DRY RUN IS THE DEFAULT AND IS THE ONLY MODE THIS FILE HAS EVER BEEN RUN IN.
// It performs no network I/O of any kind: it builds the Signed Statement,
// verifies it offline, and prints the exact HTTP request that WOULD be sent.
//
// ENDPOINT IS NOT KNOWN. The submission endpoint of the Markovian transparency
// log is NOT documented anywhere in this repository. The only Markovian
// coordinate the repo holds is the tlog ORIGIN string `markovianprotocol.com/log`
// (interop/markovian-emilia/MARKOVIAN-CROSS-RUN-20260729-001.json), which is a
// signed-note origin, not an HTTP submission URL. The placeholder below must be
// replaced with an endpoint confirmed by Markovian before anything is sent.
//
// SENDING IS IMAN'S GATE. Publishing to a third-party registry is an outbound
// act. The send path exists but is inert unless all three of --send,
// --endpoint=<https url> and --i-have-approval are supplied together.

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildEpScittSignedStatement,
  verifyEpScittSignedStatement,
  describeScittRegistrationRequest,
  EP_SCITT_STATEMENT_PROFILE,
  SCITT_STATEMENT_MEDIA_TYPE,
} from '../../packages/verify/scitt-statement.js';
import { ed25519FromSeed, buildFixtureReceipt, ISS, KID, STATEMENT_SEED, RECEIPT_ISSUER_SEED }
  from './generate-vectors.mjs';

/**
 * PLACEHOLDER, NOT A REAL ENDPOINT. Confirm with Markovian before use.
 * `markovianprotocol.com/log` is the c2sp signed-note origin from the checked-in
 * cross-run return package; it is not known to be an HTTP submission URL.
 */
export const MARKOVIAN_ENDPOINT_PLACEHOLDER =
  'https://CONFIRM-WITH-MARKOVIAN.invalid/entries';

function parseArgs(argv) {
  const args = { dryRun: true, send: false, approval: false, endpoint: null };
  for (const arg of argv) {
    if (arg === '--dry-run') args.dryRun = true;
    else if (arg === '--send') { args.send = true; args.dryRun = false; }
    else if (arg === '--i-have-approval') args.approval = true;
    else if (arg.startsWith('--endpoint=')) args.endpoint = arg.slice('--endpoint='.length);
  }
  return args;
}

function hexPreview(bytes, limit = 64) {
  const hex = Buffer.from(bytes).toString('hex');
  return hex.length <= limit * 2 ? hex : `${hex.slice(0, limit * 2)}... (${bytes.length} bytes total)`;
}

export function buildRegistrationArtifacts() {
  const statementKey = ed25519FromSeed(STATEMENT_SEED);
  const receiptIssuer = ed25519FromSeed(RECEIPT_ISSUER_SEED);
  const receipt = buildFixtureReceipt(receiptIssuer);

  const built = buildEpScittSignedStatement(receipt, {
    statementPrivateKey: statementKey.privateKey,
    kid: KID,
    iss: ISS,
  });
  if (!built.ok) throw new Error(`build refused: ${built.reason}`);

  // Verify our own statement offline BEFORE describing any request. A client
  // that cannot verify what it is about to publish has no business publishing.
  const verified = verifyEpScittSignedStatement(built.value.statement, {
    statementPublicKeyBase64url: statementKey.publicKeyBase64url,
    receiptIssuerPublicKeyBase64url: receiptIssuer.publicKeyBase64url,
    expectedIss: ISS,
    expectedSub: built.value.sub,
    expectedKid: KID,
  });
  if (!verified.valid) throw new Error(`self-verification refused: ${verified.reason}`);

  return { statementKey, receiptIssuer, receipt, built: built.value, verified };
}

function printDryRun(artifacts, endpoint) {
  const { built, verified, statementKey, receiptIssuer } = artifacts;
  const described = describeScittRegistrationRequest(built.statement, endpoint);
  if (!described.ok) throw new Error(`request description refused: ${described.reason}`);
  const request = described.value;

  console.log(`profile: ${EP_SCITT_STATEMENT_PROFILE}`);
  console.log('');
  console.log('Signed Statement (RFC 9943 Section 6)');
  console.log(`  iss (CWT claim 1)   : ${built.iss}`);
  console.log(`  sub (CWT claim 2)   : ${built.sub}`);
  console.log(`  kid (COSE label 4)  : ${KID}`);
  console.log(`  payload             : receipt canonical JSON, ${built.payload.length} bytes`);
  console.log(`  payload sha256      : ${built.payloadSha256}`);
  console.log(`  protected header    : ${hexPreview(built.protectedHeaderBytes, 48)}`);
  console.log(`  statement sha256    : ${request.bodySha256}`);
  console.log(`  statement bytes     : ${request.bodyBytes}`);
  console.log('');
  console.log('Offline verification before any send');
  for (const [name, value] of Object.entries(verified.checks)) {
    console.log(`  ${name.padEnd(24)}: ${value}`);
  }
  console.log(`  ${'registered'.padEnd(24)}: ${verified.registered}  <- VERIFIED is not REGISTERED`);
  console.log('');
  console.log('Pinned keys a relying party needs (SPKI DER, base64url)');
  console.log(`  statement signer    : ${statementKey.publicKeyBase64url}`);
  console.log(`  receipt issuer      : ${receiptIssuer.publicKeyBase64url}`);
  console.log('');
  console.log('THE REQUEST THAT WOULD BE SENT (nothing was sent)');
  console.log(`  ${request.method} ${request.url}`);
  for (const [k, v] of Object.entries(request.headers)) console.log(`  ${k}: ${v}`);
  console.log(`  Content-Length: ${request.bodyBytes}`);
  console.log('');
  console.log(`  body (tagged COSE_Sign1, hex): ${hexPreview(request.body, 48)}`);
  console.log('');
  if (endpoint === MARKOVIAN_ENDPOINT_PLACEHOLDER) {
    console.log('ENDPOINT UNCONFIRMED. The Markovian submission endpoint is not documented in');
    console.log('this repository. The URL above is a placeholder. Confirm the real endpoint and');
    console.log('its expected content type with Markovian before sending anything.');
    console.log('');
  }
  console.log('Sending is a separate act and is IMAN\'S GATE (publishing to a third-party');
  console.log('registry). Nothing in this run touched the network.');
  return request;
}

async function send(request) {
  // Reached only with --send --endpoint=<https url> --i-have-approval.
  const response = await fetch(request.url, {
    method: request.method,
    headers: { ...request.headers, 'Content-Length': String(request.bodyBytes) },
    body: request.body,
  });
  const text = await response.text();
  console.log(`HTTP ${response.status} ${response.statusText}`);
  console.log(text);
  console.log('');
  console.log('A 2xx here means the Transparency Service ACCEPTED the statement for');
  console.log('registration. Registration is proven by the Receipt it returns, verified');
  console.log('separately. Do not describe this statement as registered until that Receipt');
  console.log('has been verified.');
  return response.status;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  const endpoint = args.endpoint ?? MARKOVIAN_ENDPOINT_PLACEHOLDER;
  const artifacts = buildRegistrationArtifacts();
  const request = printDryRun(artifacts, endpoint);

  if (args.send) {
    const problems = [];
    if (!args.approval) problems.push('--i-have-approval was not supplied');
    if (!args.endpoint) problems.push('--endpoint=<https url> was not supplied (no endpoint is documented in-repo)');
    if (args.endpoint === MARKOVIAN_ENDPOINT_PLACEHOLDER) problems.push('the placeholder endpoint cannot be used');
    if (problems.length) {
      console.error('');
      console.error('REFUSING TO SEND:');
      for (const p of problems) console.error(`  - ${p}`);
      console.error('');
      console.error(`Publishing to a third-party registry is Iman's gate. Nothing was sent.`);
      process.exit(1);
    }
    console.error('');
    console.error(`SENDING to ${request.url} with Content-Type ${SCITT_STATEMENT_MEDIA_TYPE}.`);
    const status = await send(request);
    process.exit(status >= 200 && status < 300 ? 0 : 1);
  }
}

export { parseArgs, printDryRun, crypto };
