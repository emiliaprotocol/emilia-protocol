// SPDX-License-Identifier: Apache-2.0
//
// EP-SCITT Composition Demo — register -> receipt -> verify.
//
// Proves the composition claim end to end: an EP authorization receipt
// (WHO approved) becomes a COSE_Sign1 Signed Statement, is registered via
// SCRAPI, yields a SCITT receipt, and a third party verifies BOTH the
// authorization and the inclusion offline.
//
// Default mode uses an in-process mock SCRAPI-like Transparency Service so CI
// can prove the complete path without network sockets or external accounts:
//
//   node examples/scitt/ep-receipt-scitt-end-to-end.mjs
//
// External mode posts to a SCRAPI-compatible target:
//
//   SCITT_URL=http://127.0.0.1:8000 node examples/scitt/ep-receipt-scitt-end-to-end.mjs
//
// External mode proves EP/COSE construction and registration. A returned
// service-specific SCITT Receipt still needs that service's receipt verifier
// before claiming full transparency/inclusion verification.

import crypto from 'node:crypto';
import {
  buildArtifacts,
  verifyProfileArtifacts,
} from './ep-receipt-scitt-conformance.mjs';
import {
  createMockScrapiRegistry,
  verifyMockTransparencyReceipt,
} from './mock-scrapi-transparency-service.mjs';

const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function postSignedStatement(baseUrl, coseSign1) {
  const url = new URL('/entries', baseUrl);
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/cose',
      accept: 'application/cose, application/json, */*',
    },
    body: coseSign1,
  });
  const body = Buffer.from(await res.arrayBuffer());
  return {
    ok: res.ok,
    status: res.status,
    location: res.headers.get('location') || '',
    contentType: res.headers.get('content-type') || '',
    body,
    bodySha256: sha256Hex(body),
  };
}

function parseJsonBody(body) {
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    return null;
  }
}

function check(id, title, pass, detail = '') {
  return { id, title, pass: Boolean(pass), detail };
}

async function runEndToEnd({ scittUrl = process.env.SCITT_URL || process.env.SCITT_TS_URL || '', useMockFallback = true } = {}) {
  const artifacts = buildArtifacts();
  const profileChecks = verifyProfileArtifacts(artifacts);
  let mock: any = null;
  let targetUrl = scittUrl;
  let target = 'external';

  if (!targetUrl && useMockFallback) {
    mock = createMockScrapiRegistry();
    targetUrl = 'mock://in-process-scrapi-transparency-service';
    target = 'mock';
  }
  if (!targetUrl) throw new Error('SCITT_URL is required when mock fallback is disabled');

  const registration = target === 'mock'
    ? { ...mock.register(artifacts.coseSign1), bodySha256: '' }
    : await postSignedStatement(targetUrl, artifacts.coseSign1);
  registration.bodySha256 ||= sha256Hex(registration.body);

  const receipt = parseJsonBody(registration.body);
  const transparencyChecks = target === 'mock' && receipt
    ? verifyMockTransparencyReceipt(
      receipt,
      artifacts.coseSign1,
      mock.publicKey,
    )
    : [
      check(
        'external_registration',
        'external SCRAPI-compatible target accepted the Signed Statement',
        registration.ok,
        `${registration.status} ${registration.contentType}`,
      ),
      check(
        'external_receipt_verifier_needed',
        'returned transparency receipt requires a target-specific verifier before claiming inclusion verification',
        true,
        'not a SCITT WG conformance claim',
      ),
    ];

  return {
    target,
    targetUrl,
    artifacts,
    profileChecks,
    registration,
    receipt,
    transparencyChecks,
    passed: profileChecks.every((c) => c.pass) && registration.ok && transparencyChecks.every((c) => c.pass),
  };
}

function printChecks(title, checks) {
  console.log(`\n${title}`);
  for (const c of checks) {
    console.log(`${c.pass ? 'PASS' : 'FAIL'} ${c.id} — ${c.title}${c.detail ? ` (${c.detail})` : ''}`);
  }
}

function printReport(result) {
  console.log('EP-SCITT register -> receipt -> verify');
  console.log(`Target: ${result.target} (${result.targetUrl})`);
  printChecks('Local EP/COSE profile checks:', result.profileChecks);
  console.log('\nSCRAPI registration:');
  console.log(`  status=${result.registration.status} ok=${result.registration.ok}`);
  console.log(`  content-type=${result.registration.contentType || '(none)'}`);
  console.log(`  location=${result.registration.location || '(none)'}`);
  console.log(`  receipt-bytes=${result.registration.body.length} receipt-sha256=${result.registration.bodySha256}`);
  printChecks(result.target === 'mock' ? 'Mock transparency receipt verification:' : 'External target status:', result.transparencyChecks);
  console.log(`\n${result.passed ? 'END-TO-END PASS' : 'END-TO-END FAIL'} — ${result.target === 'mock' ? 'mock register/receipt/inclusion path verified in CI' : 'external registration only unless a receipt verifier is configured'}.`);
}

async function main() {
  const result = await runEndToEnd();
  printReport(result);
  if (!result.passed) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

export {
  postSignedStatement,
  runEndToEnd,
};
