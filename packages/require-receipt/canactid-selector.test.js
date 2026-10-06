// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import { beginReceiptApproval } from './index.js';

const DIGEST = 'A'.repeat(43);
const AUTHORIZATION = {
  authorization_endpoint: 'https://approval.example.test/v1/requests',
  flow: 'EP-APPROVAL-v1',
};
const CHALLENGE = {
  action: 'payment.release.1',
  required_fields: ['action_caid'],
  caid_selector: { field: 'action_caid' },
};

function approvalResponse() {
  return new Response(JSON.stringify({
    request_id: `apr_${'a'.repeat(32)}`,
    status: 'pending',
    poll_token: `apt_${'b'.repeat(48)}`,
    expires_at: '2027-01-01T00:00:00Z',
    approval_url: 'https://approval.example.test/review/apr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  }), {
    status: 201,
    headers: { 'content-type': 'application/json' },
  });
}

function begin(action_caid, fetchImpl) {
  return beginReceiptApproval({
    authorization: AUTHORIZATION,
    trustedAuthorization: AUTHORIZATION,
    challenge: CHALLENGE,
    action: { action_type: 'payment.release.1', action_caid },
    approver_id: 'person@example.test',
    idempotency_key: 'approval-request-0001',
    requesterAuthorization: 'Bearer ep_requester-token',
    fetchImpl,
  });
}

test('approval acquisition accepts the registered canactid scheme', async () => {
  let calls = 0;
  await begin(`canactid:1:payment.release.1:jcs-sha256:${DIGEST}`, async () => {
    calls += 1;
    return approvalResponse();
  });
  assert.equal(calls, 1);
});

test('approval acquisition refuses the obsolete caid scheme before network I/O', async () => {
  let calls = 0;
  await assert.rejects(
    begin(`caid:1:payment.release.1:jcs-sha256:${DIGEST}`, async () => {
      calls += 1;
      return approvalResponse();
    }),
    /caid_binding_invalid:action_caid/u,
  );
  assert.equal(calls, 0);
});
