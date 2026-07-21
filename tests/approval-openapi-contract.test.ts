// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const SPEC_PATHS = ['openapi.yaml', 'docs/api/govguard-v1.yaml'];
const APPROVAL_PATH = '/api/cloud/approvals';
const CONSUME_PATH = '/api/cloud/approvals/{receiptId}/consume';
const EVIDENCE_PATH = '/api/cloud/approvals/{receiptId}/evidence';
const ACQUISITION_PATH = '/api/v1/approvals';
const ACQUISITION_POLL_PATH = '/api/v1/approvals/{requestId}';
const EXPECTED_PERMISSIONS = ['approval_request', 'admin'];
const EXPECTED_MATURITY = 'experimental-pre-standard-prototype';
const EXPECTED_CAID_PATTERN =
  '^caid:1:payment\\.release\\.1:jcs-sha256:[A-Za-z0-9_-]{43}$';
const ACQUISITION_REQUIRED_FIELDS = [
  'action_type',
  'amount_usd',
  'currency',
  'payment_instruction_id',
  'beneficiary_account_hash',
];

function loadSpec(relativePath) {
  const source = readFileSync(resolve(ROOT, relativePath), 'utf8');
  const document = YAML.parseDocument(source, { uniqueKeys: true });
  return {
    relativePath,
    source,
    document,
    spec: document.toJS(),
  };
}

function resolveLocalRef(spec, ref) {
  expect(ref).toMatch(/^#\//);
  return ref
    .slice(2)
    .split('/')
    .reduce((value, key) => value?.[key], spec);
}

function requestSchema(spec, path, method) {
  const ref = spec.paths[path][method].requestBody.content['application/json'].schema.$ref;
  return resolveLocalRef(spec, ref);
}

function responseSchema(spec, path, method, status) {
  const ref = spec.paths[path][method].responses[status]
    .content['application/json'].schema.$ref;
  return resolveLocalRef(spec, ref);
}

function singleLine(value) {
  return String(value).replace(/\s+/g, ' ').trim();
}

const SPECS = SPEC_PATHS.map(loadSpec);
const PROTOTYPE_DOC = readFileSync(
  resolve(ROOT, 'docs/APPROVAL-ENDPOINT-PROTOTYPE.md'),
  'utf8',
);

describe('connected approval OpenAPI source contract', () => {
  it('keeps both YAML documents parseable with duplicate keys rejected', () => {
    for (const { relativePath, document } of SPECS) {
      expect(
        document.errors.map((error) => error.message),
        `${relativePath} must parse without duplicate keys`,
      ).toEqual([]);
      expect(document.warnings.map((warning) => warning.message)).toEqual([]);
    }
  });

  it('documents exactly the connected prototype route and method set', () => {
    for (const { spec } of SPECS) {
      expect(Object.keys(spec.paths[APPROVAL_PATH]).sort()).toEqual(['get', 'post']);
      expect(Object.keys(spec.paths[CONSUME_PATH])).toEqual(['post']);
      expect(Object.keys(spec.paths[EVIDENCE_PATH])).toEqual(['get']);
    }
  });

  it('requires a Cloud bearer key with approval_request or admin everywhere', () => {
    for (const { spec } of SPECS) {
      const scheme = spec.components.securitySchemes.CloudBearerAuth;
      expect(scheme).toMatchObject({ type: 'http', scheme: 'bearer' });
      expect(scheme.description).toContain('approval_request');
      expect(scheme.description).toContain('admin');

      for (const [path, method] of [
        [APPROVAL_PATH, 'get'],
        [APPROVAL_PATH, 'post'],
        [CONSUME_PATH, 'post'],
        [EVIDENCE_PATH, 'get'],
      ]) {
        const operation = spec.paths[path][method];
        expect(operation.tags).toEqual(['Cloud Approval Prototype']);
        expect(operation.security).toEqual([{ CloudBearerAuth: [] }]);
        expect(operation['x-emilia-maturity']).toBe(EXPECTED_MATURITY);
        expect(operation['x-emilia-permissions']).toEqual(EXPECTED_PERMISSIONS);
        expect(operation['x-emilia-fixed-action-type']).toBe('large_payment_release');
        expect(operation['x-emilia-caid-action-type']).toBe('payment.release.1');
      }
    }
  });

  it('fixes creation to the six payment inputs and a server-computed CAID', () => {
    for (const { spec } of SPECS) {
      const create = spec.paths[APPROVAL_PATH].post;
      const input = requestSchema(spec, APPROVAL_PATH, 'post');
      const output = responseSchema(spec, APPROVAL_PATH, 'post', '201');

      expect(input['x-emilia-fixed-action-type']).toBe('large_payment_release');
      expect(input['x-emilia-caid-action-type']).toBe('payment.release.1');
      expect(input.required).toEqual([
        'amount',
        'currency',
        'counterparty_name',
        'payment_destination_hash',
        'payment_reference',
        'approver_id',
      ]);
      expect(input.properties.action_type).toBeUndefined();
      expect(input.properties.payment_destination_hash.pattern)
        .toBe('^sha256:[a-f0-9]{64}$');
      expect(input.properties.currency.pattern).toBe('^[A-Z]{3}$');
      expect(input.properties.approver_id.pattern)
        .toBe('^[A-Za-z0-9:_.@-]{3,128}$');

      expect(create['x-emilia-required-assurance']).toBe('A');
      expect(create.description).toContain('large_payment_release');
      expect(create.description).toContain('Class-A');
      expect(create.description).toContain('WebAuthn/WYSIWYS');
      expect(create.description).toContain('payment.release.1');
      expect(create.description).toContain('does not establish authorization');

      expect(output.required).toContain('action_caid');
      expect(output.properties.action_caid.pattern).toBe(EXPECTED_CAID_PATTERN);
      expect(output.properties.required_assurance.enum).toEqual(['A']);
      expect(output.properties.status.enum).toEqual(['pending']);
      expect(output.properties.implementation_status.enum).toEqual(['prototype']);
    }
  });

  it('exposes action_caid directly in the queue and documents its signed evidence location', () => {
    for (const { spec } of SPECS) {
      const queue = responseSchema(spec, APPROVAL_PATH, 'get', '200');
      const record = resolveLocalRef(spec, queue.properties.approvals.items.$ref);
      const evidence = responseSchema(spec, EVIDENCE_PATH, 'get', '200');

      expect(record.required).toContain('action_caid');
      expect(record.required).toContain('payment_destination_hash');
      expect(record.properties.action_type.enum).toEqual(['large_payment_release']);
      expect(record.properties.action_caid.pattern).toBe(EXPECTED_CAID_PATTERN);
      expect(record.properties.action_caid.description.toLowerCase())
        .toContain('not an authorization');
      expect(record.properties.payment_destination_hash.pattern)
        .toBe('^sha256:[a-f0-9]{64}$');

      expect(singleLine(evidence.properties.document.description))
        .toContain('payload.claim.canonical_action.action_caid');
      expect(singleLine(evidence.properties.document.description))
        .toContain('does not establish authorization');

      expect(spec.paths[EVIDENCE_PATH].get.description).toContain('action_caid');
      expect(singleLine(spec.paths[EVIDENCE_PATH].get.description))
        .toContain('does not establish authorization');
    }
  });

  it('documents one-time consume with a fixed server-side executing system', () => {
    for (const { spec } of SPECS) {
      const operation = spec.paths[CONSUME_PATH].post;
      const input = requestSchema(spec, CONSUME_PATH, 'post');
      const output = responseSchema(spec, CONSUME_PATH, 'post', '200');

      expect(operation['x-emilia-consumption']).toBe('one-time');
      expect(operation.description).toContain('cannot be reused');
      expect(operation.description).toContain('does not itself move money');
      expect(input.required).toEqual(['action_hash']);
      expect(input.properties.executing_system).toBeUndefined();
      expect(output.properties.status.enum).toEqual(['consumed']);
      expect(output.properties.consumed_by_system.enum)
        .toEqual(['emilia_cloud_approval_endpoint']);
    }
  });

  it('labels the connected surface as experimental and makes all non-claims', () => {
    for (const { source } of SPECS) {
      const lowerSource = source.toLowerCase();
      expect(lowerSource).toContain('experimental pre-standard');
      expect(lowerSource).toContain('not a production api');
      expect(lowerSource).toContain('not a certification program');
      expect(lowerSource).toContain('not an interoperability claim');
      expect(lowerSource).toContain('caid does not establish authorization');
    }

    const lower = PROTOTYPE_DOC.toLowerCase();
    expect(lower).toContain('experimental pre-standard connected prototype');
    expect(lower).toContain('not a production api');
    expect(lower).toContain('not a certification');
    expect(lower).toContain('not an interoperability claim');
    expect(lower).toContain('caid does not establish authorization');
  });

  it('keeps the prototype guide on the exact routes, fields, and lifecycle', () => {
    for (const route of [APPROVAL_PATH, CONSUME_PATH, EVIDENCE_PATH]) {
      expect(PROTOTYPE_DOC).toContain(route);
    }
    for (const field of [
      'amount',
      'currency',
      'counterparty_name',
      'payment_destination_hash',
      'payment_reference',
      'approver_id',
      'action_caid',
    ]) {
      expect(PROTOTYPE_DOC).toContain(`\`${field}\``);
    }
    expect(PROTOTYPE_DOC).toContain('Authorization: Bearer <tenant Cloud API key>');
    expect(PROTOTYPE_DOC).toContain('`approval_request` capability or `admin`');
    expect(PROTOTYPE_DOC).toContain('WebAuthn/WYSIWYS');
    expect(PROTOTYPE_DOC).toContain('service-recorded Class-C decisions');
    expect(PROTOTYPE_DOC).toContain('emilia_cloud_approval_endpoint');
    expect(singleLine(PROTOTYPE_DOC)).toContain('does not itself move money');
  });
});

describe('EP-APPROVAL-v1 acquisition OpenAPI contract', () => {
  it('separates Cloud creation auth from the private EP-Approval polling capability', () => {
    for (const { spec } of SPECS) {
      expect(Object.keys(spec.paths[ACQUISITION_PATH])).toEqual(['post']);
      expect(Object.keys(spec.paths[ACQUISITION_POLL_PATH])).toEqual(['get']);

      const create = spec.paths[ACQUISITION_PATH].post;
      const poll = spec.paths[ACQUISITION_POLL_PATH].get;
      expect(create.security).toEqual([{ CloudBearerAuth: [] }]);
      expect(create['x-emilia-permissions']).toEqual(EXPECTED_PERMISSIONS);
      expect(poll.security).toEqual([{ ApprovalPollTokenAuth: [] }]);
      expect(create['x-emilia-flow']).toBe('EP-APPROVAL-v1');
      expect(poll['x-emilia-flow']).toBe('EP-APPROVAL-v1');
      expect(create['x-emilia-fixed-action-type']).toBe('payment.release');
      expect(poll['x-emilia-fixed-action-type']).toBe('payment.release');

      expect(spec.components.securitySchemes.CloudBearerAuth)
        .toMatchObject({ type: 'http', scheme: 'bearer' });
      expect(spec.components.securitySchemes.ApprovalPollTokenAuth)
        .toMatchObject({ type: 'apiKey', in: 'header', name: 'Authorization' });
      expect(singleLine(spec.components.securitySchemes.ApprovalPollTokenAuth.description))
        .toContain('Authorization: EP-Approval <poll_token>');
    }
  });

  it('documents only the closed payment.release reference request profile', () => {
    for (const { spec } of SPECS) {
      const input = requestSchema(spec, ACQUISITION_PATH, 'post');
      const challenge = resolveLocalRef(spec, input.properties.challenge.$ref);
      const action = resolveLocalRef(spec, input.properties.action.$ref);

      expect(input.additionalProperties).toBe(false);
      expect(input.required).toEqual([
        'flow', 'challenge', 'action', 'approver_id', 'idempotency_key',
      ]);
      expect(input.properties.flow.enum).toEqual(['EP-APPROVAL-v1']);
      expect(challenge.additionalProperties).toBe(false);
      expect(challenge.properties.action.enum).toEqual(['payment.release']);
      expect(challenge.properties.required_fields).toMatchObject({
        minItems: 5,
        maxItems: 5,
        uniqueItems: true,
      });
      expect(challenge.properties.required_fields.items.enum)
        .toEqual(ACQUISITION_REQUIRED_FIELDS);
      expect(challenge.properties.caid_selector.properties.field.enum)
        .toEqual(['action_caid']);

      expect(action.additionalProperties).toBe(false);
      expect(action.required).toEqual([
        'action_caid',
        'action_type',
        'amount_usd',
        'beneficiary_account_hash',
        'counterparty_name',
        'currency',
        'payment_instruction_id',
      ]);
      expect(action.properties.action_type.enum).toEqual(['payment.release']);
      expect(action.properties.action_caid.pattern).toBe(EXPECTED_CAID_PATTERN);
      expect(action.properties.beneficiary_account_hash.pattern)
        .toBe('^sha256:[a-f0-9]{64}$');
    }
  });

  it('keeps the 201 response closed and receipt-free', () => {
    for (const { spec } of SPECS) {
      const operation = spec.paths[ACQUISITION_PATH].post;
      const output = responseSchema(spec, ACQUISITION_PATH, 'post', '201');

      expect(Object.keys(operation.responses).sort()).toEqual([
        '201', '400', '401', '403', '409', '413', '415', '429', '503',
      ]);
      expect(output.additionalProperties).toBe(false);
      expect(output.required).toEqual([
        'request_id', 'poll_token', 'approval_url', 'status', 'expires_at',
      ]);
      expect(output.properties.request_id.pattern).toBe('^apr_[a-f0-9]{32}$');
      expect(output.properties.poll_token.pattern).toBe('^apt_[a-f0-9]{48}$');
      expect(output.properties.status.enum).toEqual(['pending', 'expired']);
      expect(output.properties.receipt).toBeUndefined();
    }
  });

  it('models approved, pending, denied, and expired as closed poll variants', () => {
    for (const { spec } of SPECS) {
      const operation = spec.paths[ACQUISITION_POLL_PATH].get;
      const output = responseSchema(spec, ACQUISITION_POLL_PATH, 'get', '200');
      const variants = output.oneOf.map(({ $ref }) => resolveLocalRef(spec, $ref));
      const byStatus = Object.fromEntries(variants.map((variant) => [
        variant.properties.status.enum[0],
        variant,
      ]));

      expect(Object.keys(operation.responses).sort()).toEqual(['200', '404', '429', '503']);
      expect(Object.keys(byStatus).sort()).toEqual(['approved', 'denied', 'expired', 'pending']);
      for (const status of ['pending', 'denied', 'expired']) {
        expect(byStatus[status].additionalProperties).toBe(false);
        expect(byStatus[status].required).toEqual(['request_id', 'status']);
        expect(byStatus[status].properties.receipt).toBeUndefined();
      }
      expect(byStatus.approved.additionalProperties).toBe(false);
      expect(byStatus.approved.required).toEqual(['request_id', 'status', 'receipt']);
      const receipt = resolveLocalRef(spec, byStatus.approved.properties.receipt.$ref);
      expect(receipt.additionalProperties).toBe(false);
      expect(receipt.properties['@version'].enum).toEqual(['EP-RECEIPT-v1']);
      expect(receipt.properties.payload.properties.profile.enum)
        .toEqual(['EP-APPROVAL-v1']);
      expect(receipt.properties.payload.properties.claim.properties.action_type.enum)
        .toEqual(['payment.release']);
    }
  });

  it('uses one strict RFC 9457 problem response for every non-success status', () => {
    for (const { spec } of SPECS) {
      for (const [path, method, success] of [
        [ACQUISITION_PATH, 'post', '201'],
        [ACQUISITION_POLL_PATH, 'get', '200'],
      ]) {
        const responses = spec.paths[path][method].responses;
        for (const [status, response] of Object.entries(responses)) {
          if (status === success) continue;
          expect(response.$ref).toBe('#/components/responses/ApprovalProblem');
        }
      }

      const response = spec.components.responses.ApprovalProblem;
      expect(Object.keys(response.content)).toEqual(['application/problem+json']);
      const problem = resolveLocalRef(
        spec,
        response.content['application/problem+json'].schema.$ref,
      );
      expect(problem.additionalProperties).toBe(false);
      expect(problem.required).toEqual(['type', 'title', 'status', 'detail', 'code']);
      expect(problem.properties.supported_action_types.items.enum)
        .toEqual(['payment.release']);
    }
  });
});

describe('GovGuard plain signoff schema source contract', () => {
  const slim = SPECS.find(({ relativePath }) =>
    relativePath === 'docs/api/govguard-v1.yaml').spec;

  it('requires approver_id for the slim single-signoff request', () => {
    expect(slim.components.schemas.RequestSignoffRequest.required)
      .toEqual(['receipt_id', 'approver_id']);
    expect(slim.components.schemas.RequestSignoffRequest.description)
      .toContain('Single-signoff');
  });

  it.each([
    ['/api/v1/signoffs/{signoffId}/approve', 'ApproveSignoffRequest'],
    ['/api/v1/signoffs/{signoffId}/reject', 'RejectSignoffRequest'],
  ])('documents %s as a service-recorded Class-C decision', (path, schemaName) => {
    const operation = slim.paths[path].post;
    const schema = slim.components.schemas[schemaName];

    expect(operation['x-emilia-key-class']).toBe('C');
    expect(operation['x-emilia-decision-recording']).toBe('service-recorded');
    expect(operation.description).toContain('not WebAuthn or Class-A evidence');
    expect(operation.description).toContain('refuses it');

    expect(schema.required).toEqual(['approved_action_hash']);
    expect(Object.keys(schema.properties).sort())
      .toEqual(['approved_action_hash', 'comment']);
    expect(schema.properties.action_hash).toBeUndefined();
    expect(schema.properties.attestation_text).toBeUndefined();
    expect(schema.properties.displayed_action_hash).toBeUndefined();
    expect(schema.properties.reason).toBeUndefined();
  });

  it('matches the plain decision response returned by runtime', () => {
    const decision = slim.components.schemas.SignoffDecision;
    expect(decision.required).toEqual([
      'signoff_id',
      'receipt_id',
      'decision',
      'approver_id',
      'decided_at',
    ]);
    expect(decision.properties.approver_id).toBeDefined();
    expect(decision.properties.decided_by).toBeUndefined();
    expect(decision.properties.reason).toBeUndefined();
    expect(decision.description).toContain('key_class C');
  });
});
