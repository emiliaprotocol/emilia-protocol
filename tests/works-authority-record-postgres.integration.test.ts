// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const connectionString = process.env.WORKS_POSTGRES_TEST_URL;
const suite = connectionString ? describe : describe.skip;

suite('Authority Record live PostgreSQL contract', () => {
  let client: pg.Client;
  const suffix = crypto.randomUUID().replaceAll('-', '').slice(0, 12);
  const entityId = crypto.randomUUID();
  const recordId = `authority-record-live-${suffix}`;
  const recordDigest = `sha256:${'a'.repeat(64)}`;
  const invitationDigest = `sha256:${'b'.repeat(64)}`;
  const ownerDigest = `sha256:${'c'.repeat(64)}`;
  const requesterDigest = `hmac-sha256:${'d'.repeat(64)}`;
  const verificationDigest = `sha256:${'e'.repeat(64)}`;
  const secondVerificationDigest = `sha256:${'f'.repeat(64)}`;

  beforeAll(async () => {
    client = new pg.Client({ connectionString });
    await client.connect();
    await client.query('BEGIN');
    await client.query('INSERT INTO public.entities (id) VALUES ($1)', [entityId]);
  });

  afterAll(async () => {
    if (!client) return;
    await client.query('ROLLBACK');
    await client.end();
  });

  it('keeps drafts private, verifies one requester once, and ignores stale subscription deletion', async () => {
    const observedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const invitationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const projection = {
      '@version': 'EMILIA-AUTHORITY-RECORD-v1',
      record_id: recordId,
      subject: {
        name: 'Live test agent', builder_name: 'Live test builder',
        repository_url: 'https://github.com/acme/agent',
      },
      provenance: {
        source_locator: 'https://github.com/acme/agent',
        watched_ref: 'refs/heads/main', resolved_revision: '1'.repeat(40),
        artifact_digest: `sha256:${'2'.repeat(64)}`,
        observed_at: observedAt, expires_at: expiresAt,
        scanner: {
          name: '@emilia-protocol/scan', version: '1.0.0',
          profile_digest: `sha256:${'3'.repeat(64)}`,
        },
      },
      surfaces: [{
        surface_id: 'code-change', label: 'Code change', action_class: 'code_change',
        consequence_class: 'code', evidence_status: 'OBSERVED',
        enforcement_status: 'NOT_ASSESSED',
      }],
      owner_statement: null,
      claim_boundary: 'versioned_public_authority_mapping_not_certification_not_safety_rating_not_complete_mediation',
    };

    await client.query(
      `SELECT public.create_works_authority_record_draft(
        $1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9
      )`,
      [recordId, recordDigest, projection, 'https://github.com/acme/agent',
        'mailto:owner@acme.example', entityId, invitationDigest,
        `claim_${'A'.repeat(32)}`, invitationExpiresAt],
    );
    const hidden = await client.query('SELECT public.list_works_authority_records_public() AS value');
    expect(hidden.rows[0].value).toEqual([]);

    await client.query(
      'SELECT public.claim_works_authority_record($1, $2, $3, $4, $5, $6)',
      [invitationDigest, ownerDigest,
        `https://raw.githubusercontent.com/acme/agent/${'1'.repeat(40)}/.well-known/emilia-authority-record.json`,
        '1'.repeat(40), `sha256:${'4'.repeat(64)}`, observedAt],
    );
    await client.query(
      'SELECT public.approve_works_authority_record_version($1, $2, $3, $4)',
      [recordId, ownerDigest, recordDigest, observedAt],
    );

    const firstDemand = await client.query(
      'SELECT public.create_works_authority_demand_request($1, $2, $3, $4, $5, $6) AS value',
      [recordId, requesterDigest, 'buyer.example', verificationDigest,
        new Date(Date.now() + 60 * 60 * 1000).toISOString(), observedAt],
    );
    expect(firstDemand.rows[0].value.status).toBe('PENDING');
    const verified = await client.query(
      'SELECT public.verify_works_authority_demand_request($1, $2) AS value',
      [verificationDigest, new Date().toISOString()],
    );
    expect(verified.rows[0].value).toMatchObject({
      verified_requesters: 1, verified_organizations: 1,
    });
    const repeated = await client.query(
      'SELECT public.create_works_authority_demand_request($1, $2, $3, $4, $5, $6) AS value',
      [recordId, requesterDigest, 'buyer.example', secondVerificationDigest,
        new Date(Date.now() + 60 * 60 * 1000).toISOString(), observedAt],
    );
    expect(repeated.rows[0].value.status).toBe('ALREADY_VERIFIED');

    await client.query(
      'SELECT public.apply_works_authority_stripe_event($1,$2,$3,$4,$5,$6,$7,$8)',
      ['evt_old00001', 'customer.subscription.created', recordId, 'active',
        'cus_customer1', 'sub_old00001', expiresAt, observedAt],
    );
    await client.query(
      'SELECT public.apply_works_authority_stripe_event($1,$2,$3,$4,$5,$6,$7,$8)',
      ['evt_new00001', 'customer.subscription.created', recordId, 'active',
        'cus_customer1', 'sub_new00001', expiresAt, observedAt],
    );
    const staleDeletion = await client.query(
      'SELECT public.apply_works_authority_stripe_event($1,$2,$3,$4,$5,$6,$7,$8) AS value',
      ['evt_old00002', 'customer.subscription.deleted', recordId, 'canceled',
        'cus_customer1', 'sub_old00001', expiresAt, observedAt],
    );
    expect(staleDeletion.rows[0].value).toMatchObject({
      status: 'ACTIVE', stripe_subscription_id: 'sub_new00001',
    });
  });
});
