// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createWorksRecord, updateWorksRecord } from '../lib/works/store.ts';
import { worksProblem } from '../lib/works/api.ts';

const OWNER = '11111111-1111-4111-8111-111111111111';
let directory = '';

beforeEach(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'works-workflow-file-'));
  process.env.WORKS_DATA_DIR = directory;
  await createWorksRecord('builders', {
    builder_id: 'builder-one', kind: 'person', name: 'Builder', affiliations: [],
    contact_route: 'mailto:builder@example.com',
  }, { ownerEntityId: OWNER });
  await createWorksRecord('listings', {
    listing_id: 'listing-one', builder_id: 'builder-one', kind: 'agent', name: 'Agent',
    summary: 'Bounded worker', supported_tasks: [], interfaces: [], operating_constraints: [],
    status: 'active',
  }, { ownerEntityId: OWNER });
  await createWorksRecord('opportunities', {
    opportunity_id: 'job-one', kind: 'problem', title: 'Job', description: 'Bounded job',
    posted_by: 'Buyer', contact_route: 'mailto:buyer@example.com', claims: [],
  }, { ownerEntityId: OWNER });
});

afterEach(() => {
  delete process.env.WORKS_DATA_DIR;
  fs.rmSync(directory, { recursive: true, force: true });
});

describe('Works deterministic file-backend workflow parity', () => {
  it('maps generic workflow bypasses to a conflict, not a storage outage', () => {
    expect(worksProblem({ ok: false, code: 'invalid_transition', detail: 'Conflict' }).status).toBe(409);
  });
  it('does not let generic PATCH bypass listing workflow commands', async () => {
    await expect(updateWorksRecord('listings', 'listing-one', { status: 'paused' }, {
      ownerEntityId: OWNER,
    })).resolves.toMatchObject({ ok: false, code: 'invalid_transition' });
  });

  it.each(['closed', 'assigned'])('does not accept a proposal for a %s job fixture', async state => {
    const workflowDir = path.join(directory, '_workflow', 'opportunities');
    fs.mkdirSync(workflowDir, { recursive: true });
    fs.writeFileSync(path.join(workflowDir, 'job-one.json'), JSON.stringify({ state, revision: 1 }));
    await expect(createWorksRecord('submissions', {
      submission_id: `proposal-${state}`, opportunity_id: 'job-one', builder_id: 'builder-one',
      listing_id: 'listing-one', proposal: 'Proposal', team: [], visibility: 'private',
    }, { ownerEntityId: OWNER })).resolves.toMatchObject({ ok: false, code: 'invalid_transition' });
  });

  it('fails closed on a malformed workflow fixture', async () => {
    const workflowDir = path.join(directory, '_workflow', 'opportunities');
    fs.mkdirSync(workflowDir, { recursive: true });
    fs.writeFileSync(path.join(workflowDir, 'job-one.json'), '{"state":"open"}');
    await expect(createWorksRecord('submissions', {
      submission_id: 'proposal-malformed', opportunity_id: 'job-one', builder_id: 'builder-one',
      listing_id: 'listing-one', proposal: 'Proposal', team: [], visibility: 'private',
    }, { ownerEntityId: OWNER })).resolves.toMatchObject({ ok: false, code: 'store_unavailable' });
  });
});
