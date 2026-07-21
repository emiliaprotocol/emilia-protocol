// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  createReleaseLock,
  isReleaseLockDemoPilotToken,
  normalizeReleaseLockParticipantView,
  RELEASE_LOCK_ENDPOINTS,
} from './api.js';

const CO_HASH = `sha256:${'1'.repeat(64)}`;
const DRAW_HASH = `sha256:${'2'.repeat(64)}`;

function participantView() {
  return {
    role: 'customer',
    credential_enrolled: true,
    lock: {
      lock_id: `rlk_${'a'.repeat(32)}`,
      status: 'effect_reserved',
    },
    change_order: {
      action_hash: CO_HASH,
      action: {
        round: 'CO_ACCEPTED',
        version: 1,
        created_at: '2030-01-01T00:00:00.000Z',
        expires_at: '2030-01-05T00:00:00.000Z',
        retained_change_order: {
          document: { reference: 'CO-02.pdf', digest: CO_HASH },
          scope: {
            project: 'Maple Street',
            title: 'Cabinet change order',
            summary: 'Install the exact approved cabinet scope.',
          },
          price_delta: '12500.00',
          currency: 'USD',
          progress_schedule_effect: { summary: 'Adds three working days.' },
        },
        parties: [
          { role: 'contractor', party_id: 'contractor:1', display_name: 'Northline' },
          { role: 'customer', party_id: 'customer:1', display_name: 'Jordan' },
        ],
      },
    },
    draw_release: {
      action_hash: DRAW_HASH,
      action: {
        round: 'DRAW_RELEASE',
        version: 1,
        created_at: '2030-01-02T00:00:00.000Z',
        draw_id: 'DRAW-04',
        amount: '12500.00',
        currency: 'USD',
        payees: [{ party_id: 'contractor:1', amount: '12500.00' }],
        completion_evidence: { reference: 'completion.zip', digest: DRAW_HASH },
        lien_waivers: [{
          payee_party_id: 'contractor:1',
          document: {
            reference: 'waiver.pdf',
            digest: DRAW_HASH,
          },
        }],
        evidence_hashes: {
          lien_waiver_hashes: [{
            payee_party_id: 'contractor:1',
            document_hash: DRAW_HASH,
          }],
        },
        custodian: { provider: 'escrow.com' },
      },
    },
    decisions: [
      {
        round: 'CO_ACCEPTED',
        role: 'contractor',
        credential_id: 'credential_contractor',
        action_hash: CO_HASH,
        resolution_digest: CO_HASH,
        decided_at: '2030-01-01T01:00:00.000Z',
        invalidated: false,
      },
      {
        round: 'CO_ACCEPTED',
        role: 'customer',
        credential_id: 'credential_customer',
        action_hash: CO_HASH,
        resolution_digest: CO_HASH,
        decided_at: '2030-01-01T01:01:00.000Z',
        invalidated: false,
      },
    ],
    round_acceptances: [
      { round: 'CO_ACCEPTED', accepted_at: '2030-01-01T01:01:00.000Z' },
      { round: 'DRAW_RELEASE', accepted_at: '2030-01-02T01:01:00.000Z' },
    ],
    effect: { status: 'reserved', effect_reference: 'rl:effect:1' },
  };
}

describe('Release Lock live API contract', () => {
  it('accepts only the fixed demo token and refuses arbitrary pilot query text', async () => {
    expect(isReleaseLockDemoPilotToken('demo-pilot-release-lock')).toBe(true);
    expect(isReleaseLockDemoPilotToken('anything')).toBe(false);
    await expect(createReleaseLock({
      pilotToken: 'anything',
      lock: {},
    })).rejects.toThrow('demo creation link is invalid');
  });

  it('maps the UI client to the hardened route namespace', () => {
    expect(RELEASE_LOCK_ENDPOINTS.create).toBe('');
    expect(RELEASE_LOCK_ENDPOINTS.exchange).toBe('/invitations/exchange');
    expect(RELEASE_LOCK_ENDPOINTS.exchangePairing).toBe('/pairings/exchange');
    expect(RELEASE_LOCK_ENDPOINTS.get('rlk_1')).toBe('/rlk_1/view');
    expect(RELEASE_LOCK_ENDPOINTS.resolutionOptions('rlk_1', 'co-accepted'))
      .toBe('/rlk_1/rounds/co-accepted/action-check/options');
    expect(RELEASE_LOCK_ENDPOINTS.resolutionSubmit('rlk_1', 'draw-release'))
      .toBe('/rlk_1/rounds/draw-release/approvals');
    expect(RELEASE_LOCK_ENDPOINTS.createPairing('rlk_1', 'draw-release'))
      .toBe('/rlk_1/rounds/draw-release/pairings');
  });

  it('builds the product read model from a role-scoped participant view', () => {
    const normalized = normalizeReleaseLockParticipantView(participantView());
    expect(normalized.role).toBe('customer');
    expect(normalized.credential_enrolled).toBe(true);
    expect(normalized.lock.project).toBe('Maple Street');
    expect(normalized.lock.ceremonies.co_acceptance.digest).toBe(CO_HASH);
    expect(normalized.lock.ceremonies.draw_release.digest).toBe(DRAW_HASH);
    expect(normalized.state.ceremonies.co_acceptance.status).toBe('CO_ACCEPTED');
    expect(normalized.state.ceremonies.draw_release.status).toBe('DRAW_RELEASE');
    expect(normalized.state.release_instruction).toEqual({
      status: 'reserved',
      eligible: true,
      executed: false,
    });
    expect(normalized.lock.draw.lien_waiver_evidence).toMatchObject({
      reference: 'contractor:1 · waiver.pdf',
      digest: DRAW_HASH,
      documents: [{
        payee_party_id: 'contractor:1',
        reference: 'waiver.pdf',
        digest: DRAW_HASH,
      }],
    });
  });
});
