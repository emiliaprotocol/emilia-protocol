// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { actionHash, canonicalize } from '../packages/issue/index.js';
import {
  MOBILE_PRESENTATION_PROFILE,
  OASNT_DISPLAY_PROFILE,
  verifyPresentationBinding,
} from '../lib/presentation-binding/profile.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const suite = JSON.parse(readFileSync(
  path.join(here, '..', 'conformance', 'vectors', 'presentation-binding.v1.json'),
  'utf8',
));
const expected = Object.fromEntries(suite.vectors.map((vector) => [vector.id, vector.expected]));

const action = Object.freeze({
  action_type: 'wire.release',
  amount: '82000.00',
  currency: 'USD',
  beneficiary: 'vendor-42',
});
const presentation = Object.freeze({
  '@version': MOBILE_PRESENTATION_PROFILE,
  title: 'Release wire',
  summary: 'Release 82000.00 USD to vendor-42.',
  risk: 'high',
  consequence: 'Funds leave treasury control.',
  material_fields: {
    action_type: 'wire.release',
    amount: '82000.00',
    beneficiary: 'vendor-42',
    currency: 'USD',
  },
});

function sha256Canonical(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function mobileEvidence(value = presentation) {
  return {
    profile: MOBILE_PRESENTATION_PROFILE,
    action_hash: actionHash(action),
    presentation: value,
  };
}

function signedContext() {
  return {
    action_hash: actionHash(action),
    display_hash: sha256Canonical(presentation),
  };
}

describe('EP-PRESENTATION-BINDING-v1', () => {
  it('accepts a presentation digest carried by a verified signed context', () => {
    const result = verifyPresentationBinding({
      action,
      evidence: mobileEvidence(),
      signedContext: signedContext(),
      contextVerified: true,
    });
    expect({ valid: result.valid, reason: result.reason })
      .toEqual(expected.accept_mobile_signed_display_hash);
  });

  it('refuses when policy requires binding and no evidence is present', () => {
    const result = verifyPresentationBinding({ action });
    expect({ valid: result.valid, reason: result.reason })
      .toEqual(expected.refuse_display_unbound);
  });

  it('refuses a presentation that differs from the digest in the signed context', () => {
    const result = verifyPresentationBinding({
      action,
      evidence: mobileEvidence({ ...presentation, summary: 'Release 1.00 USD.' }),
      signedContext: signedContext(),
      contextVerified: true,
    });
    expect({ valid: result.valid, reason: result.reason })
      .toEqual(expected.refuse_display_mismatch);
  });

  it('re-derives the action hash instead of trusting two matching attacker claims', () => {
    const wrongActionHash = actionHash({ ...action, amount: '1.00' });
    const result = verifyPresentationBinding({
      action,
      evidence: { ...mobileEvidence(), action_hash: wrongActionHash },
      signedContext: { ...signedContext(), action_hash: wrongActionHash },
      contextVerified: true,
    });
    expect(result).toMatchObject({ valid: false, reason: 'display-mismatch' });
    expect(result.checks.action_bound).toBe(false);
  });

  it('fails closed rather than throwing on a non-canonical presentation', () => {
    const result = verifyPresentationBinding({
      action,
      evidence: mobileEvidence({ ...presentation, material_fields: { amount: 1.5 } }),
      signedContext: signedContext(),
      contextVerified: true,
    });
    expect(result).toMatchObject({ valid: false, reason: 'display-untrusted' });
  });

  it('accepts OASNT dsp only after native verification and action matching', () => {
    const canonicalDisplay = 'Action: wire.release\nAmount: 82000.00 USD\nPayee: vendor-42';
    const result = verifyPresentationBinding({
      action,
      evidence: {
        profile: OASNT_DISPLAY_PROFILE,
        canonical_display: canonicalDisplay,
        token: {
          dsp: crypto.createHash('sha256').update(Buffer.from(canonicalDisplay, 'utf8')).digest('base64url'),
        },
      },
      verifyNativeOasnt: () => ({ valid: true, action_match: true }),
    });
    expect({ valid: result.valid, reason: result.reason })
      .toEqual(expected.accept_oasnt_dsp_cross_profile);
  });

  it('does not accept a producer-asserted OASNT token without a native verifier', () => {
    const result = verifyPresentationBinding({
      action,
      evidence: {
        profile: OASNT_DISPLAY_PROFILE,
        canonical_display: 'Action: wire.release',
        token: { dsp: 'producer-asserted' },
      },
    });
    expect(result).toMatchObject({ valid: false, reason: 'display-untrusted' });
  });

  it('fails closed when a native OASNT verifier throws', () => {
    const result = verifyPresentationBinding({
      action,
      evidence: {
        profile: OASNT_DISPLAY_PROFILE,
        canonical_display: 'Action: wire.release',
        token: { dsp: 'invalid' },
      },
      verifyNativeOasnt: () => { throw new Error('native parser failed'); },
    });
    expect(result).toMatchObject({ valid: false, reason: 'display-untrusted' });
  });
});
