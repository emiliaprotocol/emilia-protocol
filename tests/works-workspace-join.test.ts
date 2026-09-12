// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearJoinCredentials, confirmOwnedJoinResume, selectOwnedJoinProfile } from '../app/works/join-profile-selection';

const profile = { builder_id: 'owned-studio', kind: 'person' as const, name: 'A builder', contact_route: 'mailto:builder@example.com' };
const source = () => readFileSync(new URL('../app/works/JoinForm.tsx', import.meta.url), 'utf8');
afterEach(() => vi.unstubAllGlobals());

describe('signed-in builder profile reuse', () => {
  it('selects only an exact profile from the authenticated workspace without changing it', () => {
    const profiles = [profile]; const before = JSON.stringify(profiles);
    expect(selectOwnedJoinProfile(profiles, profile.builder_id)).toMatchObject(profile);
    expect(JSON.stringify(profiles)).toBe(before);
    expect(() => selectOwnedJoinProfile(profiles, 'foreign-profile')).toThrow('join_profile_not_owned');
    expect(() => selectOwnedJoinProfile(null, profile.builder_id)).toThrow('join_profile_not_owned');
    expect(() => selectOwnedJoinProfile([profile, profile], profile.builder_id)).toThrow('join_profile_not_owned');
  });

  it('rejects malformed or example profiles and drops non-public fields', () => {
    expect(() => selectOwnedJoinProfile([{ ...profile, contact_route: 'javascript:alert(1)' }], profile.builder_id)).toThrow();
    expect(() => selectOwnedJoinProfile([{ ...profile, example: true }], profile.builder_id)).toThrow();
    expect(JSON.stringify(selectOwnedJoinProfile([{ ...profile, owner_entity_id: 'private-owner' }], profile.builder_id))).not.toContain('private-owner');
  });

  it('uses authenticated workspace choices, not a public directory or display-name identity', () => {
    const form = source();
    expect(form).toContain('loadWorkspace(request.signal)');
    expect(form).toContain('Your builder profile');
    expect(form).toContain('selectOwnedJoinProfile(profiles, id)');
    expect(form).toContain('accountContext !== access.account');
    expect(form).toContain('useLayoutEffect');
    expect(form).toContain("querySelectorAll<HTMLInputElement>('input[type=\"password\"]')");
    expect(form).not.toMatch(/accountContext\??\.displayName\s*[!=]=/);
    expect(form).not.toMatch(/localStorage|sessionStorage/);
  });

  it('keeps exact publication progress frozen during ordinary retries and preserves a new draft through initial sign-in', () => {
    const form = source();
    expect(form).toContain('await publishWorks(progress, request)');
    expect(form).toContain('builderCreated: reuseBuilder');
    expect(form).toContain('payloads.builder = ownedBuilder.record');
    expect(form).toContain("if (accountContext || progress || profileMode === 'existing') setDraft(null)");
    expect(form).toContain('window.addEventListener(\'pagehide\', clearPrivateAccess)');
    expect(form).toContain('setOwnedBuilder(null)');
  });

  it('clears secrets without losing an unresolved write or changing its IDs and original public fields', () => {
    const pending = { apiKey: 'secret-key', keyCreatedHere: true, ownerId: 'private-owner', builderCreated: true, listingCreated: false,
      payloads: { builder: profile, listing: { listing_id: 'original-agent', builder_id: profile.builder_id } } };
    const cleared = clearJoinCredentials(pending);
    expect(cleared).toMatchObject({ apiKey: '', ownerId: '', keyCreatedHere: false, accessCheckRequired: true, builderCreated: true, listingCreated: false });
    expect(cleared.payloads).toBe(pending.payloads);
    expect(clearJoinCredentials(cleared).payloads).toBe(pending.payloads);
    expect(pending.apiKey).toBe('secret-key');
    const form = source();
    expect(form).toContain('progress.accessCheckRequired');
    expect(form).toContain('await confirmOwnedJoinResume(progress, apiKey, request.signal)');
  });

  it('rechecks exact ownership before continuing a confirmed builder with refreshed account access', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ owned: true, collection: 'builders', record: profile })));
    vi.stubGlobal('fetch', fetcher);
    await confirmOwnedJoinResume({ builderCreated: true, payloads: { builder: profile } }, null, new AbortController().signal);
    expect(fetcher).toHaveBeenCalledWith('/api/works/builders/owned-studio/owned', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' }));
    expect(fetcher.mock.calls[0][1].method).toBeUndefined();
  });

  it.each([
    { status: 404, body: {} },
    { status: 200, body: { owned: false, collection: 'builders', record: profile } },
    { status: 200, body: { owned: true, collection: 'builders', record: { ...profile, builder_id: 'foreign-studio' } } },
    { status: 200, body: { owned: true, collection: 'builders', record: { ...profile, name: 'Changed profile' } } },
  ])('does not resume a foreign, mismatched, or unconfirmed profile: %j', async ({ status, body }) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status })));
    await expect(confirmOwnedJoinResume({ builderCreated: true, payloads: { builder: profile } }, null, new AbortController().signal)).rejects.toThrow();
  });

  it('rejects resume if access changes while the owned response is decoded', async () => {
    const controller = new AbortController();
    const response = new Response('{}');
    vi.spyOn(response, 'json').mockImplementation(async () => { controller.abort(); return { owned: true, collection: 'builders', record: profile }; });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
    await expect(confirmOwnedJoinResume({ builderCreated: true, payloads: { builder: profile } }, null, controller.signal)).rejects.toThrow();
  });

  it('does not mistake an unknown first write for a confirmed profile or create a new ID', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    const pending = { builderCreated: false, payloads: { builder: profile } };
    await confirmOwnedJoinResume(pending, null, new AbortController().signal);
    expect(fetcher).not.toHaveBeenCalled();
    expect(pending.payloads.builder.builder_id).toBe('owned-studio');
  });
});
