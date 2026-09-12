// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
const mocks = vi.hoisted(() => ({ read: vi.fn(), bearer: vi.fn() }));
vi.mock('@/lib/works/session', () => ({ getWorksSessionActor: mocks.read,
  assertWorksSameOrigin: (req: Request) => req.headers.get('origin') === 'https://www.emiliaprotocol.ai',
  WORKS_SESSION_COOKIE_NAME: '__Host-emilia_works_session' }));
vi.mock('@/lib/supabase', async original => ({ ...await original<typeof import('@/lib/supabase')>(), authenticateRequest: mocks.bearer }));
import { authenticateWorksRead, authenticateWorksWrite } from '../app/api/works/_write-auth';
const ID = '11111111-1111-4111-8111-111111111111';
const actor = { ownerEntityId: ID, displayName: 'Email account', emailVerified: true };
beforeEach(() => { vi.clearAllMocks(); mocks.read.mockResolvedValue(actor); mocks.bearer.mockResolvedValue({ error: 'refused', status: 401 }); });
afterEach(() => vi.unstubAllEnvs());
function request(method = 'POST', origin: string | null = 'https://www.emiliaprotocol.ai', bearer?: string) {
  return new NextRequest('https://www.emiliaprotocol.ai/api/works/opportunities', { method, headers: {
    cookie: '__Host-emilia_works_session=test', ...(origin ? {origin} : {}), ...(bearer ? {authorization: bearer} : {}),
  } });
}
describe('Works sessions authorize only the Works owner surface', () => {
  it('binds session publications to the server-resolved owner and name', async () => {
    expect(await authenticateWorksWrite(request())).toEqual({ok:true,actor:{ownerEntityId:ID,displayName:'Email account'}});
    expect(mocks.bearer).not.toHaveBeenCalled();
  });
  it.each([null,'https://attacker.example'])('refuses a session write with wrong or missing origin %s', async origin => {
    const result = await authenticateWorksWrite(request('POST', origin));
    expect(result.ok).toBe(false); if (!result.ok) expect(result.response.status).toBe(403);
  });
  it('does not require Origin for an authenticated private GET', async () => {
    expect(await authenticateWorksWrite(request('GET', null))).toMatchObject({ok:true,actor:{ownerEntityId:ID}});
  });
  it('never falls back from an explicit refused bearer to another signed-in account', async () => {
    const result = await authenticateWorksWrite(request('POST',null,'Bearer bad-key'));
    expect(result.ok).toBe(false); expect(mocks.read).not.toHaveBeenCalled();
  });
  it('gives a session reader its own identity and never admin privileges', async () => {
    expect(await authenticateWorksRead(request('GET',null))).toEqual({ok:true,access:{viewerEntityId:ID,isAdmin:false}});
  });
  it('distinguishes session infrastructure failure from anonymous access', async () => {
    mocks.read.mockRejectedValue(new Error('private db details'));
    const result = await authenticateWorksRead(request('GET',null));
    expect(result.ok).toBe(false); if (!result.ok) {expect(result.response.status).toBe(503); expect(await result.response.text()).not.toContain('private db');}
  });
});
