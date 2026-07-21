/**
 * SAML 2.0 Service Provider — metadata, AuthnRequest, and signed-Response
 * validation.
 *
 * Wraps `@node-saml/node-saml` (which uses `xml-crypto` for XML-DSig). All
 * signature verification — the part where naive implementations fall to XML
 * signature-wrapping attacks — is done by that vetted library, not hand-rolled.
 * `wantAssertionsSigned` is on by default: an unsigned or wrong-key assertion is
 * rejected.
 *
 * Config-injected so structure + rejection paths are unit-testable. The positive
 * round-trip (a real signed assertion from Okta/Entra) is exercised during
 * onboarding against that tenant.
 *
 * @license Apache-2.0
 */

import { SAML } from '@node-saml/node-saml';

/**
 * Construct a SAML SP for one tenant's IdP connection.
 */
export function buildSamlSp(cfg: any): any {
  if (!cfg?.idpCert)
    throw new Error(
      'buildSamlSp requires idpCert (the IdP signing certificate)',
    );
  if (!cfg.spEntityId || !cfg.acsUrl)
    throw new Error('buildSamlSp requires spEntityId and acsUrl');

  return new SAML({
    entryPoint: cfg.idpEntryPoint,
    idpCert: cfg.idpCert,
    issuer: cfg.spEntityId,
    callbackUrl: cfg.acsUrl,
    audience: cfg.audience ?? cfg.spEntityId,
    wantAssertionsSigned: cfg.wantAssertionsSigned ?? true,
    // We do not sign AuthnRequests (no SP private key required for a basic SP),
    // and we accept unsolicited responses (IdP-initiated SSO is common in gov).
    wantAuthnResponseSigned: cfg.wantAuthnResponseSigned ?? false,
    disableRequestedAuthnContext: true,
    // ACS clock-skew tolerance (NTP-bounded), seconds.
    acceptedClockSkewMs: 30_000,
  });
}

/** Build the IdP redirect URL for SP-initiated login (AuthnRequest). */
export async function buildLoginUrl(
  sp: any,
  { relayState = '', host = '' }: any = {},
): Promise<string> {
  return sp.getAuthorizeUrlAsync(relayState, host, {});
}

/**
 * Validate a base64 SAML Response from the ACS POST.
 */
export async function validateSamlResponse(
  sp: any,
  samlResponseB64: string,
): Promise<
  | { valid: false; error: string; profile?: undefined }
  | { valid: true; profile: any }
> {
  if (!samlResponseB64 || typeof samlResponseB64 !== 'string') {
    return { valid: false, error: 'Missing SAMLResponse' };
  }
  try {
    const { profile } = await sp.validatePostResponseAsync({
      SAMLResponse: samlResponseB64,
    });
    if (!profile) return { valid: false, error: 'No profile in SAML response' };
    return {
      valid: true,
      profile: {
        nameID: profile.nameID,
        email: profile.email || profile.nameID,
        issuer: profile.issuer,
        sessionIndex: profile.sessionIndex,
        attributes: profile.attributes || {},
      },
    };
  } catch (err) {
    // node-saml throws on bad/absent signature, wrong audience, expired
    // conditions, replay — all the cases that must NOT authenticate.
    return {
      valid: false,
      error: (err as any)?.message || 'SAML validation failed',
    };
  }
}

/** SP metadata XML for the IdP administrator to consume. */
export function spMetadata(sp: any): string {
  // (decryptionCert, signingCert) — null for a basic SP that neither encrypts
  // nor signs requests.
  return sp.generateServiceProviderMetadata(null, null);
}
