/**
 * SAML 2.0 Service Provider — tests.
 *
 * Structure + the security-critical REJECTION paths are exercised here against
 * node-saml's real validator (unsigned, garbage, and empty responses must NOT
 * authenticate, because wantAssertionsSigned is on). When openssl is available
 * (CI + dev), we additionally generate a throwaway IdP cert, sign a real SAML
 * assertion with xml-crypto, and prove the ACS ACCEPTS a valid signed assertion
 * and REJECTS one signed by a different key.
 *
 * No private keys are committed — the fixture cert/key are generated at runtime.
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { SignedXml } from 'xml-crypto';
import { buildSamlSp, buildLoginUrl, validateSamlResponse, spMetadata } from '../lib/sso/saml.js';

const SP_ENTITY_ID = 'https://www.emiliaprotocol.ai/sp';
const ACS_URL = 'https://www.emiliaprotocol.ai/api/sso/saml/acs';
const IDP_ENTRY = 'https://idp.example.com/sso';

// Generate a throwaway IdP keypair+cert via openssl AT COLLECTION TIME (sync, at
// import) so it.skipIf — which is evaluated when tests are collected, before any
// beforeAll — sees the real availability. No private keys are committed.
function genCert() {
  const key = execFileSync('openssl', ['genrsa', '2048'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  const cert = execFileSync('openssl', ['req', '-new', '-x509', '-key', '/dev/stdin', '-days', '2', '-subj', '/CN=fixture-idp'], { input: key, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] });
  return { key, cert, certBody: cert.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '') };
}

let idp = null;          // { key, cert, certBody }
let otherCertBody = null;
try {
  idp = genCert();
  otherCertBody = genCert().certBody;
} catch {
  idp = null;            // openssl unavailable — positive signed tests skip cleanly
}
const NO_OPENSSL = !idp;

function sp(idpCertBody) {
  return buildSamlSp({ idpEntryPoint: IDP_ENTRY, idpCert: idpCertBody, spEntityId: SP_ENTITY_ID, acsUrl: ACS_URL });
}

describe('SAML SP — structure', () => {
  it('buildSamlSp throws without an IdP cert', () => {
    expect(() => buildSamlSp({ spEntityId: SP_ENTITY_ID, acsUrl: ACS_URL })).toThrow(/idpCert/);
  });

  it('generates SP metadata with the entityID and ACS endpoint', () => {
    const xml = spMetadata(sp('MIIFAKECERT'));
    expect(xml).toContain('entityID="' + SP_ENTITY_ID + '"');
    expect(xml).toContain('AssertionConsumerService');
    expect(xml).toContain(ACS_URL);
    expect(xml).toContain('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
  });

  it('builds an SP-initiated login redirect carrying a SAMLRequest', async () => {
    const url = await buildLoginUrl(sp('MIIFAKECERT'), { relayState: 'rs1' });
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe(IDP_ENTRY);
    expect(u.searchParams.get('SAMLRequest')).toBeTruthy();
    expect(u.searchParams.get('RelayState')).toBe('rs1');
  });
});

describe('SAML SP — rejection paths (must not authenticate)', () => {
  it('rejects an empty response', async () => {
    const r = await validateSamlResponse(sp('MIIFAKECERT'), '');
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Missing SAMLResponse/);
  });

  it('rejects non-XML garbage', async () => {
    const r = await validateSamlResponse(sp('MIIFAKECERT'), Buffer.from('not xml at all').toString('base64'));
    expect(r.valid).toBe(false);
  });

  it('rejects an UNSIGNED assertion (wantAssertionsSigned)', async () => {
    const unsigned = samlResponseXml({ signed: false });
    const r = await validateSamlResponse(sp('MIIFAKECERT'), Buffer.from(unsigned).toString('base64'));
    expect(r.valid).toBe(false);
  });
});

describe('SAML SP — signed assertion round-trip (openssl required)', () => {
  it.skipIf(NO_OPENSSL)('ACCEPTS a validly-signed assertion', async () => {
    const signed = signAssertion(samlResponseXml({ signed: true }), idp.key, idp.cert);
    const r = await validateSamlResponse(sp(idp.certBody), Buffer.from(signed).toString('base64'));
    expect(r.valid).toBe(true);
    expect(r.profile.nameID).toBe('approver@example.com');
  });

  it.skipIf(NO_OPENSSL)('REJECTS an assertion signed by a different key', async () => {
    const signed = signAssertion(samlResponseXml({ signed: true }), idp.key, idp.cert);
    // Configure the SP to trust a DIFFERENT cert than the one that signed.
    const r = await validateSamlResponse(sp(otherCertBody), Buffer.from(signed).toString('base64'));
    expect(r.valid).toBe(false);
  });
});

// ── helpers ──────────────────────────────────────────────────────────────────

// A minimal-but-valid SAML 2.0 Response with one Assertion. `signed:false`
// returns the unsigned XML; signAssertion() adds the enveloped signature.
function samlResponseXml() {
  // Anchor to real now so the assertion's Conditions window is currently valid
  // (a hardcoded instant would expire by test-run time and be rejected).
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000).toISOString();
  const notAfter = new Date(now.getTime() + 3600_000).toISOString();
  const issueInstant = now.toISOString();
  return `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="${issueInstant}" Destination="${ACS_URL}">
  <saml:Issuer>${IDP_ENTRY}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert1" Version="2.0" IssueInstant="${issueInstant}">
    <saml:Issuer>${IDP_ENTRY}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">approver@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${notAfter}" Recipient="${ACS_URL}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notAfter}">
      <saml:AudienceRestriction><saml:Audience>${SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="_sess1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>approver@example.com</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
}

// Sign the Assertion element (enveloped, exclusive-c14n, rsa-sha256) with xml-crypto.
function signAssertion(xml, privateKey, publicCert) {
  const sig = new SignedXml({
    privateKey,
    publicCert,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' },
  });
  return sig.getSignedXml();
}
