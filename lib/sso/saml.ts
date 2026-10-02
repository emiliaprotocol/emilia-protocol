/**
 * SAML 2.0 Service Provider — metadata, AuthnRequest, and signed-Response
 * validation.
 *
 * Wraps `@node-saml/node-saml` (which uses `xml-crypto` for XML-DSig). All
 * signature verification — the part where naive implementations fall to XML
 * signature-wrapping attacks — is done by that vetted library, not hand-rolled.
 * Both the Response envelope and Assertion are signed by default: unsigned or
 * wrong-key messages are rejected, and the caller must pin the expected ACS
 * target used for Destination and bearer Recipient validation.
 *
 * Config-injected so structure + rejection paths are unit-testable. The positive
 * round-trip (a real signed assertion from Okta/Entra) is exercised during
 * onboarding against that tenant.
 *
 * Two xmldom lines are in play by design. node-saml, xml-crypto, and
 * xml-encryption declare only `@xmldom/xmldom` ^0.8, so package.json pins them
 * to their own nested 0.8.15 copy and signature verification runs on 0.8. The
 * endpoint-binding check below is this module's own code and runs on the
 * directly-depended 0.9 line. Its parser is deliberately stricter than
 * node-saml's (which tolerates warnings): any 0.9 diagnostic rejects the
 * message. Only XML that 0.9 parses without a single warning reaches the
 * Destination and Recipient comparison, which keeps the inputs the two parser
 * versions could read differently (unquoted or redefined attributes, unbound
 * prefixes, stray end-tag characters, replacement characters) away from that
 * comparison.
 *
 * @license Apache-2.0
 */

import { SAML } from '@node-saml/node-saml';
import { DOMParser, MIME_TYPE } from '@xmldom/xmldom';
import type { Document, Element } from '@xmldom/xmldom';

const SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const SAML_ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const SAML_BEARER_METHOD = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

type SamlResponseTargetOptions = {
  expectedAcsUrl: string;
};

/**
 * Parse an already signature-validated SAML Response with xmldom 0.9 under the
 * strict SAML policy: every parser diagnostic, at the `warning`, `error`, and
 * `fatalError` levels alike, rejects the message. The callback records the
 * first diagnostic and throws, which xmldom 0.9 turns into a `ParseError` that
 * stops parsing; the recorded diagnostic is checked as well so the policy does
 * not depend on that conversion. Returns null when the XML must be refused.
 *
 * A single leading U+FEFF is the UTF-8 byte-order mark left over from decoding
 * the base64 bytes with `toString('utf8')`. It is an encoding signature, not
 * document content (XML 1.0 section 4.3.3), and node-saml's 0.8 parse ignores
 * it, but xmldom 0.9 reports it as content outside the root element. Dropping
 * exactly that one character keeps a BOM-prefixed IdP response, which the
 * signature check already accepted, from being refused here.
 */
function parseSignedResponseXml(xml: string): Document | null {
  if (xml.charCodeAt(0) === 0xfeff) xml = xml.slice(1);
  let diagnostic: string | null = null;
  let document: Document;
  try {
    document = new DOMParser({
      onError: (level, message) => {
        diagnostic ??= `${level}: ${message}`;
        throw new Error(diagnostic);
      },
    }).parseFromString(xml, MIME_TYPE.XML_APPLICATION);
  } catch {
    return null;
  }
  return diagnostic === null ? document : null;
}

function validateSignedResponseTarget(
  xml: string,
  expectedAcsUrl: string,
): string | null {
  const document = parseSignedResponseXml(xml);
  if (!document) return 'SAML response XML could not be parsed';

  const response = document.documentElement;
  if (response?.namespaceURI !== SAML_PROTOCOL_NS || response.localName !== 'Response') {
    return 'SAML response root must be a SAML Response';
  }
  if (response.getAttribute('Destination') !== expectedAcsUrl) {
    return 'SAML response Destination does not match the configured ACS endpoint';
  }

  const assertions = response.getElementsByTagNameNS(SAML_ASSERTION_NS, 'Assertion');
  if (assertions.length !== 1) {
    return 'SAML response must contain exactly one Assertion';
  }

  const confirmations = assertions[0].getElementsByTagNameNS(
    SAML_ASSERTION_NS,
    'SubjectConfirmation',
  );
  let bearerConfirmations = 0;
  for (let i = 0; i < confirmations.length; i += 1) {
    const confirmation = confirmations[i];
    if (confirmation.getAttribute('Method') !== SAML_BEARER_METHOD) continue;
    bearerConfirmations += 1;
    if (bearerConfirmations > 1) {
      return 'SAML response must contain exactly one bearer SubjectConfirmation';
    }
    const data: Element[] = [];
    for (let child = confirmation.firstChild; child; child = child.nextSibling) {
      const element = child as Element;
      if (child.nodeType === child.ELEMENT_NODE
          && element.namespaceURI === SAML_ASSERTION_NS
          && element.localName === 'SubjectConfirmationData') {
        data.push(element);
      }
    }
    if (data.length !== 1 || data[0].getAttribute('Recipient') !== expectedAcsUrl) {
      return 'SAML bearer Recipient does not match the configured ACS endpoint';
    }
  }
  if (bearerConfirmations !== 1) {
    return 'SAML response must contain exactly one bearer SubjectConfirmation';
  }
  return null;
}

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
    // We do not sign AuthnRequests (no SP private key required for a basic SP).
    // The Response envelope must be signed so its Destination and the nested
    // bearer Recipient can be treated as authenticated endpoint bindings.
    wantAuthnResponseSigned: cfg.wantAuthnResponseSigned ?? true,
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
  options: SamlResponseTargetOptions,
): Promise<
  | { valid: false; error: string; profile?: undefined }
  | { valid: true; profile: any }
> {
  const expectedAcsUrl = options?.expectedAcsUrl;
  if (typeof expectedAcsUrl !== 'string' || expectedAcsUrl.length === 0) {
    return { valid: false, error: 'Configured SAML ACS target is required' };
  }
  if (!samlResponseB64 || typeof samlResponseB64 !== 'string') {
    return { valid: false, error: 'Missing SAMLResponse' };
  }
  const xml = Buffer.from(samlResponseB64, 'base64').toString('utf8');
  // Reject document-type/entity declarations before either validator parses
  // the bytes. SAML messages do not need them and accepting them would add an
  // unnecessary entity-expansion / parser-differential surface.
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml)) {
    return { valid: false, error: 'SAML response XML declarations are not allowed' };
  }
  try {
    const { profile } = await sp.validatePostResponseAsync({
      SAMLResponse: samlResponseB64,
    });
    if (!profile) return { valid: false, error: 'No profile in SAML response' };
    // Inspect endpoint-binding attributes only after node-saml has validated the
    // signed Response. The ACS config requires that envelope signature, making
    // Destination and the bearer Recipient authenticated inputs rather than
    // mutable transport hints.
    const targetError = validateSignedResponseTarget(xml, expectedAcsUrl);
    if (targetError) return { valid: false, error: targetError };
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
