/**
 * Remote MCP server — streamable HTTP at /api/mcp/mcp.
 * @license Apache-2.0
 *
 * The hosted counterpart to @emilia-protocol/mcp-server (stdio, npm): a
 * no-auth, read-only connector exposing EP's public verification + trust
 * tools to claude.ai, Claude Desktop, and any streamable-HTTP MCP client —
 * no install, no API key. Write tools (guard/mint/signoff) intentionally stay
 * on the authenticated local server.
 *
 * ep_verify_receipt / ep_verify_signoff run the actual offline verifier
 * (lib/verify-web.js, Web Crypto) in-process — the server never needs to be
 * trusted, which is the protocol's whole point. Profile/evaluate proxy EP's
 * public read endpoints.
 */

import { createMcpHandler } from 'mcp-handler';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyReceipt, verifyWebAuthnSignoff } from '@/lib/verify-web';
import { getPublicBaseUrl } from '@/lib/env';

const BASE = getPublicBaseUrl();
const MAX_MCP_BYTES = 256 * 1024;

const text = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

export async function verifyReceiptTool({ document, public_key }) {
  if (typeof public_key !== 'string' || !public_key) {
    return {
      valid: false,
      accepted: null,
      scope: 'cryptographic_integrity',
      error: 'A caller-supplied issuer key is required. Artifact-embedded keys cannot establish their own trust.',
    };
  }
  const result = await verifyReceipt(document, public_key);
  return {
    ...result,
    accepted: null,
    scope: 'cryptographic_integrity',
    key_source: 'caller_supplied',
    limitation: 'This verifies bytes under the supplied key. It does not establish who controls that key, issuer authority, policy acceptance, or legal reliance.',
  };
}

export async function verifySignoffTool({ signoff, approver_public_key, rp_id, allowed_origins }) {
  if (typeof approver_public_key !== 'string' || !approver_public_key) {
    return {
      valid: false,
      accepted: null,
      scope: 'scoped_webauthn_integrity',
      error: 'A caller-supplied approver key is required. Artifact-embedded keys cannot establish their own identity.',
    };
  }
  if (typeof rp_id !== 'string' || !rp_id
      || !Array.isArray(allowed_origins) || allowed_origins.length === 0
      || allowed_origins.some((origin) => typeof origin !== 'string' || !origin)) {
    return {
      valid: false,
      accepted: null,
      scope: 'scoped_webauthn_integrity',
      error: 'rp_id and at least one exact allowed_origins entry are required for WebAuthn verification.',
    };
  }
  const result = await verifyWebAuthnSignoff(signoff, approver_public_key, {
    rpId: rp_id,
    allowedOrigins: allowed_origins,
  });
  return {
    ...result,
    accepted: null,
    scope: 'scoped_webauthn_integrity',
    key_source: 'caller_supplied',
    limitation: 'This verifies a user-present, user-verified ceremony under the supplied key and WebAuthn scope. It does not prove legal identity, perception, authority, or relying-party acceptance.',
  };
}

const handler = createMcpHandler(
  (server) => {
    server.registerTool(
      'ep_verify_receipt',
      {
        title: 'Check receipt signature integrity (offline, in-process)',
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        description:
          'Check an EP-RECEIPT-v1 with pure public-key math — Ed25519 over '
          + 'canonical JSON plus an optional Merkle anchor — under a key supplied '
          + 'by the caller. This checks integrity, not issuer identity, authority, '
          + 'policy acceptance, or legal reliance. No account, no '
          + 'stored state; the same open-source verifier anyone can run '
          + '(npm: @emilia-protocol/verify).',
        inputSchema: {
          document: z.record(z.string(), z.unknown()).describe('The EP-RECEIPT-v1 document (JSON object)'),
          public_key: z.string().min(1).describe('Issuer Ed25519 public key from the caller\'s trust configuration (base64url SPKI DER). Artifact-embedded keys are not accepted as trust anchors.'),
        },
      },
      async (input) => text(await verifyReceiptTool(input)),
    );

    server.registerTool(
      'ep_verify_signoff',
      {
        title: 'Check scoped WebAuthn signoff (offline, in-process)',
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        description:
          'Check a WebAuthn assertion (ECDSA P-256) whose challenge is the '
          + 'SHA-256 of the canonicalized authorization context, under a '
          + 'caller-supplied key, RP ID, and exact origin allowlist. This checks '
          + 'a user-present and user-verified ceremony; it does not establish '
          + 'legal identity, authority, perception, or relying-party acceptance.',
        inputSchema: {
          signoff: z.record(z.string(), z.unknown()).describe('Signoff object with { context, webauthn: { authenticator_data, client_data_json, signature } }'),
          approver_public_key: z.string().min(1).describe('Approver P-256 public key from the caller\'s trust configuration (base64url SPKI DER).'),
          rp_id: z.string().min(1).describe('Expected WebAuthn relying-party ID (e.g. emiliaprotocol.ai).'),
          allowed_origins: z.array(z.string().min(1)).min(1).describe('Exact WebAuthn origins accepted by the relying party.'),
        },
      },
      async (input) => text(await verifySignoffTool(input)),
    );

  },
  {
    serverInfo: { name: 'emilia-protocol', version: '1.0.0' },
    capabilities: { tools: {} },
  },
  {
    basePath: '/api/mcp', // endpoint: POST /api/mcp/mcp (streamable HTTP)
    maxDuration: 60,
    verboseLogs: false,
  },
);

function bodyTooLarge(request) {
  const declaredLen = parseInt(request.headers.get('content-length') || '0', 10);
  return declaredLen && declaredLen > MAX_MCP_BYTES;
}

export const GET = handler;
export const DELETE = handler;

export async function POST(request, context) {
  if (bodyTooLarge(request)) {
    return NextResponse.json({
      jsonrpc: '2.0',
      error: { code: -32600, message: 'Request body too large' },
      id: null,
    }, { status: 413 });
  }
  return handler(request, context);
}
