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
import { z } from 'zod';
import { verifyReceipt, verifyWebAuthnSignoff } from '@/lib/verify-web';
import { getPublicBaseUrl } from '@/lib/env';

const BASE = getPublicBaseUrl();

const text = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

const handler = createMcpHandler(
  (server) => {
    server.registerTool(
      'ep_verify_receipt',
      {
        title: 'Verify Trust Receipt (offline math, in-process)',
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        description:
          'Verify an EP-RECEIPT-v1 trust receipt with pure public-key math — '
          + 'Ed25519 over canonical JSON plus optional Merkle anchor. Proves the '
          + 'receipt was signed by its issuer and not altered. No account, no '
          + 'stored state; the same open-source verifier anyone can run '
          + '(npm: @emilia-protocol/verify).',
        inputSchema: {
          document: z.record(z.string(), z.unknown()).describe('The EP-RECEIPT-v1 document (JSON object)'),
          public_key: z.string().optional().describe("Issuer Ed25519 public key (base64url SPKI DER). Optional if the document embeds issuer_public_key."),
        },
      },
      async ({ document, public_key }) => {
        const key = public_key || document?.issuer_public_key;
        if (!key) return text({ valid: false, error: 'No public key: pass public_key or embed issuer_public_key in the document.' });
        return text(await verifyReceipt(document, key));
      },
    );

    server.registerTool(
      'ep_verify_signoff',
      {
        title: 'Verify Class-A Device Signoff (offline math, in-process)',
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        description:
          'Verify a Class-A human device signoff: a WebAuthn assertion (ECDSA '
          + 'P-256) whose challenge is the SHA-256 of the canonicalized '
          + 'authorization context. Proves a named human approved this EXACT '
          + 'action on their own device (user-present + user-verified) — change '
          + 'one field and verification fails.',
        inputSchema: {
          signoff: z.record(z.string(), z.unknown()).describe('Signoff object with { context, webauthn: { authenticator_data, client_data_json, signature } }'),
          approver_public_key: z.string().optional().describe('Approver P-256 public key (base64url SPKI DER). Optional if the signoff embeds approver_public_key.'),
          rp_id: z.string().optional().describe('Expected relying-party ID (e.g. emiliaprotocol.ai). Optional if embedded as rp_id.'),
        },
      },
      async ({ signoff, approver_public_key, rp_id }) => {
        const key = approver_public_key || signoff?.approver_public_key;
        if (!key) return text({ valid: false, error: 'No public key: pass approver_public_key or embed it in the signoff.' });
        const rpId = rp_id || signoff?.rp_id || undefined;
        return text(await verifyWebAuthnSignoff(signoff, key, rpId ? { rpId } : {}));
      },
    );

    server.registerTool(
      'ep_trust_profile',
      {
        title: 'Get Trust Profile',
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        description: "Fetch an entity's public EP trust profile — composite score, behavioral rates, and receipt-backed history.",
        inputSchema: {
          entity_id: z.string().describe('The EP entity id'),
        },
      },
      async ({ entity_id }) => {
        const res = await fetch(`${BASE}/api/trust/profile/${encodeURIComponent(entity_id)}`);
        return text(await res.json());
      },
    );

    server.registerTool(
      'ep_trust_evaluate',
      {
        title: 'Evaluate Trust Policy',
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        description: 'Evaluate an entity against a named EP trust policy (standard, strict, permissive, discovery) and return the allow/review/deny decision with reasons.',
        inputSchema: {
          entity_id: z.string().describe('The EP entity id'),
          policy: z.enum(['standard', 'strict', 'permissive', 'discovery']).default('standard').describe('Policy to evaluate against'),
        },
      },
      async ({ entity_id, policy }) => {
        const res = await fetch(`${BASE}/api/trust/evaluate`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ entity_id, policy }),
        });
        return text(await res.json());
      },
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

export { handler as GET, handler as POST, handler as DELETE };
