import { NextResponse } from "next/server";
import { authenticateCloudRequest } from "@/lib/cloud/auth";
import { requirePermission } from "@/lib/cloud/authorize";
import { loadTenantGuardReceipts } from "@/lib/cloud/guard-receipts";
import { getGuardedClient } from "@/lib/write-guard";
import { epProblem, EP_ERRORS } from "@/lib/errors";
import { logger } from "@/lib/logger.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;
const MAX_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;

function boundedText(value: unknown, max = 512): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return normalized ? normalized.slice(0, max) : null;
}

function parseLimit(value: string | null): number | null {
  if (value === null) return DEFAULT_LIMIT;
  if (!/^[1-9][0-9]*$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= MAX_LIMIT ? parsed : null;
}

function parseInstant(value: string | null): { value?: string; valid: boolean } {
  if (value === null) return { valid: true };
  if (value.length > 64 || !Number.isFinite(Date.parse(value))) return { valid: false };
  return { value: new Date(value).toISOString(), valid: true };
}

function normalizeRun(receipt: Record<string, unknown>) {
  const receiptId = boundedText(receipt.receipt_id, 128);
  if (!receiptId) return null;
  return {
    receipt_id: receiptId,
    created_at: boundedText(receipt.created_at, 64),
    action_type: boundedText(receipt.action_type, 256),
    action_hash: boundedText(receipt.action_hash, 128),
    caid: boundedText(receipt.caid, 512),
    decision: boundedText(receipt.decision, 128),
    status: boundedText(receipt.status, 128),
    policy_id: boundedText(receipt.policy_id, 256),
    authority_verdict: boundedText(receipt.authority_verdict, 128),
    enforcement_mode: boundedText(receipt.enforcement_mode, 64),
    adapter: boundedText(receipt.adapter, 128),
    amount: typeof receipt.amount === "number" && Number.isFinite(receipt.amount)
      ? receipt.amount
      : null,
    currency: boundedText(receipt.currency, 16),
    signoff_required: receipt.signoff_required === true,
  };
}

export async function GET(request: Request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, "read");

    // audit_events predates Cloud environments. Until each persisted row has
    // an environment binding, admitting a staging/development key would let it
    // read the tenant's production receipt stream. Fail closed instead.
    if (auth.environment !== "production") {
      return epProblem(
        403,
        "environment_scope_unsupported",
        "Evidence readiness currently requires a production-scoped Cloud key.",
      );
    }

    const url = new URL(request.url);
    const limit = parseLimit(url.searchParams.get("limit"));
    const from = parseInstant(url.searchParams.get("date_from"));
    const to = parseInstant(url.searchParams.get("date_to"));
    if (limit === null || !from.valid || !to.valid) {
      return epProblem(
        400,
        "invalid_query",
        "limit must be an integer from 1 to 100 and dates must be valid instants.",
      );
    }
    if (from.value && to.value) {
      const windowMs = Date.parse(to.value) - Date.parse(from.value);
      if (windowMs < 0 || windowMs > MAX_WINDOW_MS) {
        return epProblem(
          400,
          "invalid_date_range",
          "date_from must precede date_to and the requested window must not exceed 31 days.",
        );
      }
    }

    const result = await loadTenantGuardReceipts({
      supabase: getGuardedClient(),
      tenantId: auth.tenantId,
      limit,
      dateFrom: from.value,
      dateTo: to.value,
      log: logger,
    });
    if (result.error) {
      return epProblem(
        503,
        "evidence_source_unavailable",
        "The tenant-scoped evidence source is unavailable; no partial result was returned.",
      );
    }

    const runs = result.receipts.flatMap((receipt) => {
      const normalized = normalizeRun(receipt);
      return normalized ? [normalized] : [];
    });
    return NextResponse.json(
      {
        schema: "emilia.evidence-readiness.v1",
        tenant_id: auth.tenantId,
        environment: auth.environment,
        source: "audit_events.guard_trust_receipts",
        returned: runs.length,
        limit,
        truncated: result.truncated === true,
        date_range: { from: from.value ?? null, to: to.value ?? null },
        runs,
        generated_at: new Date().toISOString(),
        claim_boundary:
          "These are tenant-scoped lifecycle records as stored by EMILIA; they may include tests and do not independently prove a claimed external effect.",
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "CloudAuthorizationError") {
      return epProblem(403, "forbidden", err.message);
    }
    logger.error("[cloud/evidence-readiness/runs] Error:", err);
    return EP_ERRORS.INTERNAL();
  }
}
