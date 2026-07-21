/**
 * Runtime bridge for the Gate lifecycle.
 *
 * This is deliberately an explicit, reviewable monitor rather than a claim
 * that TLA+ can be mechanically compiled into JavaScript. Its transition
 * table mirrors the load-bearing lifecycle invariants in
 * formal/ep_handshake.tla: an effect follows authorization, consumption is
 * one-way, and execution evidence follows the effect attempt. A divergence
 * enters fail-closed safe mode; recovery requires an operator-supplied
 * authorizer and never re-authorizes an old receipt.
 */
export declare const RUNTIME_MONITOR_VERSION = "EP-GATE-RUNTIME-MONITOR-v1";
export declare const RUNTIME_MONITOR_MODES: Readonly<{
    NORMAL: "normal";
    DEGRADED: "degraded";
    LOCKDOWN: "lockdown";
}>;
export declare const RUNTIME_INVARIANTS: Readonly<{
    CONSUME_ONCE: "ConsumeOnceSafety";
    WRITE_BYPASS: "WriteBypassSafety";
    SIGNOFF_BINDING: "SignoffBindingMatch";
}>;
/**
 * Create a process-local monitor. Operators should export divergence events to
 * durable SIEM/evidence storage through onDivergence; the monitor itself keeps
 * only a bounded diagnostic buffer.
 *
 * @param {{ now?: (() => number) | number, onDivergence?: ((event: object) => any) | null, authorizeRecovery?: ((input: object) => boolean) | null }} [options]
 */
export declare function createRuntimeMonitor({ now, onDivergence, authorizeRecovery, }?: {
    now?: (() => number) | number;
    onDivergence?: ((event: object) => any) | null;
    authorizeRecovery?: ((input: object) => boolean) | null;
}): {
    version: string;
    beginCheck({ action, receipt_id }?: {
        action?: null | undefined;
        receipt_id?: null | undefined;
    }): string;
    preflight({ hasReceipt }?: {
        hasReceipt?: boolean;
    }): {
        ok: boolean;
        reason?: undefined;
        mode?: undefined;
    } | {
        ok: boolean;
        reason: string;
        mode: "degraded" | "lockdown";
    };
    minimumAssuranceTier(declaredTier: any): any;
    recordDecision(cycleId: any, details: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    beginExecution(cycleId: any, authorization: any): {
        ok: boolean;
    };
    effectReturned(cycleId: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    effectFailed(cycleId: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    capabilityRefused(cycleId: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    consumptionCommitted(cycleId: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    executionRecorded(cycleId: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    executionSkipped(cycleId: any): {
        ok: boolean;
        reason: string;
        event: any;
    } | {
        ok: boolean;
    };
    getMode(): "normal" | "degraded" | "lockdown";
    getEvents(): any[];
    getState(cycleId: any): any;
    recover(input?: {}): {
        ok: boolean;
        mode: "normal";
        reason?: undefined;
    } | {
        ok: boolean;
        reason: string;
        mode: "degraded" | "lockdown";
    };
};
declare const _default: {
    createRuntimeMonitor: typeof createRuntimeMonitor;
    RUNTIME_MONITOR_VERSION: string;
    RUNTIME_MONITOR_MODES: Readonly<{
        NORMAL: "normal";
        DEGRADED: "degraded";
        LOCKDOWN: "lockdown";
    }>;
    RUNTIME_INVARIANTS: Readonly<{
        CONSUME_ONCE: "ConsumeOnceSafety";
        WRITE_BYPASS: "WriteBypassSafety";
        SIGNOFF_BINDING: "SignoffBindingMatch";
    }>;
};
export default _default;
//# sourceMappingURL=runtime-monitor.d.ts.map