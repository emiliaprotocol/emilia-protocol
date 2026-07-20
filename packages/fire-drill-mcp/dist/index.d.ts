#!/usr/bin/env node
/**
 * @emilia-protocol/fire-drill-mcp
 * @license Apache-2.0
 *
 * The static receipt-declaration scanner, exposed over MCP.
 *
 * A directory of MCP servers, plus one server whose job is to audit the others:
 * given any MCP manifest, OpenAPI spec, or tool list, it reports which detected
 * dangerous actions omit a required receipt declaration. Runtime is unassessed.
 *
 * Pure wrapper — all scoring logic lives in @emilia-protocol/fire-drill (zero-dep,
 * the same source of truth as `npx @emilia-protocol/fire-drill` and the web /fire-drill).
 *
 * Tools:
 *   fire_drill_scan        — score a target (manifest / OpenAPI / tool list)
 *   fire_drill_leaderboard — static declaration corpus (missing first)
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
type JsonRecord = Record<string, unknown>;
export declare const TOOLS: ({
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            target: {
                type: string;
                description: string;
            };
            target_json: {
                type: string;
                description: string;
            };
        };
        additionalProperties: boolean;
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            target?: undefined;
            target_json?: undefined;
        };
        additionalProperties: boolean;
    };
})[];
export declare function handleToolRequest(request: {
    params: {
        name: string;
        arguments?: JsonRecord;
    };
}): Promise<{
    content: {
        type: string;
        text: string;
    }[];
}>;
export declare function createServer(): Server<{
    method: string;
    params?: {
        [x: string]: unknown;
        _meta?: {
            [x: string]: unknown;
            progressToken?: string | number | undefined;
            "io.modelcontextprotocol/related-task"?: {
                taskId: string;
            } | undefined;
        } | undefined;
    } | undefined;
}, {
    method: string;
    params?: {
        [x: string]: unknown;
        _meta?: {
            [x: string]: unknown;
            progressToken?: string | number | undefined;
            "io.modelcontextprotocol/related-task"?: {
                taskId: string;
            } | undefined;
        } | undefined;
    } | undefined;
}, {
    [x: string]: unknown;
    _meta?: {
        [x: string]: unknown;
        progressToken?: string | number | undefined;
        "io.modelcontextprotocol/related-task"?: {
            taskId: string;
        } | undefined;
    } | undefined;
}>;
export declare function startServer(): Promise<void>;
export {};
//# sourceMappingURL=index.d.ts.map