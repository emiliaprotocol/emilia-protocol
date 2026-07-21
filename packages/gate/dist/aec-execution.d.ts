import { MemoryConsumptionStore } from './store.js';
type Obj = Record<string, any>;
type ConsumptionStore = {
    durable?: boolean;
    ownershipFenced?: boolean;
    permanentConsumption?: boolean;
    reserve?: (key: string) => Promise<boolean> | boolean;
    commit?: (key: string) => Promise<boolean> | boolean;
    release?: (key: string) => Promise<void> | void;
};
type ExecutionEvidenceLog = {
    durable?: boolean;
    strict?: boolean;
    forkAware?: boolean;
    atomicAppend?: boolean;
    record?: (entry: Obj) => Promise<Obj> | Obj;
};
declare function deepFreeze(value: any): any;
declare function validLogRecord(record: any, atomicRequired: any, expectedEntry: any): boolean;
declare function validComponent(result: any, type: any): any;
declare function humanFloorSatisfied(result: any, floor: any): any;
declare function evidenceSatisfied(result: any): boolean;
declare function consumptionKey(result: any): string | null;
declare function instant(now: any): string | null;
/**
 * @param {object} [config]
 * @param {string} [config.requirement] relying-party AEC requirement (required at runtime)
 * @param {object} [config.policiesByType] relying-party human acceptance profiles (required at runtime)
 * @param {object} [config.verifiers] relying-party-pinned custom component verifiers
 * @param {object} [config.keysByType] relying-party-pinned custom verifier keys
 * @param {'class_a'|'quorum'|'class_a_or_quorum'} [config.humanFloor] (required at runtime)
 * @param {object} [config.store] ownership-fenced consumption store
 * @param {object} [config.log] tamper-evident evidence log
 * @param {boolean} [config.allowEphemeralState=false] test/demo opt-in only
 * @param {Function|number|Date} [config.now=Date.now]
 */
export declare function createAECExecutionGate({ requirement, policiesByType, verifiers, keysByType, humanFloor, store, log, allowEphemeralState, now, }?: {
    requirement?: string;
    policiesByType?: Obj;
    verifiers?: Record<string, Function>;
    keysByType?: Obj;
    humanFloor?: 'class_a' | 'quorum' | 'class_a_or_quorum';
    store?: ConsumptionStore;
    log?: ExecutionEvidenceLog;
    allowEphemeralState?: boolean;
    now?: (() => number) | number | Date;
}): {
    run: (request: Obj | undefined, effect: (input: {
        action: any;
        result: any;
        authorization: any;
    }) => any) => Promise<{
        ok: false;
        allow: false;
        reason: string;
        result: Obj | null;
        decision: any;
        value?: undefined;
        authorization?: undefined;
        execution?: undefined;
    } | {
        ok: true;
        allow: true;
        value: any;
        result: any;
        authorization: any;
        execution: any;
        reason?: undefined;
    }>;
    evidence: {
        durable: boolean;
        persisted: boolean;
        strict: boolean;
        forkAware: boolean;
        atomicAppend: boolean;
        record(entry: any): Promise<any>;
        all(): Record<string, any>[];
        verify(): {
            ok: boolean;
            at: any;
            reason: string;
            length?: undefined;
            head?: undefined;
        } | {
            ok: boolean;
            length: number;
            head: string | null;
            at?: undefined;
            reason?: undefined;
        };
    } | ExecutionEvidenceLog;
    store: MemoryConsumptionStore | ConsumptionStore;
};
export declare const __aecExecutionSecurityInternals: Readonly<{
    deepFreeze: typeof deepFreeze;
    validLogRecord: typeof validLogRecord;
    validComponent: typeof validComponent;
    humanFloorSatisfied: typeof humanFloorSatisfied;
    evidenceSatisfied: typeof evidenceSatisfied;
    consumptionKey: typeof consumptionKey;
    instant: typeof instant;
}>;
declare const _default: {
    createAECExecutionGate: typeof createAECExecutionGate;
};
export default _default;
//# sourceMappingURL=aec-execution.d.ts.map