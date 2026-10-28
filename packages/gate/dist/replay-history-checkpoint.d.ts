export interface ReplayHistoryCheckpoint {
    sequence: number;
    checkpoint_digest: string;
}
export interface ReplayHistoryCheckpointStore {
    read(): Promise<ReplayHistoryCheckpoint>;
    advance(expected: Readonly<ReplayHistoryCheckpoint>, next: Readonly<ReplayHistoryCheckpoint>): Promise<ReplayHistoryCheckpoint>;
}
/** Explicit one-time provisioning. Existing directories are NEVER reinitialized. */
export declare function provisionReplayHistoryCheckpoint(directory: string, genesis: string): Promise<void>;
export declare function createFileReplayHistoryCheckpoint(directory: string): ReplayHistoryCheckpointStore;
//# sourceMappingURL=replay-history-checkpoint.d.ts.map