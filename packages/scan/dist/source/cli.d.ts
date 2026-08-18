export interface SourceIo {
    stdout: (value: string) => void;
    stderr: (value: string) => void;
}
export declare function sourceMain(argv: string[], io?: SourceIo): number;
//# sourceMappingURL=cli.d.ts.map