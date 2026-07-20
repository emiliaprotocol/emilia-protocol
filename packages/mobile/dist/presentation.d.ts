export declare const MOBILE_PRESENTATION_VERSION = "EP-MOBILE-PRESENTATION-v1";
type AnyRecord = Record<string, any>;
export declare function projectMobileAction(action: AnyRecord): AnyRecord;
export declare function normalizeMobilePresentation(value: AnyRecord, { allowUnversioned }?: AnyRecord): AnyRecord;
export declare function normalizeControlledMobilePresentation(action: AnyRecord, value: AnyRecord, options?: AnyRecord): AnyRecord;
export declare function validControlledMobilePresentation(action: AnyRecord, value: AnyRecord): boolean;
export declare function validMobilePresentation(value: AnyRecord): boolean;
declare const _default: {
    MOBILE_PRESENTATION_VERSION: string;
    projectMobileAction: typeof projectMobileAction;
    normalizeMobilePresentation: typeof normalizeMobilePresentation;
    normalizeControlledMobilePresentation: typeof normalizeControlledMobilePresentation;
    validMobilePresentation: typeof validMobilePresentation;
    validControlledMobilePresentation: typeof validControlledMobilePresentation;
};
export default _default;
//# sourceMappingURL=presentation.d.ts.map