/**
 * Server-pinned EP-STATUS-v1 verification for Proposal-to-Effect AEB legs.
 *
 * Signed non-revocation status and relying-party consumption state answer
 * different questions. This helper authenticates the former with
 * verifyStatusArtifact and requires an authenticated local answer for the
 * latter. The later atomic AEB reserve remains the race-closing operation.
 */
import type { AebDigest } from '@emilia-protocol/verify/aeb-adapter-contract';
import { type RevokerAuthorityPin, type StatusTarget } from '@emilia-protocol/verify/status';
import type { ProposalToEffectOptions } from './proposal-to-effect.js';
type MaybePromise<T> = T | Promise<T>;
type ProposalToEffectStatusVerifier = ProposalToEffectOptions['aeb']['statusVerifier'];
export type ProposalToEffectStatusVerifierInput = Parameters<ProposalToEffectStatusVerifier>[0];
export type ProposalToEffectStatusExpected = Readonly<ProposalToEffectStatusVerifierInput['expected']>;
export interface ProposalToEffectStatusResolverContext {
    expected: ProposalToEffectStatusExpected;
    target: Readonly<StatusTarget>;
}
export interface ProposalToEffectPreviousHeadResolution {
    /** Confirms this result came from the relying party's authenticated store. */
    authenticated: boolean;
    /** Null means the store authoritatively has no accepted head for the target. */
    status: unknown | null;
}
export interface ProposalToEffectConsumptionState {
    /** Must be true; presenter assertions and unauthenticated cache data fail. */
    authenticated: boolean;
    consumed: boolean;
}
export interface ProposalToEffectConsumptionResolverContext extends ProposalToEffectStatusResolverContext {
    status_digest: AebDigest;
    sequence: number;
}
export interface ProposalToEffectStatusVerifierOptions {
    /** Copied at factory construction; callers cannot swap the authority pin later. */
    authorityPin: RevokerAuthorityPin;
    /** Trusted code mapping the closed PTE expected binding to one exact status target. */
    targetMapper(input: {
        expected: ProposalToEffectStatusExpected;
    }): MaybePromise<StatusTarget>;
    /** Server-side certificate lookup. The presenter never supplies this certificate. */
    certificateResolver(input: ProposalToEffectStatusResolverContext): MaybePromise<unknown>;
    /** Server-side lookup of the relying party's previously accepted status head. */
    previousHeadResolver(input: ProposalToEffectStatusResolverContext): MaybePromise<ProposalToEffectPreviousHeadResolution>;
    /** Authenticated local consumption lookup; this is not inferred from EP-STATUS-v1. */
    consumptionStateResolver(input: ProposalToEffectConsumptionResolverContext): MaybePromise<ProposalToEffectConsumptionState>;
}
/**
 * Build the server-side verifier expected by
 * `ProposalToEffectOptions.aeb.statusVerifier`.
 */
export declare function createProposalToEffectStatusVerifier(options: ProposalToEffectStatusVerifierOptions): ProposalToEffectStatusVerifier;
export {};
//# sourceMappingURL=proposal-to-effect-status.d.ts.map