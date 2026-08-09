type Obj = Record<string, any>;
export declare const A2A_AE_CHALLENGE_EXTENSION_URI = "https://emiliaprotocol.ai/extensions/a2a/authorization-evidence-challenge/v1";
export declare const A2A_AE_CHALLENGE_PART_PROFILE = "AE-CHALLENGE-v1";
export declare const A2A_AP2_NATIVE_PRESENTATION_METHOD = "ap2-native";
export interface A2AAuthorizationChallengeTaskInput {
    task_id: string;
    context_id: string;
    message_id: string;
    timestamp: string;
    challenge: unknown;
}
export interface A2AAuthorizationChallengeVerification {
    valid: boolean;
    task_id: string | null;
    context_id: string | null;
    challenge: unknown | null;
    reasons: string[];
    authorization_granted: false;
    admission_transferred: false;
}
export declare function createA2AAuthorizationChallengeTask(input: A2AAuthorizationChallengeTaskInput): Readonly<Obj>;
export declare function verifyA2AAuthorizationChallengeTask(candidate: unknown, expectedAction: unknown, now: string): A2AAuthorizationChallengeVerification;
export {};
//# sourceMappingURL=a2a-evidence-challenge.d.ts.map