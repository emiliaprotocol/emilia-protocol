type Obj = Record<string, any>;
export declare const AGENTROA_DRAFT = "draft-nivalto-agentroa-route-authorization-01";
/**
 * Verify an AgentROA -01 evidence bundle.
 *
 * Expected evidence:
 *   { chain: [roaEnvelope, ...araObjects], aer }
 *
 * Expected relying-party context (the shape AEC supplies custom verifiers):
 *   {
 *     keysByType: {
 *       agentroa: {
 *         roa: { [signer]: ed25519Spki },
 *         ara: { [signer]: ed25519Spki },
 *         aer: { [gatewayId]: ed25519Spki }
 *       }
 *     },
 *     policiesByType: {
 *       agentroa: {
 *         expected_policy_id,
 *         expected_policy_version,
 *         expected_policy_digest,
 *         allow_degraded,
 *         allowed_topologies,
 *         capability_manifest: { [wildcard]: [concreteCapability, ...] }
 *       }
 *     },
 *     verificationTime,
 *     action
 *   }
 */
export declare function verifyAgentROA(evidence: Obj, context?: Obj): Obj;
export {};
//# sourceMappingURL=agentroa.d.ts.map