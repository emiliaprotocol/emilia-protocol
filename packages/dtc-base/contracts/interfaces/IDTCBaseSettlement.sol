// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/**
 * @title DTC Base settlement interface
 * @notice Exact-value settlement profile for consequence-bound EMILIA operations.
 */
interface IDTCBaseSettlement {
    enum Status {
        NONE,
        RESERVED,
        INVOKED,
        INDETERMINATE,
        SUCCEEDED,
        FAILED,
        CANCELLED
    }

    enum OutcomeKind {
        NONE,
        SUCCEEDED,
        FAILED,
        INDETERMINATE
    }

    enum Resolution {
        NONE,
        PROVIDER_EVIDENCE,
        RECONCILED_PROVIDER_EVIDENCE,
        PARTY_AGREEMENT,
        EXPIRY_CANCELLATION,
        PAYER_PRE_EFFECT_CANCELLATION
    }

    struct Authorization {
        bytes32 receiptHash;
        bytes32 caid;
        bytes32 actionHash;
        bytes32 programHash;
        bytes32 inputHash;
        address payer;
        address executor;
        address merchant;
        address authorizationSigner;
        address providerSigner;
        uint256 maxAmount;
        uint64 expiresAt;
        uint64 providerConfigVersion;
        uint256 nonce;
    }

    struct Invocation {
        bytes32 operationId;
        bytes32 invocationHash;
        bytes32 providerRequestId;
        uint64 observedAt;
    }

    struct Outcome {
        bytes32 operationId;
        bytes32 invocationHash;
        bytes32 providerRequestId;
        bytes32 evidenceHash;
        bytes32 priorOutcomeDigest;
        uint256 amount;
        uint64 observedAt;
        OutcomeKind kind;
    }

    struct Operation {
        bytes32 authorizationDigest;
        bytes32 receiptHash;
        bytes32 caid;
        bytes32 actionHash;
        bytes32 programHash;
        bytes32 inputHash;
        bytes32 invocationHash;
        bytes32 providerRequestId;
        bytes32 invocationSignatureHash;
        bytes32 outcomeDigest;
        bytes32 evidenceHash;
        bytes32 resolutionSignatureHash;
        bytes32 certificateHash;
        address payer;
        address executor;
        address merchant;
        address authorizationSigner;
        address providerSigner;
        uint256 maxAmount;
        uint256 settledAmount;
        uint64 expiresAt;
        uint64 providerConfigVersion;
        uint64 reservedAt;
        uint64 invokedAt;
        uint64 outcomeObservedAt;
        uint64 terminalAt;
        Status status;
        Resolution resolution;
    }

    event OperationReserved(
        bytes32 indexed operationId,
        bytes32 indexed receiptHash,
        bytes32 indexed caid,
        address payer,
        address executor,
        address merchant,
        address providerSigner,
        uint256 maxAmount
    );
    event ProviderBoundaryEntered(
        bytes32 indexed operationId,
        bytes32 indexed invocationHash,
        bytes32 indexed providerRequestId,
        uint64 observedAt,
        bytes32 signatureHash
    );
    event OutcomeRecorded(
        bytes32 indexed operationId,
        OutcomeKind kind,
        bytes32 indexed evidenceHash,
        uint256 amount,
        uint64 observedAt,
        address signer,
        bytes32 signatureHash
    );
    event TerminalCertificateCreated(
        bytes32 indexed operationId,
        bytes32 indexed certificateHash,
        Status status,
        Resolution resolution
    );
    event Withdrawal(address indexed account, address indexed recipient, uint256 amount);

    function reserve(Authorization calldata authorization, bytes calldata signature)
        external
        payable
        returns (bytes32 operationId);
    function markInvoked(Invocation calldata invocation, bytes calldata providerSignature) external;
    function submitOutcome(Outcome calldata outcome, bytes calldata providerSignature) external;
    function reconcile(Outcome calldata outcome, bytes calldata providerSignature) external;
    function settleByAgreement(
        Outcome calldata outcome,
        bytes calldata payerSignature,
        bytes calldata merchantSignature
    ) external;
    function cancelBeforeInvocation(bytes32 operationId) external;
    function cancelExpired(bytes32 operationId) external;
    function withdraw() external;
    function withdrawTo(address payable recipient) external;
    function hashAuthorization(Authorization calldata authorization) external view returns (bytes32);
    function hashInvocation(Invocation calldata invocation) external view returns (bytes32);
    function hashOutcome(Outcome calldata outcome) external view returns (bytes32);
    function getOperation(bytes32 operationId) external view returns (Operation memory);
}
