// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AccessControlDefaultAdminRules} from
    "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IDTCBaseSettlement} from "./interfaces/IDTCBaseSettlement.sol";

/**
 * @title DTCBaseSettlement
 * @author EMILIA Protocol
 * @notice Optional Base settlement profile for exact, consequence-bound EMILIA actions.
 * @dev A role-pinned bridge attests the verified EMILIA authorization. A merchant-pinned
 *      provider signer separately attests provider entry and outcome. This contract binds
 *      those attestations to escrow; it does not reimplement the EMILIA Gate or CAID resolver.
 */
contract DTCBaseSettlement is
    IDTCBaseSettlement,
    AccessControlDefaultAdminRules,
    Pausable,
    ReentrancyGuard,
    EIP712
{
    bytes32 public constant AUTHORIZATION_SIGNER_ROLE = keccak256("AUTHORIZATION_SIGNER_ROLE");
    bytes32 public constant RECONCILER_ROLE = keccak256("RECONCILER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant PROVIDER_SECURITY_ROLE = keccak256("PROVIDER_SECURITY_ROLE");

    uint48 public constant DEFAULT_ADMIN_DELAY = 2 days;
    uint64 public constant MAX_FUTURE_OBSERVATION_SKEW = 5 minutes;

    bytes32 private constant AUTHORIZATION_TYPEHASH = keccak256(
        "Authorization(bytes32 receiptHash,bytes32 caid,bytes32 actionHash,bytes32 programHash,bytes32 inputHash,address payer,address executor,address merchant,address authorizationSigner,address providerSigner,uint256 maxAmount,uint64 expiresAt,uint64 providerConfigVersion,uint256 nonce)"
    );
    bytes32 private constant INVOCATION_TYPEHASH = keccak256(
        "Invocation(bytes32 operationId,bytes32 invocationHash,bytes32 providerRequestId,uint64 observedAt)"
    );
    bytes32 private constant OUTCOME_TYPEHASH = keccak256(
        "Outcome(bytes32 operationId,bytes32 invocationHash,bytes32 providerRequestId,bytes32 evidenceHash,bytes32 priorOutcomeDigest,uint256 amount,uint64 observedAt,uint8 kind)"
    );
    bytes32 private constant CERTIFICATE_TYPEHASH = keccak256(
        "TerminalCertificate(bytes32 operationId,bytes32 authorizationDigest,bytes32 caid,bytes32 actionHash,bytes32 programHash,bytes32 inputHash,bytes32 invocationHash,bytes32 providerRequestId,bytes32 invocationSignatureHash,bytes32 outcomeDigest,bytes32 evidenceHash,bytes32 resolutionSignatureHash,uint8 status,uint8 resolution,uint256 amount,address providerSigner,uint64 terminalAt)"
    );

    struct ProviderBinding {
        address signer;
        uint64 version;
    }

    mapping(bytes32 => Operation) private operations;
    mapping(bytes32 => bool) private operationExists;

    mapping(address => ProviderBinding) public providerBindings;
    mapping(address => bool) public providerSignerRevoked;
    mapping(bytes32 => bool) public receiptReplayConsumed;
    mapping(bytes32 => bool) public authorizationNonceConsumed;
    mapping(bytes32 => bool) public providerRequestConsumed;
    mapping(bytes32 => bool) public invocationReplayConsumed;
    mapping(bytes32 => bool) public providerEvidenceConsumed;
    mapping(address => uint256) public claimable;

    uint256 public totalLocked;
    uint256 public totalClaimable;
    bool public settlementsPaused;

    error ZeroAddress();
    error ZeroDigest(string field);
    error ZeroAmount();
    error ZeroNonce();
    error WrongPayer(address expected, address actual);
    error WrongExecutor(address expected, address actual);
    error ValueMismatch(uint256 expected, uint256 actual);
    error AuthorizationExpired(uint64 expiresAt, uint64 observedAt);
    error AuthorizationNotExpired(uint64 expiresAt, uint64 observedAt);
    error UnauthorizedAuthorizationSigner(address signer);
    error ProviderBindingMismatch(address merchant, address expectedSigner, uint64 expectedVersion);
    error ProviderSignerRevoked(address signer);
    error InvalidAuthorization();
    error InvalidProviderEvidence();
    error InvalidPartyAgreement();
    error InvalidObservationTime(uint64 minimum, uint64 observedAt);
    error ReceiptAlreadyConsumed(bytes32 replayKey);
    error AuthorizationNonceAlreadyConsumed(bytes32 replayKey);
    error ProviderRequestAlreadyConsumed(bytes32 replayKey);
    error InvocationAlreadyConsumed(bytes32 replayKey);
    error EvidenceAlreadyConsumed(bytes32 replayKey);
    error OperationAlreadyExists(bytes32 operationId);
    error OperationNotFound(bytes32 operationId);
    error InvalidState(Status expected, Status actual);
    error InvalidOutcomeKind(OutcomeKind kind);
    error InvalidOutcomeAmount(OutcomeKind kind, uint256 amount);
    error AmountExceedsAuthorization(uint256 authorized, uint256 reported);
    error OutcomeNotBoundToInvocation();
    error InvalidPriorOutcome(bytes32 expected, bytes32 actual);
    error SettlementsPaused();
    error NothingToWithdraw();
    error TransferFailed();

    event ProviderSignerSet(address indexed merchant, address indexed signer, uint64 indexed version);
    event ProviderSignerRevokedPermanently(address indexed signer);
    event SettlementPauseChanged(bool paused);

    constructor(address admin, address initialAuthorizationSigner)
        AccessControlDefaultAdminRules(DEFAULT_ADMIN_DELAY, admin)
        EIP712("EMILIA DTC Base Settlement", "2")
    {
        if (admin == address(0) || initialAuthorizationSigner == address(0)) revert ZeroAddress();
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(RECONCILER_ROLE, admin);
        _grantRole(PROVIDER_SECURITY_ROLE, admin);
        _grantRole(AUTHORIZATION_SIGNER_ROLE, initialAuthorizationSigner);
    }

    function setProviderSigner(address merchant, address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (merchant == address(0)) revert ZeroAddress();
        if (signer != address(0) && providerSignerRevoked[signer]) revert ProviderSignerRevoked(signer);
        uint64 version = providerBindings[merchant].version + 1;
        providerBindings[merchant] = ProviderBinding({signer: signer, version: version});
        emit ProviderSignerSet(merchant, signer, version);
    }

    function revokeProviderSigner(address signer) external onlyRole(PROVIDER_SECURITY_ROLE) {
        if (signer == address(0)) revert ZeroAddress();
        providerSignerRevoked[signer] = true;
        emit ProviderSignerRevokedPermanently(signer);
    }

    function pauseReservations() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpauseReservations() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function pauseSettlements() external onlyRole(PAUSER_ROLE) {
        settlementsPaused = true;
        emit SettlementPauseChanged(true);
    }

    function unpauseSettlements() external onlyRole(PAUSER_ROLE) {
        settlementsPaused = false;
        emit SettlementPauseChanged(false);
    }

    function reserve(Authorization calldata authorization, bytes calldata signature)
        external
        payable
        override
        whenNotPaused
        nonReentrant
        returns (bytes32 operationId)
    {
        _validateAuthorizationShape(authorization);
        if (msg.sender != authorization.payer) revert WrongPayer(authorization.payer, msg.sender);
        if (msg.value != authorization.maxAmount) revert ValueMismatch(authorization.maxAmount, msg.value);
        if (authorization.expiresAt <= block.timestamp) {
            revert AuthorizationExpired(authorization.expiresAt, uint64(block.timestamp));
        }
        if (!hasRole(AUTHORIZATION_SIGNER_ROLE, authorization.authorizationSigner)) {
            revert UnauthorizedAuthorizationSigner(authorization.authorizationSigner);
        }

        ProviderBinding memory binding = providerBindings[authorization.merchant];
        if (
            binding.signer != authorization.providerSigner
                || binding.version != authorization.providerConfigVersion
        ) {
            revert ProviderBindingMismatch(authorization.merchant, binding.signer, binding.version);
        }
        if (providerSignerRevoked[authorization.providerSigner]) {
            revert ProviderSignerRevoked(authorization.providerSigner);
        }

        bytes32 authorizationDigest = _hashTypedDataV4(_hashAuthorizationStruct(authorization));
        if (!SignatureChecker.isValidSignatureNow(authorization.authorizationSigner, authorizationDigest, signature)) {
            revert InvalidAuthorization();
        }

        bytes32 receiptKey = receiptReplayKey(
            authorization.authorizationSigner, authorization.payer, authorization.receiptHash
        );
        if (receiptReplayConsumed[receiptKey]) revert ReceiptAlreadyConsumed(receiptKey);
        bytes32 nonceKey = authorizationNonceKey(
            authorization.authorizationSigner, authorization.payer, authorization.nonce
        );
        if (authorizationNonceConsumed[nonceKey]) revert AuthorizationNonceAlreadyConsumed(nonceKey);

        operationId = authorizationDigest;
        if (operationExists[operationId]) revert OperationAlreadyExists(operationId);

        Operation storage operation = operations[operationId];
        operation.authorizationDigest = authorizationDigest;
        operation.receiptHash = authorization.receiptHash;
        operation.caid = authorization.caid;
        operation.actionHash = authorization.actionHash;
        operation.programHash = authorization.programHash;
        operation.inputHash = authorization.inputHash;
        operation.payer = authorization.payer;
        operation.executor = authorization.executor;
        operation.merchant = authorization.merchant;
        operation.authorizationSigner = authorization.authorizationSigner;
        operation.providerSigner = authorization.providerSigner;
        operation.maxAmount = authorization.maxAmount;
        operation.expiresAt = authorization.expiresAt;
        operation.providerConfigVersion = authorization.providerConfigVersion;
        operation.reservedAt = uint64(block.timestamp);
        operation.status = Status.RESERVED;

        operationExists[operationId] = true;
        receiptReplayConsumed[receiptKey] = true;
        authorizationNonceConsumed[nonceKey] = true;
        totalLocked += authorization.maxAmount;

        emit OperationReserved(
            operationId,
            authorization.receiptHash,
            authorization.caid,
            authorization.payer,
            authorization.executor,
            authorization.merchant,
            authorization.providerSigner,
            authorization.maxAmount
        );
    }

    function markInvoked(Invocation calldata invocation, bytes calldata providerSignature) external override {
        if (settlementsPaused) revert SettlementsPaused();
        Operation storage operation = _operation(invocation.operationId);
        _requireState(operation, Status.RESERVED);
        if (msg.sender != operation.executor) revert WrongExecutor(operation.executor, msg.sender);
        if (block.timestamp > operation.expiresAt) {
            revert AuthorizationExpired(operation.expiresAt, uint64(block.timestamp));
        }
        if (providerSignerRevoked[operation.providerSigner]) revert ProviderSignerRevoked(operation.providerSigner);
        if (invocation.invocationHash == bytes32(0)) revert ZeroDigest("invocationHash");
        if (invocation.providerRequestId == bytes32(0)) revert ZeroDigest("providerRequestId");
        _validateObservationTime(operation.reservedAt, invocation.observedAt);

        bytes32 digest = _hashTypedDataV4(_hashInvocationStruct(invocation));
        if (!SignatureChecker.isValidSignatureNow(operation.providerSigner, digest, providerSignature)) {
            revert InvalidProviderEvidence();
        }

        bytes32 requestKey = providerRequestReplayKey(operation.merchant, invocation.providerRequestId);
        if (providerRequestConsumed[requestKey]) revert ProviderRequestAlreadyConsumed(requestKey);
        bytes32 invocationKey = invocationReplayKey(operation.merchant, invocation.invocationHash);
        if (invocationReplayConsumed[invocationKey]) revert InvocationAlreadyConsumed(invocationKey);

        providerRequestConsumed[requestKey] = true;
        invocationReplayConsumed[invocationKey] = true;
        operation.invocationHash = invocation.invocationHash;
        operation.providerRequestId = invocation.providerRequestId;
        operation.invocationSignatureHash = keccak256(providerSignature);
        operation.invokedAt = invocation.observedAt;
        operation.status = Status.INVOKED;

        emit ProviderBoundaryEntered(
            invocation.operationId,
            invocation.invocationHash,
            invocation.providerRequestId,
            invocation.observedAt,
            operation.invocationSignatureHash
        );
    }

    function submitOutcome(Outcome calldata outcome, bytes calldata providerSignature)
        external
        override
        nonReentrant
    {
        if (settlementsPaused) revert SettlementsPaused();
        Operation storage operation = _operation(outcome.operationId);
        _requireState(operation, Status.INVOKED);
        if (outcome.priorOutcomeDigest != bytes32(0)) {
            revert InvalidPriorOutcome(bytes32(0), outcome.priorOutcomeDigest);
        }
        bytes32 outcomeDigest = _verifyProviderOutcome(operation, outcome, providerSignature);
        _consumeProviderEvidence(operation.merchant, outcome.evidenceHash);

        if (outcome.kind == OutcomeKind.INDETERMINATE) {
            if (outcome.amount != 0) revert InvalidOutcomeAmount(outcome.kind, outcome.amount);
            operation.outcomeDigest = outcomeDigest;
            operation.evidenceHash = outcome.evidenceHash;
            operation.outcomeObservedAt = outcome.observedAt;
            operation.resolutionSignatureHash = keccak256(providerSignature);
            operation.status = Status.INDETERMINATE;
            emit OutcomeRecorded(
                outcome.operationId,
                outcome.kind,
                outcome.evidenceHash,
                0,
                outcome.observedAt,
                operation.providerSigner,
                operation.resolutionSignatureHash
            );
            return;
        }

        _settleTerminal(
            operation,
            outcome,
            outcomeDigest,
            Resolution.PROVIDER_EVIDENCE,
            keccak256(providerSignature),
            operation.providerSigner
        );
    }

    function reconcile(Outcome calldata outcome, bytes calldata providerSignature)
        external
        override
        onlyRole(RECONCILER_ROLE)
        nonReentrant
    {
        if (settlementsPaused) revert SettlementsPaused();
        Operation storage operation = _operation(outcome.operationId);
        _requireState(operation, Status.INDETERMINATE);
        _requireTerminalKind(outcome.kind);
        _requireReconciliationChain(operation, outcome);
        bytes32 outcomeDigest = _verifyProviderOutcome(operation, outcome, providerSignature);
        _consumeProviderEvidence(operation.merchant, outcome.evidenceHash);
        _settleTerminal(
            operation,
            outcome,
            outcomeDigest,
            Resolution.RECONCILED_PROVIDER_EVIDENCE,
            keccak256(providerSignature),
            operation.providerSigner
        );
    }

    function settleByAgreement(
        Outcome calldata outcome,
        bytes calldata payerSignature,
        bytes calldata merchantSignature
    ) external override nonReentrant {
        Operation storage operation = _operation(outcome.operationId);
        if (operation.status != Status.INVOKED && operation.status != Status.INDETERMINATE) {
            revert InvalidState(Status.INVOKED, operation.status);
        }
        _requireTerminalKind(outcome.kind);
        if (operation.status == Status.INDETERMINATE) {
            _requireReconciliationChain(operation, outcome);
        } else if (outcome.priorOutcomeDigest != bytes32(0)) {
            revert InvalidPriorOutcome(bytes32(0), outcome.priorOutcomeDigest);
        }
        _validateOutcomeBinding(operation, outcome);
        bytes32 outcomeDigest = _hashTypedDataV4(_hashOutcomeStruct(outcome));
        if (
            !SignatureChecker.isValidSignatureNow(operation.payer, outcomeDigest, payerSignature)
                || !SignatureChecker.isValidSignatureNow(operation.merchant, outcomeDigest, merchantSignature)
        ) revert InvalidPartyAgreement();

        bytes32 signaturesHash = keccak256(abi.encode(keccak256(payerSignature), keccak256(merchantSignature)));
        _settleTerminal(
            operation,
            outcome,
            outcomeDigest,
            Resolution.PARTY_AGREEMENT,
            signaturesHash,
            address(0)
        );
    }

    function cancelExpired(bytes32 operationId) external override nonReentrant {
        Operation storage operation = _operation(operationId);
        _requireState(operation, Status.RESERVED);
        if (block.timestamp <= operation.expiresAt) {
            revert AuthorizationNotExpired(operation.expiresAt, uint64(block.timestamp));
        }
        _cancelReserved(operationId, operation, Resolution.EXPIRY_CANCELLATION);
    }

    function cancelBeforeInvocation(bytes32 operationId) external override nonReentrant {
        Operation storage operation = _operation(operationId);
        _requireState(operation, Status.RESERVED);
        if (msg.sender != operation.payer) revert WrongPayer(operation.payer, msg.sender);
        _cancelReserved(operationId, operation, Resolution.PAYER_PRE_EFFECT_CANCELLATION);
    }

    function _cancelReserved(bytes32 operationId, Operation storage operation, Resolution resolution) private {
        operation.status = Status.CANCELLED;
        operation.resolution = resolution;
        operation.terminalAt = uint64(block.timestamp);
        _unlockTo(operation.payer, operation.maxAmount);
        operation.certificateHash = _certificateHash(operationId, operation);

        emit TerminalCertificateCreated(
            operationId,
            operation.certificateHash,
            Status.CANCELLED,
            resolution
        );
    }

    function withdraw() external override nonReentrant {
        _withdrawTo(payable(msg.sender));
    }

    function withdrawTo(address payable recipient) external override nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        _withdrawTo(recipient);
    }

    function hashAuthorization(Authorization calldata authorization) external view override returns (bytes32) {
        return _hashTypedDataV4(_hashAuthorizationStruct(authorization));
    }

    function hashInvocation(Invocation calldata invocation) external view override returns (bytes32) {
        return _hashTypedDataV4(_hashInvocationStruct(invocation));
    }

    function hashOutcome(Outcome calldata outcome) external view override returns (bytes32) {
        return _hashTypedDataV4(_hashOutcomeStruct(outcome));
    }

    function getOperation(bytes32 operationId) external view override returns (Operation memory) {
        if (!operationExists[operationId]) revert OperationNotFound(operationId);
        return operations[operationId];
    }

    function accountedBalance() public view returns (uint256) {
        return totalLocked + totalClaimable;
    }

    function receiptReplayKey(address authorizationSigner, address payer, bytes32 receiptHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(authorizationSigner, payer, receiptHash));
    }

    function authorizationNonceKey(address authorizationSigner, address payer, uint256 nonce)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(authorizationSigner, payer, nonce));
    }

    function providerRequestReplayKey(address merchant, bytes32 providerRequestId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(merchant, providerRequestId));
    }

    function invocationReplayKey(address merchant, bytes32 invocationHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(merchant, invocationHash));
    }

    function providerEvidenceReplayKey(address merchant, bytes32 evidenceHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(merchant, evidenceHash));
    }

    function _settleTerminal(
        Operation storage operation,
        Outcome calldata outcome,
        bytes32 outcomeDigest,
        Resolution resolution,
        bytes32 signaturesHash,
        address evidenceSigner
    ) private {
        if (outcome.kind == OutcomeKind.SUCCEEDED) {
            if (outcome.amount == 0) revert InvalidOutcomeAmount(outcome.kind, outcome.amount);
            if (outcome.amount > operation.maxAmount) {
                revert AmountExceedsAuthorization(operation.maxAmount, outcome.amount);
            }
            operation.status = Status.SUCCEEDED;
            operation.settledAmount = outcome.amount;
            claimable[operation.merchant] += outcome.amount;
            claimable[operation.payer] += operation.maxAmount - outcome.amount;
        } else if (outcome.kind == OutcomeKind.FAILED) {
            if (outcome.amount != 0) revert InvalidOutcomeAmount(outcome.kind, outcome.amount);
            operation.status = Status.FAILED;
            claimable[operation.payer] += operation.maxAmount;
        } else {
            revert InvalidOutcomeKind(outcome.kind);
        }

        operation.outcomeDigest = outcomeDigest;
        operation.evidenceHash = outcome.evidenceHash;
        operation.outcomeObservedAt = outcome.observedAt;
        operation.resolution = resolution;
        operation.resolutionSignatureHash = signaturesHash;
        operation.terminalAt = uint64(block.timestamp);
        totalLocked -= operation.maxAmount;
        totalClaimable += operation.maxAmount;
        operation.certificateHash = _certificateHash(outcome.operationId, operation);

        emit OutcomeRecorded(
            outcome.operationId,
            outcome.kind,
            outcome.evidenceHash,
            outcome.amount,
            outcome.observedAt,
            evidenceSigner,
            signaturesHash
        );
        emit TerminalCertificateCreated(
            outcome.operationId,
            operation.certificateHash,
            operation.status,
            resolution
        );
    }

    function _unlockTo(address account, uint256 amount) private {
        totalLocked -= amount;
        totalClaimable += amount;
        claimable[account] += amount;
    }

    function _withdrawTo(address payable recipient) private {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        claimable[msg.sender] = 0;
        totalClaimable -= amount;
        (bool sent,) = recipient.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit Withdrawal(msg.sender, recipient, amount);
    }

    function _verifyProviderOutcome(
        Operation storage operation,
        Outcome calldata outcome,
        bytes calldata signature
    ) private view returns (bytes32 outcomeDigest) {
        if (providerSignerRevoked[operation.providerSigner]) revert ProviderSignerRevoked(operation.providerSigner);
        _validateOutcomeBinding(operation, outcome);
        outcomeDigest = _hashTypedDataV4(_hashOutcomeStruct(outcome));
        if (!SignatureChecker.isValidSignatureNow(operation.providerSigner, outcomeDigest, signature)) {
            revert InvalidProviderEvidence();
        }
    }

    function _validateOutcomeBinding(Operation storage operation, Outcome calldata outcome) private view {
        if (outcome.kind == OutcomeKind.NONE) revert InvalidOutcomeKind(outcome.kind);
        if (outcome.evidenceHash == bytes32(0)) revert ZeroDigest("evidenceHash");
        if (
            outcome.invocationHash != operation.invocationHash
                || outcome.providerRequestId != operation.providerRequestId
        ) revert OutcomeNotBoundToInvocation();
        _validateObservationTime(operation.invokedAt, outcome.observedAt);
    }

    function _requireReconciliationChain(Operation storage operation, Outcome calldata outcome) private view {
        if (outcome.priorOutcomeDigest != operation.outcomeDigest) {
            revert InvalidPriorOutcome(operation.outcomeDigest, outcome.priorOutcomeDigest);
        }
        if (outcome.observedAt <= operation.outcomeObservedAt) {
            revert InvalidObservationTime(operation.outcomeObservedAt + 1, outcome.observedAt);
        }
    }

    function _consumeProviderEvidence(address merchant, bytes32 evidenceHash) private {
        bytes32 evidenceKey = providerEvidenceReplayKey(merchant, evidenceHash);
        if (providerEvidenceConsumed[evidenceKey]) revert EvidenceAlreadyConsumed(evidenceKey);
        providerEvidenceConsumed[evidenceKey] = true;
    }

    function _validateObservationTime(uint64 minimum, uint64 observedAt) private view {
        if (observedAt < minimum || observedAt > block.timestamp + MAX_FUTURE_OBSERVATION_SKEW) {
            revert InvalidObservationTime(minimum, observedAt);
        }
    }

    function _requireTerminalKind(OutcomeKind kind) private pure {
        if (kind != OutcomeKind.SUCCEEDED && kind != OutcomeKind.FAILED) revert InvalidOutcomeKind(kind);
    }

    function _hashAuthorizationStruct(Authorization calldata authorization) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                AUTHORIZATION_TYPEHASH,
                authorization.receiptHash,
                authorization.caid,
                authorization.actionHash,
                authorization.programHash,
                authorization.inputHash,
                authorization.payer,
                authorization.executor,
                authorization.merchant,
                authorization.authorizationSigner,
                authorization.providerSigner,
                authorization.maxAmount,
                authorization.expiresAt,
                authorization.providerConfigVersion,
                authorization.nonce
            )
        );
    }

    function _hashInvocationStruct(Invocation calldata invocation) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                INVOCATION_TYPEHASH,
                invocation.operationId,
                invocation.invocationHash,
                invocation.providerRequestId,
                invocation.observedAt
            )
        );
    }

    function _hashOutcomeStruct(Outcome calldata outcome) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                OUTCOME_TYPEHASH,
                outcome.operationId,
                outcome.invocationHash,
                outcome.providerRequestId,
                outcome.evidenceHash,
                outcome.priorOutcomeDigest,
                outcome.amount,
                outcome.observedAt,
                outcome.kind
            )
        );
    }

    function _certificateHash(bytes32 operationId, Operation storage operation) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                CERTIFICATE_TYPEHASH,
                operationId,
                operation.authorizationDigest,
                operation.caid,
                operation.actionHash,
                operation.programHash,
                operation.inputHash,
                operation.invocationHash,
                operation.providerRequestId,
                operation.invocationSignatureHash,
                operation.outcomeDigest,
                operation.evidenceHash,
                operation.resolutionSignatureHash,
                operation.status,
                operation.resolution,
                operation.settledAmount,
                operation.providerSigner,
                operation.terminalAt
            )
        );
    }

    function _validateAuthorizationShape(Authorization calldata authorization) private pure {
        if (
            authorization.payer == address(0) || authorization.executor == address(0)
                || authorization.merchant == address(0) || authorization.authorizationSigner == address(0)
                || authorization.providerSigner == address(0)
        ) revert ZeroAddress();
        if (authorization.receiptHash == bytes32(0)) revert ZeroDigest("receiptHash");
        if (authorization.caid == bytes32(0)) revert ZeroDigest("caid");
        if (authorization.actionHash == bytes32(0)) revert ZeroDigest("actionHash");
        if (authorization.programHash == bytes32(0)) revert ZeroDigest("programHash");
        if (authorization.inputHash == bytes32(0)) revert ZeroDigest("inputHash");
        if (authorization.maxAmount == 0) revert ZeroAmount();
        if (authorization.nonce == 0) revert ZeroNonce();
    }

    function _operation(bytes32 operationId) private view returns (Operation storage operation) {
        if (!operationExists[operationId]) revert OperationNotFound(operationId);
        operation = operations[operationId];
    }

    function _requireState(Operation storage operation, Status expected) private view {
        if (operation.status != expected) revert InvalidState(expected, operation.status);
    }
}
