// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockERC1271Signer is IERC1271 {
    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 digest, bytes memory signature) external view returns (bytes4) {
        return ECDSA.recover(digest, signature) == owner ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }
}
