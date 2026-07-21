// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

interface IWithdrawableSettlement {
    function withdraw() external;
    function withdrawTo(address payable recipient) external;
}

contract ReentrantWithdrawer {
    IWithdrawableSettlement public immutable settlement;
    bool public reentrySucceeded;
    uint256 public received;

    constructor(address settlement_) {
        settlement = IWithdrawableSettlement(settlement_);
    }

    function attackWithdraw() external {
        settlement.withdraw();
    }

    function redirectWithdraw(address payable recipient) external {
        settlement.withdrawTo(recipient);
    }

    receive() external payable {
        received += msg.value;
        (reentrySucceeded,) = address(settlement).call(abi.encodeCall(IWithdrawableSettlement.withdraw, ()));
    }
}
