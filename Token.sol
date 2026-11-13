// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: reentrancy - balance updated AFTER external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;  // too late!
    }

    // VULNERABILITY: anyone can call this, no access control
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    // VULNERABILITY: selfdestruct with no auth
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}
// Trigger re-scan
