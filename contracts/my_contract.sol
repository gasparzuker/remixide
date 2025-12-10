// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SendEther {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function getBalance() external view returns(uint) {
        return address(this).balance;
    }

    receive() external payable { }

    function sendEth(address payable _to, uint256 _amount) external payable onlyOwner {
        bool sent = _to.send(_amount);
        require(sent, "Send failed");
    }

    // Remix ASSISTANT recommended me to add this in order to add security to the contract
        modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}