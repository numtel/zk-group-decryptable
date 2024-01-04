// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Script, console2} from "forge-std/Script.sol";

import "../build/semaphore/groth16_verifier.sol";
import "../contracts/Semaphore.sol";

contract Deploy is Script {
  function run() public {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    vm.startBroadcast(deployerPrivateKey);

    Groth16Verifier verifier = new Groth16Verifier();
    new Semaphore(ISemaphoreVerifier(address(verifier)));
  }
}
