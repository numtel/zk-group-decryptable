//SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import "../contracts/ISemaphoreVerifier.sol";

contract MockVerifier is ISemaphoreVerifier {
  function verifyProof(
    uint[2] calldata _pA,
    uint[2][2] calldata, //_pB,
    uint[2] calldata, //_pC,
    uint[10] calldata //_pubSignals
  ) external override pure returns (bool) {
   return _pA[0] == 123456789;
  }
}
