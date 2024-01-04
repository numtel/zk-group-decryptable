// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import {Test, console2} from "forge-std/Test.sol";
import {Semaphore} from "../contracts/Semaphore.sol";
import {ISemaphore} from "../contracts/ISemaphore.sol";
import {ISemaphoreGroups} from "../contracts/ISemaphoreGroups.sol";
import {MockVerifier} from "./MockVerifier.sol";

contract SemaphoreTest is Test {
  Semaphore public semaphore;

  // TODO Why can't these be imported?
  error Semaphore__GroupDoesNotExist();
  error Semaphore__CallerIsNotTheGroupAdmin();
  error Semaphore__MerkleTreeRootIsNotPartOfTheGroup();
  error Semaphore__InvalidProof();
  error Semaphore__YouAreUsingTheSameNillifierTwice();
  error Semaphore__MerkleTreeRootIsExpired();
  event GroupCreated(uint256 indexed groupId);
  event GroupAdminUpdated(uint256 indexed groupId, address indexed oldAdmin, address indexed newAdmin);
  event GroupMerkleTreeDurationUpdated(
      uint256 indexed groupId,
      uint256 oldMerkleTreeDuration,
      uint256 newMerkleTreeDuration
  );
  event MemberAdded(uint256 indexed groupId, uint256 leafIndex, uint256 identityCommitment, uint256 merkleTreeRoot);
  event MemberUpdated(
    uint256 indexed groupId,
    uint256 leafIndex,
    uint256 identityCommitment,
    uint256 newIdentityCommitment,
    uint256 merkleTreeRoot
  );
  event MemberRemoved(uint256 indexed groupId, uint256 leafIndex, uint256 identityCommitment, uint256 merkleTreeRoot);
  event ProofVerified(
    uint256 indexed groupId,
    uint256 indexed merkleTreeRoot,
    uint256 nullifier,
    uint256 message,
    uint256 indexed scope,
    uint256[6] decryptables,
    uint256[8] proof
  );

  function setUp() public {
  MockVerifier verifier = new MockVerifier();
    semaphore = new Semaphore(verifier);
  }

  function test_createGroupDefaultExpiration() public {
    uint groupId = 1;
    vm.expectEmit();
    emit GroupCreated(groupId);
    emit GroupAdminUpdated(groupId, address(0), address(this));
    semaphore.createGroup(groupId, address(this));

    vm.prank(address(1));
    vm.expectRevert(Semaphore__CallerIsNotTheGroupAdmin.selector);
    semaphore.updateGroupMerkleTreeDuration(groupId, 300);

    vm.expectEmit();
    emit GroupMerkleTreeDurationUpdated(groupId, 3600, 300);
    semaphore.updateGroupMerkleTreeDuration(groupId, 300);

    vm.prank(address(1));
    vm.expectRevert(Semaphore__CallerIsNotTheGroupAdmin.selector);
    semaphore.updateGroupAdmin(groupId, address(1));

    vm.expectEmit();
    emit GroupAdminUpdated(groupId, address(this), address(1));
    semaphore.updateGroupAdmin(groupId, address(1));

    // Change it back
    vm.prank(address(1));
    semaphore.updateGroupAdmin(groupId, address(this));

    vm.prank(address(1));
    vm.expectRevert(Semaphore__CallerIsNotTheGroupAdmin.selector);
    semaphore.addMember(groupId, 1);

    vm.expectEmit();
    emit MemberAdded(groupId, 0, 1, 1);
    semaphore.addMember(groupId, 1);

    uint[] memory newMembers = new uint[](2);
    newMembers[0] = 2;
    newMembers[1] = 3;
    vm.prank(address(1));
    vm.expectRevert(Semaphore__CallerIsNotTheGroupAdmin.selector);
    semaphore.addMembers(groupId, newMembers);

    vm.expectEmit();
    emit MemberAdded(groupId, 1, 2,
      7853200120776062878684798364095072458815029376092732009249414926327459813530);
    emit MemberAdded(groupId, 2, 3,
      13816780880028945690020260331303642730075999758909899334839547418969502592169);
    semaphore.addMembers(groupId, newMembers);

    vm.prank(address(1));
    vm.expectRevert(Semaphore__CallerIsNotTheGroupAdmin.selector);
    semaphore.updateMember(groupId, 1, 4, newMembers);

    vm.expectEmit();
    emit MemberUpdated(groupId, 0, 1, 4,
      13770529461509016961767643725607007323747608717565390872392152293944827377484);
    semaphore.updateMember(groupId, 1, 4, newMembers);

    uint[6] memory decryptables;
    uint[8] memory proof;

    vm.expectRevert(Semaphore__GroupDoesNotExist.selector);
    semaphore.verifyProof(groupId + 1, 1, 0, 0, 0, decryptables, proof);

    vm.expectRevert(Semaphore__MerkleTreeRootIsNotPartOfTheGroup.selector);
    semaphore.verifyProof(groupId, 69, 0, 0, 0, decryptables, proof);

    vm.expectRevert(Semaphore__InvalidProof.selector);
    semaphore.verifyProof(groupId, 1, 0, 0, 0, decryptables, proof);

    // Special mock value to pass proof verification
    proof[0] = 123456789;
    vm.expectEmit();
    emit ProofVerified(groupId, 1, 0, 0, 0, decryptables, proof);
    semaphore.verifyProof(groupId, 1, 0, 0, 0, decryptables, proof);

    vm.expectRevert(Semaphore__YouAreUsingTheSameNillifierTwice.selector);
    semaphore.verifyProof(groupId, 1, 0, 0, 0, decryptables, proof);

    vm.warp(10000); // Must be > 300
    vm.expectRevert(Semaphore__MerkleTreeRootIsExpired.selector);
    semaphore.verifyProof(
      groupId,
      13816780880028945690020260331303642730075999758909899334839547418969502592169,
      1, 1, 1, decryptables, proof);

  }

  function test_removeMember() public {
    uint groupId = 1;
    semaphore.createGroup(groupId, address(this));
    uint[] memory newMembers = new uint[](3);
    newMembers[0] = 1;
    newMembers[1] = 2;
    newMembers[2] = 3;
    semaphore.addMembers(groupId, newMembers);

    uint[] memory siblings = new uint[](1);
    siblings[0] = 7853200120776062878684798364095072458815029376092732009249414926327459813530;
    vm.prank(address(1));
    vm.expectRevert(Semaphore__CallerIsNotTheGroupAdmin.selector);
    semaphore.removeMember(groupId, 3, siblings);

    vm.expectEmit();
    emit MemberRemoved(groupId, 2, 3,
      6523545945079737711123707703987669864906825769893131535256183694760671086364);
    semaphore.removeMember(groupId, 3, siblings);
  }

  function test_createGroupCustomExpiration() public {
    uint groupId = 2;
    vm.expectEmit();
    emit GroupCreated(groupId);
    emit GroupAdminUpdated(groupId, address(0), address(this));
    semaphore.createGroup(groupId, address(this), 5);
  }
}
