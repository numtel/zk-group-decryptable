import assert from "node:assert";
import Group from "../src/Group.js";

describe("Group", () => {
  describe("# Group", () => {
    it("Should create a group", () => {
      const group = new Group();

      assert.strictEqual(group.root, undefined);
      assert.strictEqual(group.depth, 0);
      assert.strictEqual(group.size, 0);
    });

    it("Should create a group with a list of members", () => {
      const group = new Group([1, 2, 3]);
      const group2 = new Group();

      group2.addMember(1);
      group2.addMember(2);
      group2.addMember(3);

      assert.strictEqual(group.root, group2.root);
      assert.strictEqual(group.depth, 2);
      assert.strictEqual(group.size, 3);
    });
  });

  describe("# addMember", () => {
    it("Should add a member to a group", () => {
      const group = new Group();

      group.addMember(3);

      assert.strictEqual(group.size, 1);
    });
  });

  describe("# addMembers", () => {
    it("Should add many members to a group", () => {
      const group = new Group();

      group.addMembers([1, 3]);

      assert.strictEqual(group.size, 2);
    });
  });

  describe("# indexOf", () => {
    it("Should return the index of a member in a group", () => {
      const group = new Group();
      group.addMembers([1, 3]);

      const index = group.indexOf(3);

      assert.strictEqual(index, 1);
    });
  });

  describe("# updateMember", () => {
    it("Should update a member in a group", () => {
      const group = new Group();
      group.addMembers([1, 3]);

      group.updateMember(0, 1);

      assert.strictEqual(group.size, 2);
      assert.strictEqual(group.members[0], "1");
    });
  });

  describe("# removeMember", () => {
    it("Should remove a member from a group", () => {
      const group = new Group();
      group.addMembers([1, 3]);

      group.removeMember(0);

      assert.strictEqual(group.size, 2);
      assert.strictEqual(group.members[0], "0");
    });
  });

  describe("# generateMerkleProof", () => {
    it("Should generate a proof of membership", () => {
      const group = new Group();

      group.addMembers([1, 3]);

      const proof = group.generateMerkleProof(0);

      assert.strictEqual(proof.leaf, "1");
    });
  });
});
