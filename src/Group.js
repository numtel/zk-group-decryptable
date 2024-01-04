import { LeanIMT } from "@zk-kit/imt";
import { poseidon2 } from "poseidon-lite";

export default class Group {
  constructor(members = []) {
    this.leanIMT = new LeanIMT((a, b) => poseidon2([a, b]), members.map(BigInt));
  }

  get root() {
    return this.leanIMT.root?.toString();
  }

  get depth() {
    return this.leanIMT.depth;
  }

  get size() {
    return this.leanIMT.size;
  }

  get members() {
    return this.leanIMT.leaves.map(String);
  }

  indexOf(member) {
    return this.leanIMT.indexOf(BigInt(member));
  }

  addMember(member) {
    this.leanIMT.insert(BigInt(member));
  }

  addMembers(members) {
    this.leanIMT.insertMany(members.map(BigInt));
  }

  updateMember(index, member) {
    this.leanIMT.update(index, BigInt(member));
  }

  removeMember(index) {
    this.leanIMT.update(index, BigInt(0));
  }

  generateMerkleProof(_index) {
    const { index, leaf, root, siblings } = this.leanIMT.generateProof(_index);

    return {
      index,
      leaf: leaf.toString(),
      root: root.toString(),
      siblings: siblings.map(String)
    };
  }
}
