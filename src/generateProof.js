import { BigNumber } from "@ethersproject/bignumber";
import { zeroPad } from "@ethersproject/bytes";
import { keccak256 } from "@ethersproject/keccak256"
import { prove } from "@zk-kit/groth16"
import { encrypt, encode } from "./elGamal.js";
import Group from "./Group.js";
import Identity from "./Identity.js";

export default async function generateProof(identity, group, message, scope, publicKey, treeDepth, snarkArtifacts) {
  const leafIndex = group.indexOf(identity.commitment);
  const merkeProof = group.generateMerkleProof(leafIndex);
  const merkleProofLength = merkeProof.siblings.length;

  treeDepth = treeDepth || merkleProofLength;

  snarkArtifacts = snarkArtifacts || {
    wasmFilePath: `https://config.clonk.me/semaphore-decryptable-dev/${treeDepth}/semaphore.wasm`,
    zkeyFilePath: `https://config.clonk.me/semaphore-decryptable-dev/${treeDepth}/semaphore.zkey`,
  };

  // The index must be converted to a list of indices, 1 for each tree level.
  // The missing siblings can be set to 0, as they won't be used in the circuit.
  const treeIndices = []
  const treeSiblings = merkeProof.siblings

  for (let i = 0; i < treeDepth; i += 1) {
      treeIndices.push((merkeProof.index >> i) & 1)

      if (treeSiblings[i] === undefined) {
          treeSiblings[i] = "0"
      }
  }

  // Encrypted value can only be 32 bits
  const identityCommitment = BigInt(identity.commitment) & 0xFFFFFFFFn;
  const encodedMsg = encode(identityCommitment);
  const encryption = encrypt(publicKey, encodedMsg);

  const { proof, publicSignals } = await prove(
    {
      privateKey: identity.secretScalar,
      treeDepth: merkleProofLength,
      treeIndices,
      treeSiblings,
      scope: hash(scope),
      message: hash(message),
      nonceKey: encryption.nonce,
      publicKey: [publicKey.x, publicKey.y],
    },
    snarkArtifacts.wasmFilePath,
    snarkArtifacts.zkeyFilePath
  )

  return {
    treeRoot: publicSignals[0],
    nullifier: publicSignals[1],
    message: String(message),
    scope: String(scope),
    decryptables: [
      publicSignals[2],
      publicSignals[3],
      publicSignals[4],
      publicSignals[5],
      publicKey.x.toString(),
      publicKey.y.toString(),
    ],
    proof: [
      proof.pi_a[0],
      proof.pi_a[1],
      proof.pi_b[0][1],
      proof.pi_b[0][0],
      proof.pi_b[1][1],
      proof.pi_b[1][0],
      proof.pi_c[0],
      proof.pi_c[1]
    ]
  }
}

function hash(message) {
  message = BigNumber.from(message).toTwos(256).toHexString();
  message = zeroPad(message, 32);

  return (BigInt(keccak256(message)) >> BigInt(8)).toString();
}
