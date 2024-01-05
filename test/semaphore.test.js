import assert from "node:assert";
import { readFileSync } from "node:fs";
import path from "node:path";
import { derivePublicKey, deriveSecretScalar } from "@zk-kit/eddsa-poseidon";
import { LeanIMT } from "@zk-kit/imt";
import { poseidon2 } from "poseidon-lite";
import { Circomkit, WitnessTester } from "circomkit";

import { genKeypair, encode, encrypt, decrypt } from "../src/elGamal.js";
import { decode } from "../src/decode.js";

const config = JSON.parse(readFileSync("circomkit.json", "utf-8"));
const circomkit = new Circomkit({...config, verbose: false});

describe("semaphore", () => {
    let circuit;
    const MAX_DEPTH = 20;

    const scope = 32;
    const message = 43;

    const privateKey = 1;
    const publicKey = derivePublicKey(privateKey);

    const leaf = poseidon2(publicKey);

    const tree = new LeanIMT((a, b) => poseidon2([a, b]));

    tree.insert(leaf);

    for (let i = 1; i < 4; i += 1) {
        tree.insert(BigInt(i));
    }

    const { siblings: treeSiblings, index } = tree.generateProof(0);

    // The index must be converted to a list of indices, 1 for each tree level.
    // The circuit tree depth is 20, so the number of siblings must be 20, even if
    // the tree depth is actually 3. The missing siblings can be set to 0, as they
    // won't be used to calculate the root in the circuit.
    const treeIndices = [];

    for (let i = 0; i < MAX_DEPTH; i += 1) {
        treeIndices.push((index >> i) & 1);

        if (treeSiblings[i] === undefined) {
            treeSiblings[i] = BigInt(0);
        }
    }

    // Encrypted value can only be 32 bits
    const identityCommitment = leaf & 0xFFFFFFFFn;
    const ecKeypair = genKeypair();
    const encodedMsg = encode(identityCommitment);
    const encryption = encrypt(ecKeypair.pubKey, encodedMsg);
    const decrypted_message = decrypt(
        ecKeypair.privKey,
        encryption.ephemeral_key,
        encryption.encrypted_message,
    );
    const decodedMsg = decode(decrypted_message, 19);
    assert.strictEqual(identityCommitment, decodedMsg);

    const INPUT = {
        privateKey: deriveSecretScalar(privateKey),
        treeDepth: tree.depth,
        treeIndices,
        treeSiblings,
        scope,
        message,
        nonceKey: encryption.nonce,
        publicKey: [
          ecKeypair.pubKey.x,
          ecKeypair.pubKey.y
        ],
    };

    const OUTPUT = {
        nullifier: poseidon2([scope, deriveSecretScalar(privateKey)]),
        treeRoot: tree.root,
        ephemeralKey: [
          encryption.ephemeral_key.x,
          encryption.ephemeral_key.y,
        ],
        encryptedMessage: [
          encryption.encrypted_message.x,
          encryption.encrypted_message.y,
        ],
    };

    before(async () => {
        circuit = await circomkit.WitnessTester("semaphore", {
            file: "circuits/semaphore",
            template: "Semaphore",
            params: [MAX_DEPTH]
        });
    });

    it("Should calculate the root and the nullifier correctly", async () => {
        await circuit.expectPass(INPUT, OUTPUT)
    });
})
