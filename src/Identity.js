import { randomBytes } from "node:crypto";
import {
  derivePublicKey,
  deriveSecretScalar,
  signMessage,
  verifySignature
} from "@zk-kit/eddsa-poseidon";
import { poseidon2 } from "poseidon-lite";

export default class Identity {
  constructor(privateKey = randomBytes(32)) {
    this.privateKey = privateKey
    this.secretScalar = deriveSecretScalar(privateKey)
    this.publicKey = derivePublicKey(privateKey)
    this.commitment = poseidon2(this.publicKey).toString()
  }

  signMessage(message) {
    return signMessage(this.privateKey, message)
  }

  verifySignature(message, signature) {
    return verifySignature(message, signature, this.publicKey)
  }

  static verifySignature(message, signature, publicKey) {
    return verifySignature(message, signature, publicKey)
  }
}
