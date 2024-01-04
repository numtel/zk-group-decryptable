import assert from "node:assert";
import Identity from "../src/Identity.js";

describe("Identity", () => {
  const privateKey = "secret";

  describe("# Identity", () => {
    it("Should create a random identity", () => {
      const identity = new Identity();
      assert.ok(Buffer.isBuffer(identity.privateKey));
      assert.strictEqual(typeof identity.secretScalar, "string");
      assert.strictEqual(identity.publicKey.length, 2);
      assert.strictEqual(typeof identity.commitment, "string");
    });

    it("Should create deterministic identities from a secret (private key)", () => {
      const identity = new Identity(privateKey);
      assert.strictEqual(typeof identity.privateKey, "string");
      assert.strictEqual(typeof identity.secretScalar, "string");
      assert.strictEqual(identity.publicKey.length, 2)
      assert.strictEqual(typeof identity.commitment, "string");
    });
  });

  describe("# signMessage", () => {
    it("Should sign a message", () => {
      const identity = new Identity(privateKey);
      const signature = identity.signMessage("message");
      assert.strictEqual(signature.R8.length, 2);
      assert.strictEqual(typeof signature.R8[0], "string");
      assert.strictEqual(typeof signature.S, "string");
    });
  });

  describe("# verifySignature", () => {
    it("Should verify a signature", () => {
      const identity = new Identity(privateKey);
      const signature = identity.signMessage("message");
      assert.ok(identity.verifySignature("message", signature));
    });

    it("Should verify an external signature", () => {
      const identity = new Identity(privateKey);
      const signature = identity.signMessage("message");
      assert.ok(Identity.verifySignature("message", signature, identity.publicKey));
    });

    it("Should verify an external signature with an unpacked public key", () => {
      const identity = new Identity(privateKey);
      const signature = identity.signMessage("message");

      assert.ok(Identity.verifySignature("message", signature, identity.publicKey));
    });
  });
});

