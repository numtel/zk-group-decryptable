import assert from "node:assert";

import { decode, split64 } from "../src/decode.js";
import { 
  babyJub,
  genRandomPoint,
  genKeypair,
  genRandomBabyJubValue,
  encode,
  encrypt,
  encrypt_s,
  decrypt,
  rerandomize,
} from "../src/elGamal.js";

const b32 = 4294967296n;

describe("Testing ElGamal Scheme on EC points directly", () => {
  it("Check compliance of orignal and decrypted message as points", () => {
    const keypair = genKeypair();
    const encryption = encrypt(keypair.pubKey);
    const decrypted_message = decrypt(
      keypair.privKey,
      encryption.ephemeral_key,
      encryption.encrypted_message,
    );
    assert.deepStrictEqual(encryption.message.toAffine(), decrypted_message.toAffine());
  });

  it("Check unhappy compliance of orignal and decrypted message as points", () => {
    const keypair = genKeypair();
    let encryption = encrypt(keypair.pubKey);
    // we just need to modify any of the inputs
    const { randomized_ephemeralKey } = rerandomize(
      keypair.pubKey,
      encryption.ephemeral_key,
      encryption.encrypted_message,
    );
    const decrypted_message = decrypt(
      keypair.privKey,
      randomized_ephemeralKey,
      encryption.encrypted_message,
    );

    assert.notDeepStrictEqual(encryption.message.toAffine(), decrypted_message.toAffine());
  });

  it("Check LOOPED compliance of orignal and decrypted message as points", () => {
    for (let i = 0; i < 100; i++) {
      let keypair = genKeypair();
      let encryption = encrypt(keypair.pubKey);
      let decrypted_message = decrypt(
        keypair.privKey,
        encryption.ephemeral_key,
        encryption.encrypted_message,
      );

      assert.deepStrictEqual(encryption.message.toAffine(), decrypted_message.toAffine());
    }
  });

  it("Check homomorphic properties of the Elgamal Scheme", () => {
    const keypair = genKeypair();

    const encryption1 = encrypt(keypair.pubKey);
    const encryption2 = encrypt(keypair.pubKey);

    // We want to prove that message3 is equal to decrypted(encryptedMessage3)
    const message3 = encryption1.message.add(encryption2.message);
    const encrypted_message3 = encryption1.encrypted_message.add(encryption2.encrypted_message);
    const ephemeral_key3 = encryption1.ephemeral_key.add(encryption2.ephemeral_key);

    const decrypted_message3 = decrypt(keypair.privKey, ephemeral_key3, encrypted_message3);

    assert.deepStrictEqual(decrypted_message3.toAffine(), message3.toAffine());
  });

  it("Check unhappy homomorphic properties for wrong inputs", () => {
    const keypair = genKeypair();

    const encryption1 = encrypt(keypair.pubKey);
    const encryption2 = encrypt(keypair.pubKey);

    const message3 = encryption1.message.add(encryption2.message);
    const encrypted_message3 = encryption1.encrypted_message.add(encryption2.encrypted_message);
    // we only modifiy ephemeral_key3 in this example
    const ephemeral_key3 = encryption1.ephemeral_key.add(babyJub.BASE);

    const decrypted_message3 = decrypt(keypair.privKey, ephemeral_key3, encrypted_message3);

    assert.notDeepStrictEqual(decrypted_message3.toAffine(), message3.toAffine());
  });
});

describe("Testing Encoding/Decoding for ElGamal Scheme", async () => {
  it("Check encoding a plain text bigger than 32 bits returns error", () => {
    const plaintext = 4294967297n;
    let expected = Error;
    const exercise = () => encode(plaintext);
    assert.throws(exercise, expected);
  });

  it("Check encoded value is a valid BabyJub point", () => {
    const plaintext = pruneTo32Bits(genRandomBabyJubValue());
    const encoded = encode(plaintext);
    encoded.assertValidity();
  });

  it("Check compliance of orignal and decoded message as 32-bit numbers", async () => {
    const plaintext = pruneTo32Bits(genRandomBabyJubValue());
    const encoded = encode(plaintext);
    const decoded = decode(encoded, 19);

    assert.strictEqual(plaintext, decoded);
  }).timeout(10_000);

  it.skip("Check unhappy compliance of orignal and decoded message for a different random input", () => {
    const plaintext = pruneTo32Bits(genRandomBabyJubValue());
    const encoded = encode(plaintext);
    const rand = genRandomPoint();
    const decoded = decode(encoded, 19);
    const decoded_rand = decode(rand, 19);

    assert.strictEqual(plaintext, decoded);
    assert.notStrictEqual(decoded, decoded_rand);
  });

  it("Check LOOPED compliance of orignal and decoded message as 32-bit numbers", () => {
    for (let i = 0; i < 1; i++) {
      let plaintext = pruneTo32Bits(genRandomBabyJubValue());
      let encoded = encode(plaintext);
      let decoded = decode(encoded, 19);

      assert.strictEqual(plaintext, decoded);
    }
  });

  it("Check decoding preserves Elgamal linear homomorphism", () => {
    // The input should be a 64-bit number
    const plaintext = pruneTo64Bits(genRandomBabyJubValue());

    // the initial input is split into two 32-bit numbers for faster decoding
    const [xlo, xhi] = split64(plaintext);

    const M1 = encode(xlo);
    const M2 = encode(xhi);

    const keypair = genKeypair();

    const encryption1 = encrypt_s(M1, keypair.pubKey);
    const encryption2 = encrypt_s(M2, keypair.pubKey);

    const decrypted_message1 = decrypt(
      keypair.privKey,
      encryption1.ephemeral_key,
      encryption1.encrypted_message,
    );
    const decrypted_message2 = decrypt(
      keypair.privKey,
      encryption2.ephemeral_key,
      encryption2.encrypted_message,
    );

    const dlo = decode(decrypted_message1, 19);
    const dhi = decode(decrypted_message2, 19);

    const decoded_input = dlo + b32 * dhi;

    assert.strictEqual(decoded_input, plaintext);
  }).timeout(10_000);

  it("Check unhappy decoding breaks Elgamal linear homomorphism", () => {
    // The input should be a 64-bit number
    const input = pruneTo64Bits(genRandomBabyJubValue());

    // the initial input is split into two 32-bit numbers for faster decoding
    const [xlo, xhi] = split64(input);

    // we swap xlo and xhi to mess with the decoding
    const M1 = encode(xhi);
    const M2 = encode(xlo);

    const keypair = genKeypair();

    const encryption1 = encrypt_s(M1, keypair.pubKey);
    const encryption2 = encrypt_s(M2, keypair.pubKey);

    const decrypted_message1 = decrypt(
      keypair.privKey,
      encryption1.ephemeral_key,
      encryption1.encrypted_message,
    );
    const decrypted_message2 = decrypt(
      keypair.privKey,
      encryption2.ephemeral_key,
      encryption2.encrypted_message,
    );

    const dlo = decode(decrypted_message1, 19);
    const dhi = decode(decrypted_message2, 19);

    const decoded_input = dlo + b32 * dhi;

    assert.notStrictEqual(decoded_input, input);
  }).timeout(10_000);

  it("Check LOOPED decoding preserves Elgamal linear homomorphism", () => {
    for (let i = 0; i < 1; i++) {
      // The input should be a 64-bit number
      const input = pruneTo64Bits(genRandomBabyJubValue());

      // the initial input is split into two 32-bit numbers for faster decoding
      let [xlo, xhi] = split64(input);

      let M1 = encode(xlo);
      let M2 = encode(xhi);

      let keypair = genKeypair();

      const encryption1 = encrypt_s(M1, keypair.pubKey);
      const encryption2 = encrypt_s(M2, keypair.pubKey);

      const decrypted_message1 = decrypt(
        keypair.privKey,
        encryption1.ephemeral_key,
        encryption1.encrypted_message,
      );
      const decrypted_message2 = decrypt(
        keypair.privKey,
        encryption2.ephemeral_key,
        encryption2.encrypted_message,
      );

      const dlo = decode(decrypted_message1, 19);
      const dhi = decode(decrypted_message2, 19);

      const decoded_input = dlo + b32 * dhi;

      assert.strictEqual(decoded_input, input);
    }
  }).timeout(10_000);
});

function pruneTo64Bits(originalValue) {
 return originalValue & 0xFFFFFFFFFFFFFFFFn;
}

function pruneTo32Bits(bigInt253Bit) {
 return bigInt253Bit & 0xFFFFFFFFn;
}
