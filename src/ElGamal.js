import crypto from "node:crypto";
import createBlakeHash from "blake-hash/js.js";
import * as ff from "ffjavascript";
import { twistedEdwards } from "@noble/curves/abstract/edwards";
import { Field } from "@noble/curves/abstract/modular";
import { sha512 } from "@noble/hashes/sha512";
import { randomBytes } from "@noble/hashes/utils";

const Fp = Field(21888242871839275222246405745257275088548364400416034343698204186575808495617n);
const CURVE = twistedEdwards({
  a: Fp.create(168700n),
  d: Fp.create(168696n),
  Fp: Fp,
  n: 21888242871839275222246405745257275088614511777268538073601725287587578984328n,
  h: 8n,
  Gx: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  Gy: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
  hash: sha512,
  randomBytes,
});
const SNARK_FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Textbook Elgamal Encryption Scheme over Baby Jubjub curve without message encoding
export const babyJub = CURVE.ExtendedPoint;

export function genRandomBabyJubValue() {
  // Prevent modulo bias
  //const lim = 0x10000000000000000000000000000000000000000000000000000000000000000n;
  //const min = (lim - SNARK_FIELD_SIZE) % SNARK_FIELD_SIZE;
  const min = 6350874878119819312338956282401532410528162663560392320966563075034087161851n;

  let rand;
  while (true) {
    rand = BigInt("0x" + crypto.randomBytes(32).toString("hex"));

    if (rand >= min) {
      break;
    }
  }

  return rand % SNARK_FIELD_SIZE;
}

export function genPubKey(privKey) {
  if(privKey > SNARK_FIELD_SIZE) throw new Error('INVALID_PRIVATE_KEY');
  return prv2pub(bigInt2Buffer(privKey));
}

export function genKeypair() {
  const privKey = genRandomBabyJubValue();
  const pubKey = genPubKey(privKey);
  return { privKey, pubKey };
}

export function genRandomPoint() {
  const salt = genRandomBabyJubValue();
  return genPubKey(salt);
}

export function encrypt(pubKey, encodedMessage, nonce) {
  if (!pubKey.assertValidity || pubKey.equals(babyJub.ZERO))
    throw new Error('INVALID_PUBLIC_KEY');

  const message = encodedMessage || genRandomPoint();
  nonce = nonce || formatPrivKeyForBabyJub(genRandomBabyJubValue());

  // The sender calculates an ephemeral key => [nonce].Base
  const ephemeral_key = babyJub.BASE.multiply(nonce);
  const masking_key = pubKey.multiply(nonce);
  const encrypted_message = message.add(masking_key);
  return { message, ephemeral_key, encrypted_message, nonce };
}

export function encrypt_s(message, public_key, nonce) {
  nonce = nonce || genRandomBabyJubValue();

  const ephemeral_key = babyJub.BASE.multiply(nonce);
  const masking_key = public_key.multiply(nonce);
  const encrypted_message = masking_key.add(message);

  return { ephemeral_key, encrypted_message };
}

export function rerandomize(pubKey, ephemeral_key, encrypted_message, nonce) {
  nonce = nonce || genRandomBabyJubValue();
  const randomized_ephemeralKey = ephemeral_key.add(babyJub.BASE.multiply(nonce));
  const randomized_encryptedMessage = encrypted_message.add(pubKey.multiply(nonce));

  return { randomized_ephemeralKey, randomized_encryptedMessage };
}

export function decrypt(privKey, ephemeral_key, encrypted_message) {
  // The receiver decrypts the message => encryptedMessage - [privKey].ephemeralKey
  const masking_key = ephemeral_key.multiply(formatPrivKeyForBabyJub(privKey));
  const decrypted_message = encrypted_message.add(masking_key.negate());
  return decrypted_message;
}

export function encode(plaintext) {
  if (plaintext > 2n ** 32n)
   throw new Error('INVALID_32_BIT_BIGINT');
  return babyJub.BASE.multiplyUnsafe(plaintext);
}

function pruneBuffer(buff) {
  buff[0] = buff[0] & 0xf8;
  buff[31] = buff[31] & 0x7f;
  buff[31] = buff[31] | 0x40;
  return buff;
}

function prv2pub(prv) {
  const sBuff = pruneBuffer(createBlakeHash("blake512").update(Buffer.from(prv)).digest());
  let s = ff.Scalar.fromRprLE(sBuff, 0, 32);
  const A = babyJub.BASE.multiply(BigInt(ff.Scalar.shr(s, 3)));
  return A;
}

function formatPrivKeyForBabyJub(privKey) {
  const sBuff = pruneBuffer(
    createBlakeHash("blake512").update(bigInt2Buffer(privKey)).digest().slice(0, 32),
  );
  const s = ff.utils.leBuff2int(sBuff);
  return ff.Scalar.shr(s, 3);
}

function bigInt2Buffer(i) {
  return Buffer.from(i.toString(16), "hex");
};

