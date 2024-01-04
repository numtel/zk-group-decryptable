pragma circom 2.1.5;

include "babyjub.circom";
include "poseidon.circom";
include "bitify.circom";
include "escalarmulany.circom";
include "escalarmulfix.circom";
include "binary-merkle-root.circom";

template Semaphore(MAX_DEPTH) {
  signal input privateKey;
  signal input treeDepth, treeIndices[MAX_DEPTH], treeSiblings[MAX_DEPTH];
  signal input message;
  signal input scope;
  signal input nonceKey;
  signal input publicKey[2];

  signal output treeRoot, nullifier, ephemeralKey[2], encryptedMessage[2];

  var Ax, Ay;
  (Ax, Ay) = BabyPbk()(privateKey);

  var identityCommitment = Poseidon(2)([Ax, Ay]);

  treeRoot <== BinaryMerkleRoot(MAX_DEPTH)(identityCommitment, treeDepth, treeIndices, treeSiblings);
  nullifier <== Poseidon(2)([scope, privateKey]);

  // Encrypted value can only be 32 bits
  var idBits[254] = Num2Bits(254)(identityCommitment);
  var truncatedIdBits[32];
  for(var i = 0; i<32; i++) {
    truncatedIdBits[i] = idBits[i];
  }
  var truncatedIdentity = Bits2Num(32)(truncatedIdBits);

  var encodedIdentity[2];
  encodedIdentity = Encode()(truncatedIdentity);

  (ephemeralKey, encryptedMessage) <== Encrypt()(encodedIdentity, nonceKey, publicKey);

  // Dummy constraint to prevent compiler from optimizing it.
  signal dummySquare <== message * message;
}

template Encode() {
  signal input plaintext;
  signal output out[2];

  // baby jubjub curve base point
  var base[2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203
  ]; 

  component plaintextBits = Num2Bits(32);
  component escalarMulF = EscalarMulFix(32, base);

  var i;
  plaintext ==> plaintextBits.in;
  for (i=0; i<32; i++) {
    plaintextBits.out[i] ==> escalarMulF.e[i];
  }

  escalarMulF.out ==> out;
}

template Encrypt() {

  // message encoded as a point on the curve: message = [plaintext].G, G: curve base point
  signal input message[2];    
  // secret key nonce          
  signal input nonceKey;    
  // public key generated by the receiver             
  signal input publicKey[2];             

  // ephemeral key: [nonce].Base
  signal output ephemeralKey[2];  
  // encrypted message: encryptedMessage = message + [nonceKey].publicKey           
  signal output encryptedMessage[2];            
  
  component isz = IsZero();
  isz.in <== publicKey[0];
  
  component ise = IsEqual();
  ise.in[0] <== publicKey[1];
  ise.in[1] <== 1;

  // protect against invalid curve attacks => Public Key shouldn't be the identity point
  isz.out + ise.out === 0;  

  component isOnCurve[2];

  // check the public key is point on curve
  isOnCurve[0] = BabyCheck();             
  isOnCurve[0].x <== publicKey[0];
  isOnCurve[0].y <== publicKey[1];

  // check the Message is a point on curve
  isOnCurve[1] = BabyCheck();             
  isOnCurve[1].x <== message[0];
  isOnCurve[1].y <== message[1];
  
  // baby jubjub curve base point
  var base[2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203
  ];        

  component n2b[2];
  // calculate the ephemeral key
  n2b[0] = Num2Bits(253);
  component escalarMulF = EscalarMulFix(253, base);

  var i;
  nonceKey ==> n2b[0].in;
  for (i=0; i<253; i++) {
    n2b[0].out[i] ==> escalarMulF.e[i];
  }

  escalarMulF.out[0] ==> ephemeralKey[0];
  escalarMulF.out[1] ==> ephemeralKey[1];
  
  // calculate the second part of the encrypted message => [nonce].PublicKey
  n2b[1] = Num2Bits(253);
  component escalarMul = EscalarMulAny(253);

  escalarMul.p[0] <== publicKey[0];
  escalarMul.p[1] <== publicKey[1];

  var j;
  nonceKey ==> n2b[1].in;
  for (j=0; j<253; j++) {
    n2b[1].out[j] ==> escalarMul.e[j];
  }

  component add = BabyAdd();
  add.x1 <== escalarMul.out[0];
  add.y1 <== escalarMul.out[1];
  add.x2 <== message[0];
  add.y2 <== message[1];
  encryptedMessage[0] <== add.xout;
  encryptedMessage[1] <== add.yout;
}