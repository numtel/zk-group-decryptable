import fs from "node:fs";
import { babyJub } from "./ElGamal.js";

const directoryName = "lookupTables";

function computeDiscreteLookup(precomputeSize) {
 const range = 32 - precomputeSize;
 const upperBound = BigInt(2) ** BigInt(precomputeSize);

 let lookupTable = {};
 let key;

 for (let xhi = BigInt(0); xhi < upperBound; xhi++) {
  key = babyJub.BASE.multiplyUnsafe(xhi * BigInt(2) ** BigInt(range))
   .toAffine()
   .x.toString();
  lookupTable[key] = xhi.toString(16);
 }
 return lookupTable;
}

function fetch_table(precomputeSize) {
 try {
  return JSON.parse(fs.readFileSync(
    `./${directoryName}/x${precomputeSize}xlookupTable.json`,
    {encoding: 'utf8'}
  ));
 } catch (error) {
  console.log('Generating new lookup table, this could take a few minutes...');
  const lookupTable = computeDiscreteLookup(precomputeSize);
  console.log('Lookup table generation complete.');
  if (!fs.existsSync(directoryName)) {
   fs.mkdirSync(directoryName);
   console.log(`Directory "${directoryName}" created.`);
  }
  fs.writeFileSync(
   `./${directoryName}/x${precomputeSize}xlookupTable.json`,
   JSON.stringify(lookupTable),
  );
  return lookupTable;
 }
}

let lookupTable;
export function decode(encoded, precomputeSize) {
  // The first time decode is called, it will call fetch_table() and store the lookupTable variable. 
  // Subsequent calls to fetchTable() will use the table stored in the lookupTable variable, rather than calling functionA again.
  // This will save the time from reading the lookupTable whenever decode is called again
  if (!lookupTable || Object.keys(lookupTable).length != 2 ** precomputeSize) {
    lookupTable = fetch_table(precomputeSize);
  }

  const range = 32 - precomputeSize;
  const rangeBound = 2n ** BigInt(range);

  for (let xlo = 0n; xlo < rangeBound; xlo++) {
    let loBase = babyJub.BASE.multiplyUnsafe(xlo);
    let key = encoded.subtract(loBase).toAffine().x.toString();

    if (lookupTable.hasOwnProperty(key)) {
      return xlo + rangeBound * BigInt("0x" + lookupTable[key]);
    }
  }
  throw new Error("NOT_FOUND");
}

// xlo and xhi merging  verification
export function split64(x) {
  function padBin(x) {
    return "0".repeat(64 - x.length) + x;
  }
  const limit = 2n ** 64n;

  if (x > limit)
    throw new Error('INVALID_64_BIT_BIGINT');
  const bin64 = padBin(x.toString(2));
  const xhi = "0b" + bin64.substring(0, 32);
  const xlo = "0b" + bin64.substring(32, 64);

  return [BigInt(xlo), BigInt(xhi)];
}
