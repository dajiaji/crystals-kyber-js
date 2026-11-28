// The minimal sponge is all the implementation needs. The hash functions with
// the validating interface are for the applications which import them.
export { KeccakCore as Keccak } from "./sha3/keccak.ts";
export { sha3_256, sha3_512, shake128, shake256 } from "./sha3/sha3.ts";
