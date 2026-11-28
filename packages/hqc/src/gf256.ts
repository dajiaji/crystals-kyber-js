/**
 * The arithmetic of the field with 2^8 elements, F_2[X] / (X^8 + X^4 + X^3 +
 * X + 1), which the Reed-Solomon code of HQC is defined over.
 *
 * The operands are secret while a message is encoded or decoded, so the
 * operations use neither a lookup table nor a branch.
 */
import { clmul16 } from "./utils.ts";

/**
 * Multiplies two elements of the field.
 */
export function gfMul(a: number, b: number): number {
  let r = clmul16(a, b);
  // X^8 = X^4 + X^3 + X + 1: two folds bring the 15 bits down to 8.
  let h = r >>> 8;
  r = (r & 0xff) ^ h ^ (h << 1) ^ (h << 3) ^ (h << 4);
  h = r >>> 8;
  return (r & 0xff) ^ h ^ (h << 1) ^ (h << 3) ^ (h << 4);
}

/**
 * Inverts an element of the field as a^254, with the addition chain
 * 1 2 3 4 7 11 15 30 60 120 127 254. The inverse of 0 is 0.
 */
export function gfInverse(a: number): number {
  let inv = gfMul(a, a); // a^2
  let tmp1 = gfMul(inv, a); // a^3
  inv = gfMul(inv, inv); // a^4
  const tmp2 = gfMul(inv, tmp1); // a^7
  tmp1 = gfMul(inv, tmp2); // a^11
  inv = gfMul(tmp1, inv); // a^15
  inv = gfMul(inv, inv); // a^30
  inv = gfMul(inv, inv); // a^60
  inv = gfMul(inv, inv); // a^120
  inv = gfMul(inv, tmp2); // a^127
  return gfMul(inv, inv); // a^254
}
