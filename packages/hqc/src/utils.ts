/**
 * compares two arrays
 * @returns 1 if they are the same or 0 if not
 */
export function constantTimeCompare(x: Uint8Array, y: Uint8Array): number {
  // check array lengths
  if (x.length != y.length) {
    return 0;
  }
  let v = 0;
  for (let i = 0; i < x.length; i++) {
    v |= x[i] ^ y[i];
  }
  // constantTimeByteEq
  let z = (~v) & 0xFF;
  z &= z >> 4;
  z &= z >> 2;
  z &= z >> 1;
  return z & 1;
}

// A vector of F_2^n is an octet string in little-endian order: the bit i of
// the vector is the bit (i mod 8) of the octet floor(i / 8). The arithmetic
// works on 32-bit words, which are converted explicitly here instead of
// aliasing the octets, so that the result does not depend on the endianness
// of the platform.

/**
 * Loads `len` octets of `src` from `off` into the 32-bit words of `out`.
 * The rest of `out` is set to zero.
 */
export function bytesToWords(
  out: Uint32Array,
  src: Uint8Array,
  off: number,
  len: number,
): void {
  const full = len >>> 2;
  let p = off;
  let i = 0;
  for (; i < full; i++, p += 4) {
    out[i] = src[p] | (src[p + 1] << 8) | (src[p + 2] << 16) |
      (src[p + 3] << 24);
  }
  const rem = len & 3;
  if (rem > 0) {
    let w = 0;
    for (let j = 0; j < rem; j++) {
      w |= src[p + j] << (8 * j);
    }
    out[i++] = w;
  }
  for (; i < out.length; i++) {
    out[i] = 0;
  }
}

/**
 * Stores the first `len` octets of the 32-bit words of `src` into `out`
 * from `off`.
 */
export function wordsToBytes(
  out: Uint8Array,
  off: number,
  src: Uint32Array,
  len: number,
): void {
  for (let i = 0; i < len; i++) {
    out[off + i] = src[i >>> 2] >>> (8 * (i & 3));
  }
}

/**
 * Multiplies two 16-bit values without carries, i.e. as polynomials over
 * F_2, with integer multiplications only: no table lookup and no branch
 * depends on the operands.
 *
 * Each operand is split into three values which hold every third bit, so
 * that a product of two of them has, at every third bit, the number of the
 * pairs of bits which meet there. That number is at most 6, which fits in the
 * 3 bits available, and its lowest bit is the coefficient of the carry-less
 * product. A product is less than 2^32, so Math.imul returns it exactly.
 */
export function clmul16(x: number, y: number): number {
  const x0 = x & 0x9249;
  const x1 = x & 0x2492;
  const x2 = x & 0x4924;
  const y0 = y & 0x9249;
  const y1 = y & 0x2492;
  const y2 = y & 0x4924;
  const z0 = Math.imul(x0, y0) ^ Math.imul(x1, y2) ^ Math.imul(x2, y1);
  const z1 = Math.imul(x0, y1) ^ Math.imul(x1, y0) ^ Math.imul(x2, y2);
  const z2 = Math.imul(x0, y2) ^ Math.imul(x1, y1) ^ Math.imul(x2, y0);
  return (z0 & 0x49249249) | (z1 & 0x92492492) | (z2 & 0x24924924);
}

/**
 * Reduces x modulo n without a division, for x < 2^24 and 2^14 < n < 2^16,
 * where mu is floor(2^32 / n).
 *
 * The quotient is estimated from the top 14 bits of x, so that the product
 * with mu stays below 2^32, and is too small by at most 1.
 */
export function reduce24(x: number, n: number, mu: number): number {
  const q = Math.imul(x >>> 10, mu) >>> 22;
  const r = x - Math.imul(q, n);
  // r is in [0, 2n): subtract n once if r >= n.
  return r - (n & -(((r - n) >>> 31) ^ 1));
}
