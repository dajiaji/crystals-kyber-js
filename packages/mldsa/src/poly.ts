/**
 * This implementation follows NIST FIPS 204 and the structure of the reference
 * implementation at https://github.com/pq-crystals/dilithium (public domain /
 * Apache-2.0).
 */
import { INV_NTT_F, N, NTT_ZETAS, Q, Q_INV } from "./consts.ts";

export type Poly = Int32Array;

export function newPolyVec(size: number): Poly[] {
  const v = new Array<Poly>(size);
  for (let i = 0; i < size; i++) {
    v[i] = new Int32Array(N);
  }
  return v;
}

export function zeroPolyVec(v: Poly[]): void {
  for (let i = 0; i < v.length; i++) {
    v[i].fill(0);
  }
}

// The high 32 bits of the 64-bit product of two signed 32-bit integers,
// computed with 32-bit integer operations only.
function mulHi(a: number, b: number): number {
  const al = a & 0xFFFF;
  const ah = a >> 16;
  const bl = b & 0xFFFF;
  const bh = b >> 16;
  const lh = Math.imul(al, bh);
  const hl = Math.imul(ah, bl);
  const mid = (Math.imul(al, bl) >>> 16) + (lh & 0xFFFF) + (hl & 0xFFFF);
  return (Math.imul(ah, bh) + (lh >> 16) + (hl >> 16) + (mid >>> 16)) | 0;
}

/**
 * Montgomery multiplication: returns a * b * 2^-32 mod Q in (-Q, Q), for
 * |a * b| < 2^31 * Q. No divide and no floating point on secret-derived data.
 */
export function montgomeryMul(a: number, b: number): number {
  const t = Math.imul(Math.imul(a, b), Q_INV);
  // a * b and t * Q agree in their low 32 bits, so the high halves subtract
  // without a borrow.
  return mulHi(a, b) - mulHi(t, Q);
}

// Reduces each coefficient to a representative in about [-6283009, 6283008].
export function reduce(a: Poly): void {
  for (let i = 0; i < N; i++) {
    a[i] -= Math.imul((a[i] + (1 << 22)) >> 23, Q);
  }
}

/**
 * In-place forward NTT. The output coefficients grow by at most 8 * Q in
 * absolute value.
 */
export function ntt(a: Poly): void {
  let k = 0;
  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = NTT_ZETAS[++k];
      for (let j = start; j < start + len; j++) {
        const t = montgomeryMul(zeta, a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}

/**
 * In-place inverse NTT and multiplication by the Montgomery factor 2^32.
 * The input coefficients must be below Q in absolute value, and so are the
 * output ones.
 */
export function invNtt(a: Poly): void {
  let k = N;
  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = -NTT_ZETAS[--k];
      for (let j = start; j < start + len; j++) {
        const t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = montgomeryMul(zeta, t - a[j + len]);
      }
    }
  }
  for (let j = 0; j < N; j++) {
    a[j] = montgomeryMul(INV_NTT_F, a[j]);
  }
}

// out = a * b in the NTT domain (Montgomery).
export function pointwiseMul(out: Poly, a: Poly, b: Poly): void {
  for (let i = 0; i < N; i++) {
    out[i] = montgomeryMul(a[i], b[i]);
  }
}

// out = sum_j row[j] * v[j] in the NTT domain (Montgomery).
export function matrixRowMul(out: Poly, row: Poly[], v: Poly[]): void {
  pointwiseMul(out, row[0], v[0]);
  for (let j = 1; j < v.length; j++) {
    const r = row[j];
    const p = v[j];
    for (let i = 0; i < N; i++) {
      out[i] += montgomeryMul(r[i], p[i]);
    }
  }
}

/**
 * Returns true if the infinity norm of `a` is at least `bound`.
 *
 * Which coefficient violates the bound may leak, since that is independent of
 * secret data, but the sign of the coefficient must not.
 */
export function exceeds(a: Poly, bound: number): boolean {
  for (let i = 0; i < N; i++) {
    let t = a[i] >> 31;
    t = a[i] - (t & (2 * a[i]));
    if (t >= bound) {
      return true;
    }
  }
  return false;
}

// HighBits (FIPS 204, Algorithm 37) for a in [0, Q).
export function highBits(a: number, gamma2: number): number {
  let a1 = (a + 127) >> 7;
  if (gamma2 === (Q - 1) / 32) {
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
  } else {
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
  }
  return a1;
}

// LowBits (FIPS 204, Algorithm 38) for a in [0, Q), given a1 = HighBits(a).
export function lowBits(a: number, a1: number, gamma2: number): number {
  let a0 = a - a1 * 2 * gamma2;
  a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
  return a0;
}

// MakeHint (FIPS 204, Algorithm 39), from the low and the high bits.
export function makeHint(a0: number, a1: number, gamma2: number): number {
  return (a0 > gamma2 || a0 < -gamma2 || (a0 === -gamma2 && a1 !== 0)) ? 1 : 0;
}

// UseHint (FIPS 204, Algorithm 40) for a in [0, Q). Works on public data.
export function useHint(a: number, hint: number, gamma2: number): number {
  const a1 = highBits(a, gamma2);
  if (hint === 0) {
    return a1;
  }
  const a0 = lowBits(a, a1, gamma2);
  if (gamma2 === (Q - 1) / 32) {
    return a0 > 0 ? (a1 + 1) & 15 : (a1 - 1) & 15;
  }
  if (a0 > 0) {
    return a1 === 43 ? 0 : a1 + 1;
  }
  return a1 === 0 ? 43 : a1 - 1;
}

// SimpleBitPack (FIPS 204, Algorithm 16): packs coefficients of `bits` bits.
export function simpleBitPack(
  out: Uint8Array,
  off: number,
  a: Poly,
  bits: number,
): void {
  let acc = 0;
  let accBits = 0;
  for (let i = 0; i < N; i++) {
    acc |= a[i] << accBits;
    accBits += bits;
    while (accBits >= 8) {
      out[off++] = acc & 0xFF;
      acc >>>= 8;
      accBits -= 8;
    }
  }
}

// SimpleBitUnpack (FIPS 204, Algorithm 18)
export function simpleBitUnpack(
  out: Poly,
  a: Uint8Array,
  off: number,
  bits: number,
): void {
  const mask = (1 << bits) - 1;
  let acc = 0;
  let accBits = 0;
  for (let i = 0; i < N; i++) {
    while (accBits < bits) {
      acc |= a[off++] << accBits;
      accBits += 8;
    }
    out[i] = acc & mask;
    acc >>>= bits;
    accBits -= bits;
  }
}

// BitPack (FIPS 204, Algorithm 17): packs b - a[i] in `bits` bits.
export function bitPack(
  out: Uint8Array,
  off: number,
  a: Poly,
  bits: number,
  b: number,
): void {
  let acc = 0;
  let accBits = 0;
  for (let i = 0; i < N; i++) {
    acc |= (b - a[i]) << accBits;
    accBits += bits;
    while (accBits >= 8) {
      out[off++] = acc & 0xFF;
      acc >>>= 8;
      accBits -= 8;
    }
  }
}

/**
 * BitUnpack (FIPS 204, Algorithm 19): unpacks coefficients b - v, where v is
 * a value of `bits` bits.
 *
 * @returns A non-zero value if any coefficient is below -b, which cannot come
 * from BitPack with the range [-b, b].
 */
export function bitUnpack(
  out: Poly,
  a: Uint8Array,
  off: number,
  bits: number,
  b: number,
): number {
  const mask = (1 << bits) - 1;
  let acc = 0;
  let accBits = 0;
  let bad = 0;
  for (let i = 0; i < N; i++) {
    while (accBits < bits) {
      acc |= a[off++] << accBits;
      accBits += 8;
    }
    const v = acc & mask;
    // v > 2 * b
    bad |= (2 * b - v) >>> 31;
    out[i] = b - v;
    acc >>>= bits;
    accBits -= bits;
  }
  return bad;
}
