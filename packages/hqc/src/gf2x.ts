/**
 * The multiplication in F_2[X] / (X^n - 1).
 *
 * As the HQC specifications v5.1 require (Section 3.4), the multiplication
 * does not take the sparsity of an operand into account: it runs the same
 * sequence of operations and touches the same memory whatever the operands
 * are, since one of them is always a secret vector of a small weight.
 */
import { clmul16 } from "./utils.ts";

// r[ro], r[ro + 1] = x * y, a carry-less multiplication of two 32-bit words
// by Karatsuba over 16-bit halves.
function clmul32(r: Uint32Array, ro: number, x: number, y: number): void {
  const xl = x & 0xffff;
  const xh = x >>> 16;
  const yl = y & 0xffff;
  const yh = y >>> 16;
  const lo = clmul16(xl, yl);
  const hi = clmul16(xh, yh);
  const mid = clmul16(xl ^ xh, yl ^ yh) ^ lo ^ hi;
  r[ro] = lo ^ (mid << 16);
  r[ro + 1] = hi ^ (mid >>> 16);
}

// r[ro..ro + 2n) = a[ao..ao + n) * b[bo..bo + n) by Karatsuba. r must not
// overlap a, b or the part of t from `to`, which is used as a scratch space
// of scratchSize(n) words.
function karatsuba(
  r: Uint32Array,
  ro: number,
  a: Uint32Array,
  ao: number,
  b: Uint32Array,
  bo: number,
  n: number,
  t: Uint32Array,
  to: number,
): void {
  if (n === 1) {
    clmul32(r, ro, a[ao], b[bo]);
    return;
  }
  const m = n >> 1;
  const n1 = n - m;
  const child = to + 4 * n1;

  // z0 = a0 * b0 and z2 = a1 * b1 are written to their places in r.
  karatsuba(r, ro, a, ao, b, bo, m, t, child);
  karatsuba(r, ro + 2 * m, a, ao + m, b, bo + m, n1, t, child);

  // zmid = (a0 + a1) * (b0 + b1)
  const ta = to;
  const tb = to + n1;
  const zmid = to + 2 * n1;
  for (let i = 0; i < m; i++) {
    t[ta + i] = a[ao + i] ^ a[ao + m + i];
    t[tb + i] = b[bo + i] ^ b[bo + m + i];
  }
  if (n1 > m) {
    t[ta + m] = a[ao + 2 * m];
    t[tb + m] = b[bo + 2 * m];
  }
  karatsuba(t, zmid, t, ta, t, tb, n1, t, child);

  // r += (zmid + z0 + z2) * X^(32 * m)
  const z2 = ro + 2 * m;
  for (let i = 0; i < 2 * m; i++) {
    t[zmid + i] ^= r[ro + i] ^ r[z2 + i];
  }
  for (let i = 2 * m; i < 2 * n1; i++) {
    t[zmid + i] ^= r[z2 + i];
  }
  const mid = ro + m;
  for (let i = 0; i < 2 * n1; i++) {
    r[mid + i] ^= t[zmid + i];
  }
}

// The number of words which karatsuba() needs as a scratch space.
function scratchSize(n: number): number {
  let size = 0;
  while (n > 1) {
    n = n - (n >> 1);
    size += 4 * n;
  }
  return size;
}

/**
 * A multiplier in F_2[X] / (X^n - 1) with its working memory.
 *
 * A polynomial is an array of ceil(n / 32) 32-bit words, of which the bit i
 * of the word j is the coefficient of X^(32 * j + i).
 */
export class Gf2x {
  private _nWords: number;
  private _rem: number;
  private _prod: Uint32Array;
  private _scratch: Uint32Array;

  /**
   * @param n The length of the vectors in bits, which is not a multiple of 32.
   */
  constructor(n: number) {
    this._nWords = (n + 31) >>> 5;
    this._rem = n & 31;
    this._prod = new Uint32Array(2 * this._nWords);
    this._scratch = new Uint32Array(scratchSize(this._nWords));
  }

  /**
   * Computes o = a * b mod (X^n - 1). o may be a or b.
   */
  mul(o: Uint32Array, a: Uint32Array, b: Uint32Array): void {
    const n = this._nWords;
    const p = this._prod;
    karatsuba(p, 0, a, 0, b, 0, n, this._scratch, 0);
    // X^n = 1: fold the high half of the product back into the low half.
    const r = this._rem;
    for (let i = 0; i < n; i++) {
      o[i] = p[i] ^ (p[i + n - 1] >>> r) ^ (p[i + n] << (32 - r));
    }
    o[n - 1] &= (1 << r) - 1;
  }

  /** Wipes the working memory. */
  clear(): void {
    this._prod.fill(0);
    this._scratch.fill(0);
  }
}
