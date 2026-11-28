/**
 * This implementation follows NIST FIPS 204 and the structure of the reference
 * implementation at https://github.com/pq-crystals/dilithium (public domain /
 * Apache-2.0).
 */
import { Keccak } from "./deps.ts";

import { D, N, Q } from "./consts.ts";
import type { MlDsaParams } from "./params.ts";
import { newPolyVec, type Poly } from "./poly.ts";
import { assertBytes } from "./utils.ts";

const SHAKE128_RATE = 168;
export const SHAKE256_RATE = 136;

export const SEED_SIZE = 32; // xi, rho, K and rnd
export const TR_SIZE = 64;
export const MU_SIZE = 64;
export const T1_BITS = 10;
export const T1_POLY_SIZE: number = N * T1_BITS / 8;
export const T0_POLY_SIZE: number = N * D / 8;
const MAX_CONTEXT_SIZE = 255;

/**
 * The part of ML-DSA which signing and verification have in common: the
 * parameter set, hashing, and sampling from public values.
 *
 * It has no key generation, signing or verification by itself, so that an
 * application which only verifies does not bundle the code for signing, and
 * vice versa. See `MlDsaSigner` and `MlDsaVerifier`.
 */
export class MlDsaBase {
  // The parameter set (FIPS 204, Table 1).
  protected _k: number;
  protected _l: number;
  protected _eta: number;
  protected _tau: number;
  protected _gamma1: number;
  protected _gamma2: number;
  protected _omega: number;
  protected _cTildeSize: number;
  // Derived values.
  protected _beta: number;
  protected _etaBits: number;
  protected _zBits: number;
  protected _w1Bits: number;
  protected _etaPolySize: number;
  protected _zPolySize: number;
  protected _w1PolySize: number;
  protected _pkSize: number;
  protected _skSize: number;
  protected _sigSize: number;
  // Keccak instances (reset before each use).
  protected _shake128: Keccak = new Keccak(SHAKE128_RATE, 0x1f, 32, true);
  protected _shake256: Keccak = new Keccak(SHAKE256_RATE, 0x1f, 32, true);
  protected _block128: Uint8Array = new Uint8Array(SHAKE128_RATE);
  protected _block256: Uint8Array = new Uint8Array(SHAKE256_RATE);
  protected _nonceBuf: Uint8Array = new Uint8Array(2);

  constructor(params: MlDsaParams) {
    this._k = params.k;
    this._l = params.l;
    this._eta = params.eta;
    this._tau = params.tau;
    this._gamma1 = 1 << params.gamma1Bits;
    this._gamma2 = params.gamma2;
    this._omega = params.omega;
    this._cTildeSize = params.cTildeSize;
    this._beta = this._tau * this._eta;
    this._etaBits = this._eta === 2 ? 3 : 4;
    this._zBits = params.gamma1Bits + 1;
    this._w1Bits = this._gamma2 === (Q - 1) / 88 ? 6 : 4;
    this._etaPolySize = N * this._etaBits / 8;
    this._zPolySize = N * this._zBits / 8;
    this._w1PolySize = N * this._w1Bits / 8;
    this._pkSize = SEED_SIZE + this._k * T1_POLY_SIZE;
    this._skSize = 2 * SEED_SIZE + TR_SIZE +
      (this._l + this._k) * this._etaPolySize + this._k * T0_POLY_SIZE;
    this._sigSize = this._cTildeSize + this._l * this._zPolySize +
      this._omega + this._k;
  }

  /**
   * Computes mu = H(tr || 0 || |ctx| || ctx || M, 64), the message
   * representative for the pure ML-DSA (FIPS 204, Algorithm 2 and 7).
   */
  protected _computeMu(
    out: Uint8Array,
    tr: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): void {
    this._h(out, tr, Uint8Array.of(0, ctx.byteLength), ctx, msg);
  }

  protected _checkContext(ctx?: Uint8Array): Uint8Array {
    if (ctx === undefined) {
      return new Uint8Array(0);
    }
    assertBytes(ctx, "context");
    if (ctx.byteLength > MAX_CONTEXT_SIZE) {
      throw new Error("context must be at most 255 bytes in length");
    }
    return ctx;
  }

  // H: SHAKE256 over the concatenation of `inputs`, filling `out`.
  protected _h(out: Uint8Array, ...inputs: Uint8Array[]): void {
    this._shake256.reset();
    for (let i = 0; i < inputs.length; i++) {
      this._shake256.updateUnsafe(inputs[i]);
    }
    this._shake256.writeIntoUnsafe(out);
  }

  protected _zeroHashes(): void {
    // reset() zeros state and resets flags
    this._shake128.reset();
    this._shake256.reset();
    this._block128.fill(0);
    this._block256.fill(0);
    this._nonceBuf.fill(0);
  }

  /**
   * ExpandA (FIPS 204, Algorithm 32): samples the k x l matrix A in the NTT
   * domain from rho.
   */
  protected _expandA(rho: Uint8Array): Poly[][] {
    const a = new Array<Poly[]>(this._k);
    for (let r = 0; r < this._k; r++) {
      a[r] = newPolyVec(this._l);
      for (let s = 0; s < this._l; s++) {
        this._rejNttPoly(a[r][s], rho, s, r);
      }
    }
    return a;
  }

  // RejNTTPoly (FIPS 204, Algorithm 30)
  protected _rejNttPoly(
    out: Poly,
    rho: Uint8Array,
    s: number,
    r: number,
  ): void {
    const buf = this._block128;
    this._nonceBuf[0] = s;
    this._nonceBuf[1] = r;
    this._shake128.reset();
    this._shake128.updateUnsafe(rho).updateUnsafe(this._nonceBuf);
    let ctr = 0;
    while (ctr < N) {
      this._shake128.writeIntoUnsafe(buf);
      for (let pos = 0; pos < SHAKE128_RATE && ctr < N; pos += 3) {
        const t = buf[pos] | (buf[pos + 1] << 8) |
          ((buf[pos + 2] & 0x7F) << 16);
        if (t < Q) {
          out[ctr++] = t;
        }
      }
    }
  }

  // SampleInBall (FIPS 204, Algorithm 29)
  protected _sampleInBall(c: Poly, cTilde: Uint8Array): void {
    const buf = this._block256;
    this._shake256.reset();
    this._shake256.updateUnsafe(cTilde);
    this._shake256.writeIntoUnsafe(buf);
    const signsLo = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
    const signsHi = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
    let pos = 8;
    c.fill(0);
    for (let i = N - this._tau; i < N; i++) {
      let j: number;
      do {
        if (pos >= SHAKE256_RATE) {
          this._shake256.writeIntoUnsafe(buf);
          pos = 0;
        }
        j = buf[pos++];
      } while (j > i);
      const n = i - (N - this._tau);
      const sign = n < 32 ? (signsLo >>> n) & 1 : (signsHi >>> (n - 32)) & 1;
      c[i] = c[j];
      c[j] = 1 - 2 * sign;
    }
  }
}
