/**
 * This implementation follows NIST FIPS 204 and the structure of the reference
 * implementation at https://github.com/pq-crystals/dilithium (public domain /
 * Apache-2.0).
 */
import { D, N, Q } from "./consts.ts";
import { MlDsaError } from "./errors.ts";
import type {
  MlDsaVerifierInterface,
  MlDsaVerifyOptions,
} from "./interfaces.ts";
import {
  MlDsaBase,
  MU_SIZE,
  SEED_SIZE,
  T1_BITS,
  T1_POLY_SIZE,
  TR_SIZE,
} from "./mlDsaBase.ts";
import type { MlDsaParams } from "./params.ts";
import {
  bitUnpack,
  exceeds,
  invNtt,
  matrixRowMul,
  montgomeryMul,
  newPolyVec,
  ntt,
  reduce,
  simpleBitPack,
  simpleBitUnpack,
  useHint,
} from "./poly.ts";
import { assertBytes } from "./utils.ts";

/**
 * Verification of ML-DSA.
 *
 * Use one of the factory functions to create an initialized instance:
 * `createMlDsa44Verifier`, `createMlDsa65Verifier` or `createMlDsa87Verifier`.
 */
export class MlDsaVerifier extends MlDsaBase implements MlDsaVerifierInterface {
  /** Verifies a signature: returns true if the signature is valid. */
  verify(
    pk: Uint8Array,
    sig: Uint8Array,
    msg: Uint8Array,
    opts?: MlDsaVerifyOptions,
  ): boolean {
    const mu = new Uint8Array(MU_SIZE);
    try {
      assertBytes(pk, "pk");
      assertBytes(sig, "sig");
      assertBytes(msg, "msg");
      const ctx = this._checkContext(opts?.context);
      // FIPS 204, Section 3.6.2: a public key or a signature of an incorrect
      // length is rejected, before hashing the message.
      if (!this._hasValidSizes(pk, sig)) {
        return false;
      }
      const tr = new Uint8Array(TR_SIZE);
      this._h(tr, pk);
      this._computeMu(mu, tr, msg, ctx);
      return this._verifyMu(pk, mu, sig);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    } finally {
      // do not leave message-derived data behind, also on an early rejection
      mu.fill(0);
      this._zeroHashes();
    }
  }

  /** @internal */
  // deno-lint-ignore require-await
  static async _create(params: MlDsaParams): Promise<MlDsaVerifier> {
    return new MlDsaVerifier(params);
  }

  private _hasValidSizes(pk: Uint8Array, sig: Uint8Array): boolean {
    return pk.byteLength === this._pkSize && sig.byteLength === this._sigSize;
  }

  /**
   * The main part of ML-DSA.Verify_internal (FIPS 204, Algorithm 8), starting
   * from the message representative mu.
   *
   * The caller must have validated the type of the arguments, and must call
   * _zeroHashes() afterwards.
   * @internal
   */
  protected _verifyMu(
    pk: Uint8Array,
    mu: Uint8Array,
    sig: Uint8Array,
  ): boolean {
    if (!this._hasValidSizes(pk, sig)) {
      return false;
    }
    const k = this._k;
    const l = this._l;
    const gamma1 = this._gamma1;
    const gamma2 = this._gamma2;
    const omega = this._omega;

    // sigDecode
    const cTilde = sig.subarray(0, this._cTildeSize);
    const z = newPolyVec(l);
    let off = this._cTildeSize;
    for (let i = 0; i < l; i++) {
      bitUnpack(z[i], sig, off, this._zBits, gamma1);
      if (exceeds(z[i], gamma1 - this._beta)) {
        return false;
      }
      off += this._zPolySize;
    }
    // HintBitUnpack (FIPS 204, Algorithm 21)
    const hints = newPolyVec(k);
    let index = 0;
    for (let i = 0; i < k; i++) {
      const end = sig[off + omega + i];
      if (end < index || end > omega) {
        return false;
      }
      const first = index;
      for (; index < end; index++) {
        if (index > first && sig[off + index - 1] >= sig[off + index]) {
          return false;
        }
        hints[i][sig[off + index]] = 1;
      }
    }
    for (; index < omega; index++) {
      if (sig[off + index] !== 0) {
        return false;
      }
    }

    const rho = pk.subarray(0, SEED_SIZE);
    const a = this._expandA(rho);
    const c = new Int32Array(N);
    this._sampleInBall(c, cTilde);
    ntt(c);
    for (let i = 0; i < l; i++) ntt(z[i]);

    // w'_approx = NTT^-1(A * NTT(z) - NTT(c) * NTT(t1 * 2^d))
    const w = new Int32Array(N);
    const t1 = new Int32Array(N);
    const w1Packed = new Uint8Array(k * this._w1PolySize);
    for (let i = 0; i < k; i++) {
      matrixRowMul(w, a[i], z);
      simpleBitUnpack(t1, pk, SEED_SIZE + i * T1_POLY_SIZE, T1_BITS);
      for (let j = 0; j < N; j++) t1[j] <<= D;
      ntt(t1);
      for (let j = 0; j < N; j++) w[j] -= montgomeryMul(c[j], t1[j]);
      reduce(w);
      invNtt(w);
      // w1' = UseHint(h, w'_approx)
      for (let j = 0; j < N; j++) {
        w[j] = useHint(w[j] + ((w[j] >> 31) & Q), hints[i][j], gamma2);
      }
      simpleBitPack(w1Packed, i * this._w1PolySize, w, this._w1Bits);
    }

    const cTilde2 = new Uint8Array(this._cTildeSize);
    this._h(cTilde2, mu, w1Packed);
    let diff = 0;
    for (let i = 0; i < cTilde.length; i++) {
      diff |= cTilde[i] ^ cTilde2[i];
    }
    return diff === 0;
  }
}
