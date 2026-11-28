/**
 * This implementation follows NIST FIPS 204 and the structure of the reference
 * implementation at https://github.com/pq-crystals/dilithium (public domain /
 * Apache-2.0).
 */
import { D, N, Q } from "./consts.ts";
import { MlDsaError } from "./errors.ts";
import type { MlDsaSignerInterface, MlDsaSignOptions } from "./interfaces.ts";
import {
  MlDsaBase,
  MU_SIZE,
  SEED_SIZE,
  SHAKE256_RATE,
  T0_POLY_SIZE,
  T1_BITS,
  T1_POLY_SIZE,
  TR_SIZE,
} from "./mlDsaBase.ts";
import type { MlDsaParams } from "./params.ts";
import {
  bitPack,
  bitUnpack,
  exceeds,
  highBits,
  invNtt,
  lowBits,
  makeHint,
  matrixRowMul,
  newPolyVec,
  ntt,
  pointwiseMul,
  type Poly,
  reduce,
  simpleBitPack,
  zeroPolyVec,
} from "./poly.ts";
import { assertBytes } from "./utils.ts";

const RHO_PRIME_SIZE = 64; // rho' and rho''

/**
 * Key generation and signing of ML-DSA.
 *
 * Use one of the factory functions to create an initialized instance:
 * `createMlDsa44Signer`, `createMlDsa65Signer` or `createMlDsa87Signer`.
 */
export class MlDsaSigner extends MlDsaBase implements MlDsaSignerInterface {
  protected _api: Crypto;

  constructor(params: MlDsaParams, api: Crypto) {
    super(params);
    this._api = api;
  }

  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array] {
    const xi = new Uint8Array(SEED_SIZE);
    try {
      this._api.getRandomValues(xi);
      return this._keyGenInternal(xi);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    } finally {
      // xi recovers the whole private key, so do not leave it behind
      xi.fill(0);
    }
  }

  /** Derives a keypair [publicKey, privateKey] deterministically from a 32-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      assertBytes(seed, "seed");
      if (seed.byteLength !== SEED_SIZE) {
        throw new Error("seed must be 32 bytes in length");
      }
      return this._keyGenInternal(seed);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    }
  }

  /** Signs a message: returns signature. */
  sign(sk: Uint8Array, msg: Uint8Array, opts?: MlDsaSignOptions): Uint8Array {
    let generated: Uint8Array | undefined;
    const mu = new Uint8Array(MU_SIZE);
    try {
      assertBytes(sk, "sk");
      if (sk.byteLength !== this._skSize) {
        throw new Error("invalid private key");
      }
      assertBytes(msg, "msg");
      const ctx = this._checkContext(opts?.context);
      let rnd = opts?.seed;
      if (rnd === undefined) {
        rnd = generated = new Uint8Array(SEED_SIZE);
        this._api.getRandomValues(rnd);
      } else {
        assertBytes(rnd, "seed");
        if (rnd.byteLength !== SEED_SIZE) {
          throw new Error("seed must be 32 bytes in length");
        }
      }
      const tr = sk.subarray(2 * SEED_SIZE, 2 * SEED_SIZE + TR_SIZE);
      this._computeMu(mu, tr, msg, ctx);
      return this._signMu(sk, mu, rnd);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    } finally {
      // only wipe a value we generated; a supplied seed belongs to the caller
      generated?.fill(0);
      mu.fill(0);
      this._zeroHashes();
    }
  }

  /** @internal */
  // deno-lint-ignore require-await
  static async _create(params: MlDsaParams): Promise<MlDsaSigner> {
    if (globalThis.crypto === undefined) {
      throw new Error("Web Crypto API is not available");
    }
    return new MlDsaSigner(params, globalThis.crypto);
  }

  /**
   * ML-DSA.KeyGen_internal (FIPS 204, Algorithm 6).
   *
   * @param xi A 32-octet seed.
   * @returns A keypair [publicKey, privateKey].
   */
  private _keyGenInternal(xi: Uint8Array): [Uint8Array, Uint8Array] {
    const k = this._k;
    const l = this._l;
    const seeds = new Uint8Array(2 * SEED_SIZE + RHO_PRIME_SIZE);
    const s1 = newPolyVec(l);
    const s1Hat = newPolyVec(l);
    const s2 = newPolyVec(k);
    const t0 = newPolyVec(k);
    const t = new Int32Array(N);
    try {
      this._h(seeds, xi, Uint8Array.of(k, l));
      const rho = seeds.subarray(0, SEED_SIZE);
      const rhoPrime = seeds.subarray(SEED_SIZE, SEED_SIZE + RHO_PRIME_SIZE);
      const key = seeds.subarray(SEED_SIZE + RHO_PRIME_SIZE);

      const a = this._expandA(rho);
      for (let i = 0; i < l; i++) {
        this._rejBoundedPoly(s1[i], rhoPrime, i);
        s1Hat[i].set(s1[i]);
        ntt(s1Hat[i]);
      }
      for (let i = 0; i < k; i++) {
        this._rejBoundedPoly(s2[i], rhoPrime, l + i);
      }

      const pk = new Uint8Array(this._pkSize);
      const sk = new Uint8Array(this._skSize);
      pk.set(rho, 0);
      const t1 = new Int32Array(N);
      for (let i = 0; i < k; i++) {
        // t = NTT^-1(A * NTT(s1)) + s2
        matrixRowMul(t, a[i], s1Hat);
        reduce(t);
        invNtt(t);
        for (let j = 0; j < N; j++) {
          let v = t[j] + s2[i][j];
          v += (v >> 31) & Q;
          // Power2Round
          const hi = (v + (1 << (D - 1)) - 1) >> D;
          t1[j] = hi;
          t0[i][j] = v - (hi << D);
        }
        simpleBitPack(pk, SEED_SIZE + i * T1_POLY_SIZE, t1, T1_BITS);
      }

      let off = 0;
      sk.set(rho, off);
      off += SEED_SIZE;
      sk.set(key, off);
      off += SEED_SIZE;
      this._h(sk.subarray(off, off + TR_SIZE), pk);
      off += TR_SIZE;
      for (let i = 0; i < l; i++) {
        bitPack(sk, off, s1[i], this._etaBits, this._eta);
        off += this._etaPolySize;
      }
      for (let i = 0; i < k; i++) {
        bitPack(sk, off, s2[i], this._etaBits, this._eta);
        off += this._etaPolySize;
      }
      for (let i = 0; i < k; i++) {
        bitPack(sk, off, t0[i], D, 1 << (D - 1));
        off += T0_POLY_SIZE;
      }
      return [pk, sk];
    } finally {
      seeds.fill(0);
      t.fill(0);
      zeroPolyVec(s1);
      zeroPolyVec(s1Hat);
      zeroPolyVec(s2);
      zeroPolyVec(t0);
      this._zeroHashes();
    }
  }

  /**
   * The main part of ML-DSA.Sign_internal (FIPS 204, Algorithm 7), starting
   * from the message representative mu.
   *
   * The caller must have validated the length of the arguments.
   * @internal
   */
  protected _signMu(
    sk: Uint8Array,
    mu: Uint8Array,
    rnd: Uint8Array,
  ): Uint8Array {
    const k = this._k;
    const l = this._l;
    const gamma1 = this._gamma1;
    const gamma2 = this._gamma2;
    const beta = this._beta;

    const s1 = newPolyVec(l);
    const s2 = newPolyVec(k);
    const t0 = newPolyVec(k);
    const y = newPolyVec(l);
    const yHat = newPolyVec(l);
    const z = newPolyVec(l);
    const w0 = newPolyVec(k);
    const w1 = newPolyVec(k);
    const hints = newPolyVec(k);
    const c = new Int32Array(N);
    const tmp = new Int32Array(N);
    const rhoPP = new Uint8Array(RHO_PRIME_SIZE);
    const maskBuf = new Uint8Array(this._zPolySize);
    const w1Packed = new Uint8Array(k * this._w1PolySize);
    const cTilde = new Uint8Array(this._cTildeSize);
    try {
      // skDecode
      const rho = sk.subarray(0, SEED_SIZE);
      const key = sk.subarray(SEED_SIZE, 2 * SEED_SIZE);
      let off = 2 * SEED_SIZE + TR_SIZE;
      let bad = 0;
      for (let i = 0; i < l; i++) {
        bad |= bitUnpack(s1[i], sk, off, this._etaBits, this._eta);
        off += this._etaPolySize;
      }
      for (let i = 0; i < k; i++) {
        bad |= bitUnpack(s2[i], sk, off, this._etaBits, this._eta);
        off += this._etaPolySize;
      }
      if (bad !== 0) {
        throw new Error("invalid private key");
      }
      for (let i = 0; i < k; i++) {
        bitUnpack(t0[i], sk, off, D, 1 << (D - 1));
        off += T0_POLY_SIZE;
      }
      for (let i = 0; i < l; i++) ntt(s1[i]);
      for (let i = 0; i < k; i++) {
        ntt(s2[i]);
        ntt(t0[i]);
      }
      const a = this._expandA(rho);

      // rho'' = H(K || rnd || mu, 64)
      this._h(rhoPP, key, rnd, mu);

      for (let kappa = 0;; kappa += l) {
        // y = ExpandMask(rho'', kappa)
        for (let i = 0; i < l; i++) {
          this._nonceBuf[0] = (kappa + i) & 0xFF;
          this._nonceBuf[1] = ((kappa + i) >> 8) & 0xFF;
          this._h(maskBuf, rhoPP, this._nonceBuf);
          bitUnpack(y[i], maskBuf, 0, this._zBits, gamma1);
          yHat[i].set(y[i]);
          ntt(yHat[i]);
        }

        // w = NTT^-1(A * NTT(y)), (w1, w0) = Decompose(w)
        for (let i = 0; i < k; i++) {
          matrixRowMul(tmp, a[i], yHat);
          reduce(tmp);
          invNtt(tmp);
          for (let j = 0; j < N; j++) {
            const w = tmp[j] + ((tmp[j] >> 31) & Q);
            const hi = highBits(w, gamma2);
            w1[i][j] = hi;
            w0[i][j] = lowBits(w, hi, gamma2);
          }
          simpleBitPack(w1Packed, i * this._w1PolySize, w1[i], this._w1Bits);
        }

        // c~ = H(mu || w1Encode(w1), lambda / 4)
        this._h(cTilde, mu, w1Packed);
        this._sampleInBall(c, cTilde);
        ntt(c);

        // z = y + c * s1
        let rejected = false;
        for (let i = 0; i < l && !rejected; i++) {
          pointwiseMul(tmp, c, s1[i]);
          invNtt(tmp);
          for (let j = 0; j < N; j++) z[i][j] = tmp[j] + y[i][j];
          reduce(z[i]);
          rejected = exceeds(z[i], gamma1 - beta);
        }
        if (rejected) continue;

        // r0 = LowBits(w - c * s2)
        for (let i = 0; i < k && !rejected; i++) {
          pointwiseMul(tmp, c, s2[i]);
          invNtt(tmp);
          for (let j = 0; j < N; j++) w0[i][j] -= tmp[j];
          reduce(w0[i]);
          rejected = exceeds(w0[i], gamma2 - beta);
        }
        if (rejected) continue;

        // h = MakeHint(-c * t0, w - c * s2 + c * t0)
        let hintCount = 0;
        for (let i = 0; i < k && !rejected; i++) {
          pointwiseMul(tmp, c, t0[i]);
          invNtt(tmp);
          reduce(tmp);
          rejected = exceeds(tmp, gamma2);
          if (rejected) break;
          for (let j = 0; j < N; j++) {
            const hint = makeHint(w0[i][j] + tmp[j], w1[i][j], gamma2);
            hints[i][j] = hint;
            hintCount += hint;
          }
        }
        if (rejected || hintCount > this._omega) continue;

        // sigEncode
        const sig = new Uint8Array(this._sigSize);
        sig.set(cTilde, 0);
        off = this._cTildeSize;
        for (let i = 0; i < l; i++) {
          bitPack(sig, off, z[i], this._zBits, gamma1);
          off += this._zPolySize;
        }
        let index = 0;
        for (let i = 0; i < k; i++) {
          for (let j = 0; j < N; j++) {
            if (hints[i][j] !== 0) sig[off + index++] = j;
          }
          sig[off + this._omega + i] = index;
        }
        return sig;
      }
    } finally {
      zeroPolyVec(s1);
      zeroPolyVec(s2);
      zeroPolyVec(t0);
      zeroPolyVec(y);
      zeroPolyVec(yHat);
      zeroPolyVec(z);
      zeroPolyVec(w0);
      zeroPolyVec(w1);
      c.fill(0);
      tmp.fill(0);
      rhoPP.fill(0);
      maskBuf.fill(0);
      w1Packed.fill(0);
      this._zeroHashes();
    }
  }

  // RejBoundedPoly (FIPS 204, Algorithm 31)
  private _rejBoundedPoly(
    out: Poly,
    rhoPrime: Uint8Array,
    nonce: number,
  ): void {
    const buf = this._block256;
    const eta = this._eta;
    this._nonceBuf[0] = nonce & 0xFF;
    this._nonceBuf[1] = nonce >> 8;
    this._shake256.reset();
    this._shake256.updateUnsafe(rhoPrime).updateUnsafe(this._nonceBuf);
    let ctr = 0;
    while (ctr < N) {
      this._shake256.writeIntoUnsafe(buf);
      for (let pos = 0; pos < SHAKE256_RATE && ctr < N; pos++) {
        let t0 = buf[pos] & 0x0F;
        let t1 = buf[pos] >> 4;
        if (eta === 2) {
          if (t0 < 15) {
            t0 -= ((205 * t0) >>> 10) * 5; // t0 mod 5
            out[ctr++] = 2 - t0;
          }
          if (t1 < 15 && ctr < N) {
            t1 -= ((205 * t1) >>> 10) * 5;
            out[ctr++] = 2 - t1;
          }
        } else {
          if (t0 < 9) {
            out[ctr++] = 4 - t0;
          }
          if (t1 < 9 && ctr < N) {
            out[ctr++] = 4 - t1;
          }
        }
      }
    }
  }
}
