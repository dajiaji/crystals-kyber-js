/**
 * This implementation follows NIST FIPS 204 and the structure of the reference
 * implementation at https://github.com/pq-crystals/dilithium (public domain /
 * Apache-2.0).
 */
import { Keccak } from "./deps.ts";

import { D, INV_NTT_F, N, NTT_ZETAS, Q, Q_INV } from "./consts.ts";
import type { MlDsaSignOptions, MlDsaVerifyOptions } from "./interfaces.ts";

type Poly = Int32Array;

const SHAKE128_RATE = 168;
const SHAKE256_RATE = 136;

const SEED_SIZE = 32; // xi, rho, K and rnd
const RHO_PRIME_SIZE = 64; // rho' and rho''
const TR_SIZE = 64;
const MU_SIZE = 64;
const T1_BITS = 10;
const T1_POLY_SIZE = N * T1_BITS / 8;
const T0_POLY_SIZE = N * D / 8;
const MAX_CONTEXT_SIZE = 255;

/**
 * Represents the base class for the ML-DSA digital signature algorithm.
 *
 * This class is not intended to be used directly. Instead, use one of the
 * factory functions: `createMlDsa44`, `createMlDsa65` or `createMlDsa87`.
 */
export class MlDsaBase {
  protected _api: Crypto | undefined = undefined;
  // Parameters to be set by subclasses (FIPS 204, Table 1).
  protected _k = 0;
  protected _l = 0;
  protected _eta = 0;
  protected _tau = 0;
  protected _gamma1Bits = 0; // gamma1 = 2^_gamma1Bits
  protected _gamma2 = 0;
  protected _omega = 0;
  protected _cTildeSize = 0; // lambda / 4
  // Derived values (see _init).
  protected _gamma1 = 0;
  protected _beta = 0;
  protected _etaPolySize = 0;
  protected _zPolySize = 0;
  protected _w1PolySize = 0;
  protected _pkSize = 0;
  protected _skSize = 0;
  protected _sigSize = 0;

  private _etaBits = 0;
  private _zBits = 0;
  private _w1Bits = 0;
  // Keccak instances (reset before each use).
  private _shake128 = new Keccak(SHAKE128_RATE, 0x1f, 32, true);
  private _shake256 = new Keccak(SHAKE256_RATE, 0x1f, 32, true);
  private _block128 = new Uint8Array(SHAKE128_RATE);
  private _block256 = new Uint8Array(SHAKE256_RATE);
  private _nonceBuf = new Uint8Array(2);

  /**
   * Creates a new instance of the MlDsaBase class.
   */
  constructor() {}

  /**
   * Computes the values derived from the parameter set.
   * Subclasses must call this at the end of their constructor.
   */
  protected _init(): void {
    this._gamma1 = 1 << this._gamma1Bits;
    this._beta = this._tau * this._eta;
    this._etaBits = this._eta === 2 ? 3 : 4;
    this._zBits = this._gamma1Bits + 1;
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
   * Sets up the MlDsaBase instance by loading the necessary crypto library.
   * If the crypto library is already loaded, this method does nothing.
   * @returns {Promise<void>} A promise that resolves when the setup is complete.
   */
  // deno-lint-ignore require-await
  protected async _setup(): Promise<void> {
    if (this._api !== undefined) {
      return;
    }
    if (globalThis.crypto === undefined) {
      throw new Error("Web Crypto API is not available");
    }
    this._api = globalThis.crypto;
  }

  protected _generateKeyPairCore(): [Uint8Array, Uint8Array] {
    const xi = new Uint8Array(SEED_SIZE);
    try {
      (this._api as Crypto).getRandomValues(xi);
      return this._keyGenInternal(xi);
    } finally {
      // xi recovers the whole private key, so do not leave it behind
      xi.fill(0);
    }
  }

  protected _deriveKeyPairCore(seed: Uint8Array): [Uint8Array, Uint8Array] {
    assertBytes(seed, "seed");
    if (seed.byteLength !== SEED_SIZE) {
      throw new Error("seed must be 32 bytes in length");
    }
    return this._keyGenInternal(seed);
  }

  protected _signCore(
    sk: Uint8Array,
    msg: Uint8Array,
    opts?: MlDsaSignOptions,
  ): Uint8Array {
    this._checkPrivateKey(sk);
    assertBytes(msg, "msg");
    const ctx = this._checkContext(opts?.context);
    const seed = opts?.seed;
    if (seed !== undefined) {
      assertBytes(seed, "seed");
      if (seed.byteLength !== SEED_SIZE) {
        throw new Error("seed must be 32 bytes in length");
      }
    }
    const rnd = seed ?? new Uint8Array(SEED_SIZE);
    const mu = new Uint8Array(MU_SIZE);
    try {
      if (seed === undefined) {
        (this._api as Crypto).getRandomValues(rnd);
      }
      const tr = sk.subarray(2 * SEED_SIZE, 2 * SEED_SIZE + TR_SIZE);
      this._computeMu(mu, tr, msg, ctx);
      return this._signMu(sk, mu, rnd);
    } finally {
      // only wipe a value we generated; a supplied seed belongs to the caller
      if (rnd !== seed) rnd.fill(0);
      mu.fill(0);
      this._zeroHashes();
    }
  }

  protected _verifyCore(
    pk: Uint8Array,
    sig: Uint8Array,
    msg: Uint8Array,
    opts?: MlDsaVerifyOptions,
  ): boolean {
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
    const mu = new Uint8Array(MU_SIZE);
    try {
      this._h(tr, pk);
      this._computeMu(mu, tr, msg, ctx);
      return this._verifyMuCore(pk, mu, sig);
    } finally {
      // do not leave message-derived data behind, also on an early rejection
      mu.fill(0);
      this._zeroHashes();
    }
  }

  /**
   * ML-DSA.Sign_internal (FIPS 204, Algorithm 7) for a formatted message M'.
   * @internal
   */
  protected _signInternal(
    sk: Uint8Array,
    mPrime: Uint8Array,
    rnd: Uint8Array,
  ): Uint8Array {
    this._checkPrivateKey(sk);
    assertBytes(mPrime, "mPrime");
    const mu = new Uint8Array(MU_SIZE);
    try {
      this._h(mu, sk.subarray(2 * SEED_SIZE, 2 * SEED_SIZE + TR_SIZE), mPrime);
      return this._signMu(sk, mu, rnd);
    } finally {
      mu.fill(0);
      this._zeroHashes();
    }
  }

  /**
   * ML-DSA.Verify_internal (FIPS 204, Algorithm 8) for a formatted message M'.
   * @internal
   */
  protected _verifyInternal(
    pk: Uint8Array,
    sig: Uint8Array,
    mPrime: Uint8Array,
  ): boolean {
    assertBytes(pk, "pk");
    assertBytes(sig, "sig");
    assertBytes(mPrime, "mPrime");
    if (!this._hasValidSizes(pk, sig)) {
      return false;
    }
    const tr = new Uint8Array(TR_SIZE);
    const mu = new Uint8Array(MU_SIZE);
    try {
      this._h(tr, pk);
      this._h(mu, tr, mPrime);
      return this._verifyMuCore(pk, mu, sig);
    } finally {
      mu.fill(0);
      this._zeroHashes();
    }
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
   * @internal
   */
  protected _signMu(
    sk: Uint8Array,
    mu: Uint8Array,
    rnd: Uint8Array,
  ): Uint8Array {
    this._checkPrivateKey(sk);
    assertBytes(mu, "mu");
    assertBytes(rnd, "rnd");
    if (mu.byteLength !== MU_SIZE) {
      throw new Error("mu must be 64 bytes in length");
    }
    if (rnd.byteLength !== SEED_SIZE) {
      throw new Error("rnd must be 32 bytes in length");
    }
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

  /**
   * The main part of ML-DSA.Verify_internal (FIPS 204, Algorithm 8), starting
   * from the message representative mu.
   * @internal
   */
  protected _verifyMu(
    pk: Uint8Array,
    mu: Uint8Array,
    sig: Uint8Array,
  ): boolean {
    assertBytes(pk, "pk");
    assertBytes(sig, "sig");
    assertBytes(mu, "mu");
    if (mu.byteLength !== MU_SIZE) {
      throw new Error("mu must be 64 bytes in length");
    }
    if (!this._hasValidSizes(pk, sig)) {
      return false;
    }
    try {
      return this._verifyMuCore(pk, mu, sig);
    } finally {
      this._zeroHashes();
    }
  }

  // Verifies a signature for mu. The caller must have validated the
  // arguments, and must call _zeroHashes() afterwards.
  private _verifyMuCore(
    pk: Uint8Array,
    mu: Uint8Array,
    sig: Uint8Array,
  ): boolean {
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

  /**
   * Computes mu = H(tr || 0 || |ctx| || ctx || M, 64), the message
   * representative for the pure ML-DSA (FIPS 204, Algorithm 2 and 7).
   */
  private _computeMu(
    out: Uint8Array,
    tr: Uint8Array,
    msg: Uint8Array,
    ctx: Uint8Array,
  ): void {
    this._h(out, tr, Uint8Array.of(0, ctx.byteLength), ctx, msg);
  }

  private _checkContext(ctx?: Uint8Array): Uint8Array {
    if (ctx === undefined) {
      return new Uint8Array(0);
    }
    assertBytes(ctx, "context");
    if (ctx.byteLength > MAX_CONTEXT_SIZE) {
      throw new Error("context must be at most 255 bytes in length");
    }
    return ctx;
  }

  private _hasValidSizes(pk: Uint8Array, sig: Uint8Array): boolean {
    return pk.byteLength === this._pkSize && sig.byteLength === this._sigSize;
  }

  private _checkPrivateKey(sk: Uint8Array): void {
    assertBytes(sk, "sk");
    if (sk.byteLength !== this._skSize) {
      throw new Error("invalid private key");
    }
  }

  // H: SHAKE256 over the concatenation of `inputs`, filling `out`.
  private _h(out: Uint8Array, ...inputs: Uint8Array[]): void {
    this._shake256.reset();
    for (let i = 0; i < inputs.length; i++) {
      this._shake256.updateUnsafe(inputs[i]);
    }
    this._shake256.writeIntoUnsafe(out);
  }

  private _zeroHashes(): void {
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
  private _expandA(rho: Uint8Array): Poly[][] {
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
  private _rejNttPoly(out: Poly, rho: Uint8Array, s: number, r: number): void {
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

  // SampleInBall (FIPS 204, Algorithm 29)
  private _sampleInBall(c: Poly, cTilde: Uint8Array): void {
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

/**
 * The getter of %TypedArray%.prototype[Symbol.toStringTag], which returns the
 * built-in type name of a typed array and undefined for anything else. Unlike
 * `instanceof` or `constructor.name`, it also identifies a Uint8Array, or an
 * instance of its subclass, which was created in another realm (an iframe or
 * node:vm), and it cannot be overridden by the value.
 */
const typedArrayName = /* @__PURE__ */ (() =>
  Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    Symbol.toStringTag,
  )!.get as (this: unknown) => string | undefined)();

/**
 * Asserts that an argument is a Uint8Array. Another type such as ArrayBuffer
 * has `byteLength` but no elements to read, so it would be hashed as empty.
 */
function assertBytes(value: unknown, name: string): void {
  if (typedArrayName.call(value) !== "Uint8Array") {
    throw new Error(`${name} must be a Uint8Array`);
  }
}

function newPolyVec(size: number): Poly[] {
  const v = new Array<Poly>(size);
  for (let i = 0; i < size; i++) {
    v[i] = new Int32Array(N);
  }
  return v;
}

function zeroPolyVec(v: Poly[]): void {
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
function montgomeryMul(a: number, b: number): number {
  const t = Math.imul(Math.imul(a, b), Q_INV);
  // a * b and t * Q agree in their low 32 bits, so the high halves subtract
  // without a borrow.
  return mulHi(a, b) - mulHi(t, Q);
}

// Reduces each coefficient to a representative in about [-6283009, 6283008].
function reduce(a: Poly): void {
  for (let i = 0; i < N; i++) {
    a[i] -= Math.imul((a[i] + (1 << 22)) >> 23, Q);
  }
}

/**
 * In-place forward NTT. The output coefficients grow by at most 8 * Q in
 * absolute value.
 */
function ntt(a: Poly): void {
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
function invNtt(a: Poly): void {
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
function pointwiseMul(out: Poly, a: Poly, b: Poly): void {
  for (let i = 0; i < N; i++) {
    out[i] = montgomeryMul(a[i], b[i]);
  }
}

// out = sum_j row[j] * v[j] in the NTT domain (Montgomery).
function matrixRowMul(out: Poly, row: Poly[], v: Poly[]): void {
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
function exceeds(a: Poly, bound: number): boolean {
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
function highBits(a: number, gamma2: number): number {
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
function lowBits(a: number, a1: number, gamma2: number): number {
  let a0 = a - a1 * 2 * gamma2;
  a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
  return a0;
}

// MakeHint (FIPS 204, Algorithm 39), from the low and the high bits.
function makeHint(a0: number, a1: number, gamma2: number): number {
  return (a0 > gamma2 || a0 < -gamma2 || (a0 === -gamma2 && a1 !== 0)) ? 1 : 0;
}

// UseHint (FIPS 204, Algorithm 40) for a in [0, Q). Works on public data.
function useHint(a: number, hint: number, gamma2: number): number {
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
function simpleBitPack(
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
function simpleBitUnpack(
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
function bitPack(
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
function bitUnpack(
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
