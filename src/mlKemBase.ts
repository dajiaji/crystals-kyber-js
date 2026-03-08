/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { Keccak } from "./deps.ts";

import { N, NTT_ZETAS, NTT_ZETAS_INV, Q, Q_INV } from "./consts.ts";
import {
  byte,
  byteopsLoad32,
  constantTimeCompare,
  equalUint8Array,
  int16,
  loadCrypto,
  uint16,
} from "./utils.ts";

/**
 * Represents the base class for the ML-KEM key encapsulation mechanism.
 *
 * This class provides the base implementation for the ML-KEM key encapsulation mechanism.
 *
 * @remarks
 *
 * This class is not intended to be used directly. Instead, use one of the subclasses:
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKemBase } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKemBase } from "mlkem"; // or "crystals-kyber-js"
 *
 * class MlKem768 extends MlKemBase {
 *   protected _k = 3;
 *   protected _du = 10;
 *   protected _dv = 4;
 *   protected _eta1 = 2;
 *   protected _eta2 = 2;
 *
 *   constructor() {
 *     super();
 *     this._skSize = 12 * this._k * N / 8;
 *     this._pkSize = this._skSize + 32;
 *     this._compressedUSize = this._k * this._du * N / 8;
 *     this._compressedVSize = this._dv * N / 8;
 *   }
 * }
 *
 * const kyber = new MlKem768();
 * ```
 */
export class MlKemBase {
  protected _api: Crypto | undefined = undefined;
  protected _k = 0;
  protected _du = 0;
  protected _dv = 0;
  protected _eta1 = 0;
  protected _eta2 = 0;
  protected _skSize = 0;
  protected _pkSize = 0;
  protected _compressedUSize = 0;
  protected _compressedVSize = 0;

  // Keccak templates (immutable after _initPool)
  private _tplG!: Keccak;
  private _tplH!: Keccak;
  private _tplKdf!: Keccak;
  private _tplXof!: Keccak;
  private _tplPrf1!: Keccak;
  private _tplPrf2!: Keccak;
  // Keccak pool instances (cloned from templates before each use)
  private _poolG!: Keccak;
  private _poolH!: Keccak;
  private _poolKdf!: Keccak;
  private _poolXof!: Keccak;
  private _poolPrf1!: Keccak;
  private _poolPrf2!: Keccak;
  // Pre-allocated output buffers
  private _bufG = new Uint8Array(64);
  private _bufH = new Uint8Array(32);
  private _bufKdf = new Uint8Array(32);
  private _bufXof = new Uint8Array(672);
  private _bufPrf1!: Uint8Array;
  private _bufPrf2!: Uint8Array;
  private _nonceBuf = new Uint8Array(1);
  private _xofSeed = new Uint8Array(34);
  private _kBuf!: Uint8Array;

  /**
   * Creates a new instance of the MlKemBase class.
   */
  constructor() {}

  protected _initPool(): void {
    // sha3_512: blockLen=72, suffix=0x06, outputLen=64
    this._tplG = new Keccak(72, 0x06, 64);
    this._poolG = this._tplG.clone();
    // sha3_256: blockLen=136, suffix=0x06, outputLen=32
    this._tplH = new Keccak(136, 0x06, 32);
    this._poolH = this._tplH.clone();
    // shake256: blockLen=136, suffix=0x1f, dkLen=32, enableXOF
    this._tplKdf = new Keccak(136, 0x1f, 32, true);
    this._poolKdf = this._tplKdf.clone();
    // shake128: blockLen=168, suffix=0x1f, dkLen=672, enableXOF
    this._tplXof = new Keccak(168, 0x1f, 672, true);
    this._poolXof = this._tplXof.clone();
    // shake256 for prf with eta1
    const prf1Len = this._eta1 * N / 4;
    this._tplPrf1 = new Keccak(136, 0x1f, prf1Len, true);
    this._poolPrf1 = this._tplPrf1.clone();
    this._bufPrf1 = new Uint8Array(prf1Len);
    // shake256 for prf with eta2
    const prf2Len = this._eta2 * N / 4;
    this._tplPrf2 = new Keccak(136, 0x1f, prf2Len, true);
    this._poolPrf2 = this._tplPrf2.clone();
    this._bufPrf2 = new Uint8Array(prf2Len);
    // constant buffer for k parameter
    this._kBuf = new Uint8Array([this._k]);
  }

  protected _zeroPool(): void {
    this._bufG.fill(0);
    this._bufH.fill(0);
    this._bufKdf.fill(0);
    this._bufXof.fill(0);
    this._bufPrf1.fill(0);
    this._bufPrf2.fill(0);
    this._nonceBuf[0] = 0;
    this._xofSeed.fill(0);
    this._poolG.destroy();
    this._poolH.destroy();
    this._poolKdf.destroy();
    this._poolXof.destroy();
    this._poolPrf1.destroy();
    this._poolPrf2.destroy();
  }

  // Hash G: SHA3-512
  private _g(a: Uint8Array, b?: Uint8Array): [Uint8Array, Uint8Array] {
    this._tplG._cloneInto(this._poolG);
    this._poolG.update(a);
    if (b !== undefined) this._poolG.update(b);
    this._poolG.digestInto(this._bufG);
    return [this._bufG.subarray(0, 32), this._bufG.subarray(32, 64)];
  }

  // Hash H: SHA3-256
  private _h(msg: Uint8Array): Uint8Array {
    this._tplH._cloneInto(this._poolH);
    this._poolH.update(msg).digestInto(this._bufH);
    return this._bufH;
  }

  // KDF: SHAKE256(dkLen=32)
  private _kdf(a: Uint8Array, b?: Uint8Array): Uint8Array {
    this._tplKdf._cloneInto(this._poolKdf);
    this._poolKdf.update(a);
    if (b !== undefined) this._poolKdf.update(b);
    this._poolKdf.digestInto(this._bufKdf);
    return this._bufKdf;
  }

  // XOF: SHAKE128(dkLen=672)
  private _xof(seed: Uint8Array): Uint8Array {
    this._tplXof._cloneInto(this._poolXof);
    this._poolXof.update(seed).digestInto(this._bufXof);
    return this._bufXof;
  }

  // PRF for eta1 noise sampling: SHAKE256(dkLen=eta1*N/4)
  protected _prf1(sigma: Uint8Array, nonce: number): Uint8Array {
    this._nonceBuf[0] = nonce;
    this._tplPrf1._cloneInto(this._poolPrf1);
    this._poolPrf1.update(sigma).update(this._nonceBuf).digestInto(
      this._bufPrf1,
    );
    return this._bufPrf1;
  }

  // PRF for eta2 noise sampling: SHAKE256(dkLen=eta2*N/4)
  private _prf2(sigma: Uint8Array, nonce: number): Uint8Array {
    this._nonceBuf[0] = nonce;
    this._tplPrf2._cloneInto(this._poolPrf2);
    this._poolPrf2.update(sigma).update(this._nonceBuf).digestInto(
      this._bufPrf2,
    );
    return this._bufPrf2;
  }

  protected _generateKeyPairCore(): [Uint8Array, Uint8Array] {
    try {
      const rnd = new Uint8Array(64);
      (this._api as Crypto).getRandomValues(rnd);
      return this._deriveKeyPair(rnd);
    } finally {
      this._zeroPool();
    }
  }

  protected _deriveKeyPairCore(seed: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      if (seed.byteLength !== 64) {
        throw new Error("seed must be 64 bytes in length");
      }
      return this._deriveKeyPair(seed);
    } finally {
      this._zeroPool();
    }
  }

  protected _encapCore(
    pk: Uint8Array,
    seed?: Uint8Array,
  ): [Uint8Array, Uint8Array] {
    try {
      // validate key type; the modulo is checked in `_encap`.
      if (pk.length !== 384 * this._k + 32) {
        throw new Error("invalid encapsulation key");
      }
      const m = this._getSeed(seed);
      const [k, r] = this._g(m, this._h(pk));
      const ct = this._encap(pk, m, r);
      return [ct, k.slice()];
    } finally {
      this._zeroPool();
    }
  }

  protected _decapCore(ct: Uint8Array, sk: Uint8Array): Uint8Array {
    try {
      // ciphertext type check
      if (ct.byteLength !== this._compressedUSize + this._compressedVSize) {
        throw new Error("Invalid ct size");
      }
      // decapsulation key type check
      if (sk.length !== 768 * this._k + 96) {
        throw new Error("Invalid decapsulation key");
      }
      const sk2 = sk.subarray(0, this._skSize);
      const pk = sk.subarray(this._skSize, this._skSize + this._pkSize);
      const hpk = sk.subarray(
        this._skSize + this._pkSize,
        this._skSize + this._pkSize + 32,
      );
      const z = sk.subarray(
        this._skSize + this._pkSize + 32,
        this._skSize + this._pkSize + 64,
      );

      const m2 = this._decap(ct, sk2);
      const [k2, r2] = this._g(m2, hpk);
      const kBar = this._kdf(z, ct);
      const ct2 = this._encap(pk, m2, r2);
      return constantTimeCompare(ct, ct2) === 1 ? k2.slice() : kBar.slice();
    } finally {
      this._zeroPool();
    }
  }

  /**
   * Sets up the MlKemBase instance by loading the necessary crypto library.
   * If the crypto library is already loaded, this method does nothing.
   * @returns {Promise<void>} A promise that resolves when the setup is complete.
   */
  protected async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadCrypto();
  }

  /**
   * Returns a Uint8Array seed for cryptographic operations.
   * If no seed is provided, a random seed of length 32 bytes is generated.
   * If a seed is provided, it must be exactly 32 bytes in length.
   *
   * @param seed - Optional seed for cryptographic operations.
   * @returns A Uint8Array seed.
   * @throws Error if the provided seed is not 32 bytes in length.
   */
  private _getSeed(seed?: Uint8Array): Uint8Array {
    if (seed == undefined) {
      const s = new Uint8Array(32);
      (this._api as Crypto).getRandomValues(s);
      return s;
    }
    if (seed.byteLength !== 32) {
      throw new Error("seed must be 32 bytes in length");
    }
    return seed;
  }

  /**
   * Derives a key pair from a given seed.
   *
   * @param seed - The seed used for key derivation.
   * @returns An array containing the public key and secret key.
   */
  private _deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array] {
    const cpaSeed = seed.subarray(0, 32);
    const z = seed.subarray(32, 64);

    const [pk, skBody] = this._deriveCpaKeyPair(cpaSeed);

    const pkh = this._h(pk);
    const sk = new Uint8Array(this._skSize + this._pkSize + 64);
    sk.set(skBody, 0);
    sk.set(pk, this._skSize);
    sk.set(pkh, this._skSize + this._pkSize);
    sk.set(z, this._skSize + this._pkSize + 32);
    return [pk, sk];
  }

  // indcpaKeyGen generates public and private keys for the CPA-secure
  // public-key encryption scheme underlying ML-KEM.

  /**
   * Derives a CPA key pair using the provided CPA seed.
   *
   * @param cpaSeed - The CPA seed used for key derivation.
   * @returns An array containing the public key and private key.
   */
  private _deriveCpaKeyPair(cpaSeed: Uint8Array): [Uint8Array, Uint8Array] {
    const [publicSeed, noiseSeed] = this._g(cpaSeed, this._kBuf);
    const a = this._sampleMatrix(publicSeed, false);
    const s = this._sampleNoise1(noiseSeed, 0, this._k);
    const e = this._sampleNoise1(noiseSeed, this._k, this._k);

    // perform number theoretic transform on secret s
    for (let i = 0; i < this._k; i++) {
      s[i] = ntt(s[i]);
      s[i] = reduce(s[i]);
      e[i] = ntt(e[i]);
    }

    // KEY COMPUTATION
    // pk = A*s + e
    const pk = new Array<Int16Array>(this._k);
    for (let i = 0; i < this._k; i++) {
      pk[i] = polyToMont(multiply(a[i], s));
      pk[i] = add(pk[i], e[i]);
      pk[i] = reduce(pk[i]);
    }

    // PUBLIC KEY
    // turn polynomials into byte arrays
    const pubKey = new Uint8Array(this._pkSize);
    for (let i = 0; i < this._k; i++) {
      pubKey.set(polyToBytes(pk[i]), i * 384);
    }
    // append public seed
    pubKey.set(publicSeed, this._skSize);

    // PRIVATE KEY
    // turn polynomials into byte arrays
    const privKey = new Uint8Array(this._skSize);
    for (let i = 0; i < this._k; i++) {
      privKey.set(polyToBytes(s[i]), i * 384);
    }
    return [pubKey, privKey];
  }

  // _encap is the encapsulation function of the CPA-secure
  // public-key encryption scheme underlying ML-KEM.

  /**
   * Encapsulates a message using the ML-KEM encryption scheme.
   *
   * @param pk - The public key.
   * @param msg - The message to be encapsulated.
   * @param seed - The seed used for generating random values.
   * @returns The encapsulated message as a Uint8Array.
   */
  private _encap(
    pk: Uint8Array,
    msg: Uint8Array,
    seed: Uint8Array,
  ): Uint8Array {
    const tHat = new Array<Int16Array>(this._k);
    const pkCheck = new Uint8Array(384 * this._k); // to validate the pk modulo (see input validation at NIST draft 6.2)
    for (let i = 0; i < this._k; i++) {
      tHat[i] = polyFromBytes(pk.subarray(i * 384, (i + 1) * 384));
      pkCheck.set(polyToBytes(tHat[i]), i * 384);
    }
    if (!equalUint8Array(pk.subarray(0, pkCheck.length), pkCheck)) {
      throw new Error("invalid encapsulation key");
    }
    const rho = pk.subarray(this._skSize);
    const a = this._sampleMatrix(rho, true);
    const r = this._sampleNoise1(seed, 0, this._k);
    const e1 = this._sampleNoise2(seed, this._k, this._k);
    const e2 = this._sampleNoise2(seed, this._k * 2, 1)[0];

    // perform number theoretic transform on random vector r
    for (let i = 0; i < this._k; i++) {
      r[i] = ntt(r[i]);
      r[i] = reduce(r[i]);
    }

    // u = A*r + e1
    const u = new Array<Int16Array>(this._k);
    for (let i = 0; i < this._k; i++) {
      u[i] = multiply(a[i], r);
      u[i] = nttInverse(u[i]);
      u[i] = add(u[i], e1[i]);
      u[i] = reduce(u[i]);
    }

    // v = tHat*r + e2 + m
    const m = polyFromMsg(msg);
    let v = multiply(tHat, r);
    v = nttInverse(v);
    v = add(v, e2);
    v = add(v, m);
    v = reduce(v);

    // compress
    const ret = new Uint8Array(this._compressedUSize + this._compressedVSize);
    this._compressU(ret.subarray(0, this._compressedUSize), u);
    this._compressV(ret.subarray(this._compressedUSize), v);
    return ret;
  }

  // indcpaDecrypt is the decryption function of the CPA-secure
  // public-key encryption scheme underlying ML-KEM.

  /**
   * Decapsulates the ciphertext using the provided secret key.
   *
   * @param ct - The ciphertext to be decapsulated.
   * @param sk - The secret key used for decapsulation.
   * @returns The decapsulated message as a Uint8Array.
   */
  private _decap(ct: Uint8Array, sk: Uint8Array): Uint8Array {
    // extract ciphertext
    const u = this._decompressU(ct.subarray(0, this._compressedUSize));
    const v = this._decompressV(ct.subarray(this._compressedUSize));

    const privateKeyPolyvec = this._polyvecFromBytes(sk);

    for (let i = 0; i < this._k; i++) {
      u[i] = ntt(u[i]);
    }

    let mp = multiply(privateKeyPolyvec, u);
    mp = nttInverse(mp);
    mp = subtract(v, mp);
    mp = reduce(mp);
    return polyToMsg(mp);
  }

  // generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
  // from a seed. Entries of the matrix are polynomials that look uniformly random.
  // Performs rejection sampling on the output of an extendable-output function (XOF).

  /**
   * Generates a sample matrix based on the provided seed and transposition flag.
   *
   * @param seed - The seed used for generating the matrix.
   * @param transposed - A flag indicating whether the matrix should be transposed or not.
   * @returns The generated sample matrix.
   */
  private _sampleMatrix(
    seed: Uint8Array,
    transposed: boolean,
  ): Array<Array<Int16Array>> {
    const a = new Array<Array<Int16Array>>(this._k);
    this._xofSeed.set(seed);

    for (let ctr = 0, i = 0; i < this._k; i++) {
      a[i] = new Array<Int16Array>(this._k);

      for (let j = 0; j < this._k; j++) {
        // set if transposed matrix or not
        if (transposed) {
          this._xofSeed[seed.length] = i;
          this._xofSeed[seed.length + 1] = j;
        } else {
          this._xofSeed[seed.length] = j;
          this._xofSeed[seed.length + 1] = i;
        }
        const output = this._xof(this._xofSeed);

        // run rejection sampling on the output from above
        const result = indcpaRejUniform(output.subarray(0, 504), 504, N);
        a[i][j] = result[0]; // the result here is an NTT-representation
        ctr = result[1]; // keeps track of index of output array from sampling function

        while (ctr < N) { // if the polynomial hasnt been filled yet with mod q entries
          const outputn = output.subarray(504, 672); // take last 168 bytes of byte array from xof
          const result1 = indcpaRejUniform(outputn, 168, N - ctr); // run sampling function again
          const missing = result1[0]; // here is additional mod q polynomial coefficients
          const ctrn = result1[1]; // how many coefficients were accepted and are in the output
          // starting at last position of output array from first sampling function until 256 is reached
          for (let k = ctr; k < N; k++) {
            a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
          }
          ctr = ctr + ctrn; // update index
        }
      }
    }
    return a;
  }

  /**
   * Generates a 2D array of noise samples.
   *
   * @param sigma - The noise parameter.
   * @param offset - The offset value.
   * @param size - The size of the array.
   * @returns The generated 2D array of noise samples.
   */
  protected _sampleNoise1(
    sigma: Uint8Array,
    offset: number,
    size: number,
  ): Array<Int16Array> {
    const r = new Array<Int16Array>(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd(this._prf1(sigma, offset), this._eta1);
      offset++;
    }
    return r;
  }

  /**
   * Generates a 2-dimensional array of noise samples.
   *
   * @param sigma - The noise parameter.
   * @param offset - The offset value.
   * @param size - The size of the array.
   * @returns The generated 2-dimensional array of noise samples.
   */
  protected _sampleNoise2(
    sigma: Uint8Array,
    offset: number,
    size: number,
  ): Array<Int16Array> {
    const r = new Array<Int16Array>(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd(this._prf2(sigma, offset), this._eta2);
      offset++;
    }
    return r;
  }

  // polyvecFromBytes deserializes a vector of polynomials.

  /**
   * Converts a Uint8Array to a 2D array of numbers representing a polynomial vector.
   * Each element in the resulting array represents a polynomial.
   * @param a The Uint8Array to convert.
   * @returns The 2D array of numbers representing the polynomial vector.
   */
  private _polyvecFromBytes(a: Uint8Array): Array<Int16Array> {
    const r = new Array<Int16Array>(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = polyFromBytes(a.subarray(i * 384, (i + 1) * 384));
    }
    return r;
  }

  // compressU lossily compresses and serializes a vector of polynomials.

  /**
   * Compresses the given array of coefficients into a Uint8Array.
   *
   * @param r - The output Uint8Array.
   * @param u - The array of coefficients.
   * @returns The compressed Uint8Array.
   */
  protected _compressU(
    r: Uint8Array,
    u: Array<Int16Array>,
  ): Uint8Array {
    const t = new Array<number>(4);
    for (let rr = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        for (let k = 0; k < 4; k++) {
          // parse {0,...,3328} to {0,...,1023}
          t[k] = (((u[i][4 * j + k] << 10) + Q / 2) / Q) &
            0b1111111111;
        }
        // converts 4 12-bit coefficients {0,...,3328} to 5 8-bit bytes {0,...,255}
        // 48 bits down to 40 bits per block
        r[rr++] = byte(t[0] >> 0);
        r[rr++] = byte((t[0] >> 8) | (t[1] << 2));
        r[rr++] = byte((t[1] >> 6) | (t[2] << 4));
        r[rr++] = byte((t[2] >> 4) | (t[3] << 6));
        r[rr++] = byte(t[3] >> 2);
      }
    }
    return r;
  }

  // compressV lossily compresses and subsequently serializes a polynomial.

  /**
   * Compresses the given array of numbers into a Uint8Array.
   *
   * @param r - The Uint8Array to store the compressed values.
   * @param v - The array of numbers to compress.
   * @returns The compressed Uint8Array.
   */
  protected _compressV(r: Uint8Array, v: Int16Array): Uint8Array {
    // const r = new Uint8Array(128);
    const t = new Uint8Array(8);
    for (let rr = 0, i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        t[j] = byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 0b1111;
      }
      r[rr++] = t[0] | (t[1] << 4);
      r[rr++] = t[2] | (t[3] << 4);
      r[rr++] = t[4] | (t[5] << 4);
      r[rr++] = t[6] | (t[7] << 4);
    }
    return r;
  }

  // decompressU de-serializes and decompresses a vector of polynomials and
  // represents the approximate inverse of compress1. Since compression is lossy,
  // the results of decompression will may not match the original vector of polynomials.

  /**
   * Decompresses a Uint8Array into a two-dimensional array of numbers.
   *
   * @param a The Uint8Array to decompress.
   * @returns The decompressed two-dimensional array.
   */
  protected _decompressU(a: Uint8Array): Array<Int16Array> {
    const r = new Array<Int16Array>(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Int16Array(N);
    }
    const t = new Array<number>(4);
    for (let aa = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
        t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
        t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
        t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
        aa = aa + 5;
        for (let k = 0; k < 4; k++) {
          r[i][4 * j + k] = int16(
            (((t[k] & 0x3FF) * Q) + 512) >> 10,
          );
        }
      }
    }
    return r;
  }

  // decompressV de-serializes and subsequently decompresses a polynomial,
  // representing the approximate inverse of compress2.
  // Note that compression is lossy, and thus decompression will not match the
  // original input.

  /**
   * Decompresses a Uint8Array into an array of numbers.
   *
   * @param a - The Uint8Array to decompress.
   * @returns An array of numbers.
   */
  protected _decompressV(a: Uint8Array): Int16Array {
    const r = new Int16Array(N);
    for (let aa = 0, i = 0; i < N / 2; i++, aa++) {
      r[2 * i + 0] = int16((((a[aa] & 15) * Q) + 8) >> 4);
      r[2 * i + 1] = int16((((a[aa] >> 4) * Q) + 8) >> 4);
    }
    return r;
  }
}

// polyToBytes serializes a polynomial into an array of bytes.

/**
 * Converts a polynomial represented by an array of numbers to a Uint8Array.
 * Each coefficient of the polynomial is reduced modulo q.
 *
 * @param a - The array representing the polynomial.
 * @returns The Uint8Array representation of the polynomial.
 */
function polyToBytes(a: Int16Array): Uint8Array {
  let t0, t1;
  const r = new Uint8Array(384);
  for (let i = 0; i < N / 2; i++) {
    // inline subtractQ: a - q if a >= q, else a
    t0 = a[2 * i] - Q;
    t0 += (t0 >> 31) & Q;
    t1 = a[2 * i + 1] - Q;
    t1 += (t1 >> 31) & Q;

    r[3 * i + 0] = byte(t0);
    r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
    r[3 * i + 2] = byte(t1 >> 4);
  }
  return r;
}

// polyFromBytes de-serialises an array of bytes into a polynomial,
// and represents the inverse of polyToBytes.

/**
 * Converts a Uint8Array to an array of numbers representing a polynomial.
 * Each element in the array represents a coefficient of the polynomial.
 * The input array `a` should have a length of 384.
 * The function performs bitwise operations to extract the coefficients from the input array.
 * @param a The Uint8Array to convert to a polynomial.
 * @returns An array of numbers representing the polynomial.
 */
function polyFromBytes(a: Uint8Array): Int16Array {
  const r = new Int16Array(N);
  for (let i = 0; i < N / 2; i++) {
    r[2 * i] = int16(
      ((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF,
    );
    r[2 * i + 1] = int16(
      ((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF,
    );
  }
  return r;
}

// polyToMsg converts a polynomial to a 32-byte message
// and represents the inverse of polyFromMsg.

/**
 * Converts a polynomial to a message represented as a Uint8Array.
 * @param a - The polynomial to convert.
 * @returns The message as a Uint8Array.
 */
function polyToMsg(a: Int16Array): Uint8Array {
  const msg = new Uint8Array(32);
  let t, v;
  for (let i = 0; i < N / 8; i++) {
    for (let j = 0; j < 8; j++) {
      // inline subtractQ: a - q if a >= q, else a
      v = a[8 * i + j] - Q;
      v += (v >> 31) & Q;
      t = (((uint16(v) << 1) + uint16(Q / 2)) /
        uint16(Q)) & 1;
      msg[i] |= byte(t << j);
    }
  }
  return msg;
}

// polyFromMsg converts a 32-byte message to a polynomial.

/**
 * Converts a Uint8Array message to an array of numbers representing a polynomial.
 * Each element in the array is an int16 (0-65535).
 *
 * @param msg - The Uint8Array message to convert.
 * @returns An array of numbers representing the polynomial.
 */
function polyFromMsg(msg: Uint8Array): Int16Array {
  const r = new Int16Array(N); // each element is int16 (0-65535)
  let mask; // int16
  for (let i = 0; i < N / 8; i++) {
    for (let j = 0; j < 8; j++) {
      mask = -1 * int16((msg[i] >> j) & 1);
      r[8 * i + j] = mask & int16((Q + 1) / 2);
    }
  }
  return r;
}

// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.

/**
 * Generates an array of random numbers from a given buffer, rejecting values greater than a specified threshold.
 *
 * @param buf - The input buffer containing random bytes.
 * @param bufl - The length of the input buffer.
 * @param len - The desired length of the output array.
 * @returns An array of random numbers and the actual length of the output array.
 */
function indcpaRejUniform(
  buf: Uint8Array,
  bufl: number,
  len: number,
): [Int16Array, number] {
  const r = new Int16Array(N);
  let ctr = 0;
  let val0, val1; // d1, d2 in kyber documentation

  for (let pos = 0; ctr < len && pos + 3 <= bufl;) {
    // compute d1 and d2
    val0 = (uint16((buf[pos]) >> 0) | (uint16(buf[pos + 1]) << 8)) & 0xFFF;
    val1 = (uint16((buf[pos + 1]) >> 4) | (uint16(buf[pos + 2]) << 4)) & 0xFFF;

    // increment input buffer index by 3
    pos = pos + 3;

    // if d1 is less than 3329
    if (val0 < Q) {
      // assign to d1
      r[ctr] = val0;
      // increment position of output array
      ctr = ctr + 1;
    }
    if (ctr < len && val1 < Q) {
      r[ctr] = val1;
      ctr = ctr + 1;
    }
  }
  return [r, ctr];
}

// byteopsCbd computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter PARAMS_ETA,
// given an array of uniformly random bytes.

/**
 * Converts a Uint8Array buffer to an array of numbers using the CBD operation.
 * @param buf - The input Uint8Array buffer.
 * @param eta - The value used in the CBD operation.
 * @returns An array of numbers obtained from the CBD operation.
 */
function byteopsCbd(buf: Uint8Array, eta: number): Int16Array {
  let t, d;
  let a, b;
  const r = new Int16Array(N);
  for (let i = 0; i < N / 8; i++) {
    t = byteopsLoad32(buf, 4 * i);
    d = t & 0x55555555;
    d = d + ((t >> 1) & 0x55555555);
    for (let j = 0; j < 8; j++) {
      a = int16((d >> (4 * j + 0)) & 0x3);
      b = int16((d >> (4 * j + eta)) & 0x3);
      r[8 * i + j] = a - b;
    }
  }
  return r;
}

// ntt performs an inplace number-theoretic transform (NTT) in `Rq`.
// The input is in standard order, the output is in bit-reversed order.

/**
 * Performs the Number Theoretic Transform (NTT) on an array of numbers.
 *
 * @param r - The input array of numbers.
 * @returns The transformed array of numbers.
 */
function ntt(r: Int16Array): Int16Array {
  // 128, 64, 32, 16, 8, 4, 2
  for (let j = 0, k = 1, l = 128; l >= 2; l >>= 1) {
    // 0,
    for (let start = 0; start < 256; start = j + l) {
      const zeta = NTT_ZETAS[k];
      k = k + 1;
      // for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
      for (j = start; j < start + l; j++) {
        // compute the modular multiplication of the zeta and each element in the subsection
        const t = nttFqMul(zeta, r[j + l]); // t is mod q
        // overwrite each element in the subsection as the opposite subsection element minus t
        r[j + l] = r[j] - t;
        // add t back again to the opposite subsection
        r[j] = r[j] + t;
      }
    }
  }
  return r;
}

// nttFqMul performs multiplication followed by Montgomery reduction
// and returns a 16-bit integer congruent to `a*b*R^{-1} mod Q`.

/**
 * Performs an NTT (Number Theoretic Transform) multiplication on two numbers in Fq.
 * @param a The first number.
 * @param b The second number.
 * @returns The result of the NTT multiplication.
 */
function nttFqMul(a: number, b: number): number {
  const ab = a * b;
  const u = (Math.imul(ab, Q_INV) << 16) >> 16;
  return (ab - u * Q) >> 16;
}

// reduce applies Barrett reduction to all coefficients of a polynomial.

/**
 * Reduces each element in the given array using the barrett function.
 *
 * @param r - The array to be reduced.
 * @returns The reduced array.
 */
function reduce(r: Int16Array): Int16Array {
  for (let i = 0; i < N; i++) {
    r[i] = barrett(r[i]);
  }
  return r;
}

// barrett computes a Barrett reduction; given
// a integer `a`, returns a integer congruent to
// `a mod Q` in {0,...,Q}.

/**
 * Performs the Barrett reduction algorithm on the given number.
 *
 * @param a - The number to be reduced.
 * @returns The result of the reduction.
 */
const BARRETT_V = ((1 << 24) + Q / 2) / Q;
function barrett(a: number): number {
  let t = BARRETT_V * a >> 24;
  t = t * Q;
  return a - t;
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.

/**
 * Converts a polynomial to the Montgomery domain.
 *
 * @param r - The polynomial to be converted.
 * @returns The polynomial in the Montgomery domain.
 */
function polyToMont(r: Int16Array): Int16Array {
  // let f = int16(((uint64(1) << 32)) % uint64(Q));
  const f = 1353; // if Q changes then this needs to be updated
  for (let i = 0; i < N; i++) {
    const a = r[i] * f;
    const u = (Math.imul(a, Q_INV) << 16) >> 16;
    r[i] = (a - u * Q) >> 16;
  }
  return r;
}

// pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.

/**
 * Multiplies two matrices element-wise and returns the result.
 * @param a - The first matrix.
 * @param b - The second matrix.
 * @returns The resulting matrix after element-wise multiplication.
 */
function multiply(
  a: Array<Int16Array>,
  b: Array<Int16Array>,
): Int16Array {
  let r = polyBaseMulMontgomery(a[0], b[0]);
  let t;
  for (let i = 1; i < a.length; i++) {
    t = polyBaseMulMontgomery(a[i], b[i]);
    r = add(r, t);
  }
  return reduce(r);
}

// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.

/**
 * Performs polynomial base multiplication in Montgomery domain.
 * @param a - The first polynomial array.
 * @param b - The second polynomial array.
 * @returns The result of the polynomial base multiplication.
 */
function polyBaseMulMontgomery(
  a: Int16Array,
  b: Int16Array,
): Int16Array {
  for (let i = 0; i < N / 4; i++) {
    const idx = 4 * i;
    const a0 = a[idx], a1 = a[idx + 1], a2 = a[idx + 2], a3 = a[idx + 3];
    const b0 = b[idx], b1 = b[idx + 1], b2 = b[idx + 2], b3 = b[idx + 3];
    const zeta = NTT_ZETAS[64 + i];
    a[idx] = nttFqMul(nttFqMul(a1, b1), zeta) + nttFqMul(a0, b0);
    a[idx + 1] = nttFqMul(a0, b1) + nttFqMul(a1, b0);
    a[idx + 2] = nttFqMul(nttFqMul(a3, b3), -zeta) + nttFqMul(a2, b2);
    a[idx + 3] = nttFqMul(a2, b3) + nttFqMul(a3, b2);
  }
  return a;
}

// adds two polynomials.

/**
 * Adds two arrays element-wise.
 * @param a - The first array.
 * @param b - The second array.
 * @returns The resulting array after element-wise addition.
 */
function add(a: Int16Array, b: Int16Array): Int16Array {
  for (let i = 0; i < N; i++) {
    a[i] += b[i];
  }
  return a;
}

// subtracts two polynomials.

/**
 * Subtracts the elements of array b from array a.
 *
 * @param a - The array from which to subtract.
 * @param b - The array to subtract.
 * @returns The resulting array after subtraction.
 */
function subtract(a: Int16Array, b: Int16Array): Int16Array {
  for (let i = 0; i < N; i++) {
    a[i] -= b[i];
  }
  return a;
}

// nttInverse performs an inplace inverse number-theoretic transform (NTT)
// in `Rq` and multiplication by Montgomery factor 2^16.
// The input is in bit-reversed order, the output is in standard order.

/**
 * Performs the inverse Number Theoretic Transform (NTT) on the given array.
 *
 * @param r - The input array to perform the inverse NTT on.
 * @returns The array after performing the inverse NTT.
 */
function nttInverse(r: Int16Array): Int16Array {
  let j = 0;
  for (let k = 0, l = 2; l <= 128; l <<= 1) {
    for (let start = 0; start < 256; start = j + l) {
      const zeta = NTT_ZETAS_INV[k];
      k = k + 1;
      for (j = start; j < start + l; j++) {
        const t = r[j];
        r[j] = barrett(t + r[j + l]);
        r[j + l] = t - r[j + l];
        r[j + l] = nttFqMul(zeta, r[j + l]);
      }
    }
  }
  for (j = 0; j < 256; j++) {
    r[j] = nttFqMul(r[j], NTT_ZETAS_INV[127]);
  }
  return r;
}
