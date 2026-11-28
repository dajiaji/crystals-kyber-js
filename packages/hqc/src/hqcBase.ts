/**
 * This implementation follows the HQC specifications v5.1 (2026-11-09) and
 * the reference implementation v5.1.0, both of which are published by the HQC
 * team at https://pqc-hqc.org. The reference implementation is released into
 * the public domain.
 */
import { Keccak } from "./deps.ts";

import {
  G_DOMAIN,
  H_DOMAIN,
  I_DOMAIN,
  J_DOMAIN,
  RM_N3,
  SALT_BYTES,
  SEED_BYTES,
  SHARED_SECRET_BYTES,
} from "./consts.ts";
import { Gf2x } from "./gf2x.ts";
import { ReedMuller } from "./reedMuller.ts";
import { ReedSolomon } from "./reedSolomon.ts";
import {
  bytesToWords,
  constantTimeCompare,
  reduce24,
  wordsToBytes,
} from "./utils.ts";

/**
 * Represents the base class for the HQC key encapsulation mechanism.
 *
 * This class provides the base implementation for the HQC key encapsulation
 * mechanism.
 *
 * @remarks
 *
 * This class is not intended to be used directly. Instead, use one of the
 * factory functions: {@link createHqc1}, {@link createHqc3} or
 * {@link createHqc5}.
 */
export class HqcBase {
  protected _api: Crypto | undefined = undefined;
  // The length of the vectors of the ambient space in bits (n).
  protected _n = 0;
  // The length of the shortened Reed-Solomon code in octets (n1).
  protected _n1 = 0;
  // The length of the duplicated Reed-Muller code in bits (n2').
  protected _n2 = 0;
  // The dimension of the shortened Reed-Solomon code (k1), which is the
  // length of a message in octets (k / 8).
  protected _k1 = 0;
  // The error correction capacity of the shortened Reed-Solomon code (t1).
  protected _t1 = 0;
  // The weight of the secret vectors x and y (omega).
  protected _omega = 0;
  // The weight of the vectors r1 and r2 (omega_r).
  protected _omegaR = 0;
  // The weight of the vector e (omega_e).
  protected _omegaE = 0;

  protected _pkSize = 0;
  protected _skSize = 0;
  protected _ctSize = 0;
  // The size of a vector of the ambient space in octets and in 32-bit words.
  private _nBytes = 0;
  private _nWords = 0;
  // The size of a codeword of the concatenated code.
  private _n1n2Bytes = 0;
  private _n1n2Words = 0;
  // mask_n: the mask of the used bits of the last octet of a vector.
  private _maskN = 0;
  // rejection_threshold_n: the largest multiple of n below 2^24.
  private _rejectionThreshold = 0;
  // floor(2^32 / n), to reduce a 24-bit value modulo n without a division.
  private _barrettMu = 0;

  private _gf2x!: Gf2x;
  private _rs!: ReedSolomon;
  private _rm!: ReedMuller;

  // Keccak pool instances (reset before each use)
  private _poolXof!: Keccak;
  private _pool256!: Keccak;
  private _pool512!: Keccak;
  // Pre-allocated output buffers
  private _bufG = new Uint8Array(64);
  private _bufH = new Uint8Array(32);
  private _bufI = new Uint8Array(64);
  private _bufJ = new Uint8Array(32);
  private _bufSeedPke = new Uint8Array(SEED_BYTES);
  private _bufDomain = new Uint8Array(1);
  private _bufCandidate = new Uint8Array(3);
  private _bufSigma!: Uint8Array;
  private _bufM!: Uint8Array;
  private _bufCdw!: Uint8Array;
  private _bufRand!: Uint8Array;
  private _bufVec!: Uint8Array;
  private _bufEk!: Uint8Array;
  private _bufCt!: Uint8Array;
  // Pre-allocated supports of the fixed weight vectors
  private _support!: Uint32Array;
  private _supportWord!: Uint32Array;
  private _supportBit!: Uint32Array;
  // Pre-allocated vectors
  private _vecX!: Uint32Array;
  private _vecY!: Uint32Array;
  private _vecH!: Uint32Array;
  private _vecS!: Uint32Array;
  private _vecR1!: Uint32Array;
  private _vecR2!: Uint32Array;
  private _vecE!: Uint32Array;
  private _vecU!: Uint32Array;
  private _vecV!: Uint32Array;
  private _vecT!: Uint32Array;

  /**
   * Creates a new instance of the HqcBase class.
   */
  constructor() {}

  protected _initPool(): void {
    const n = this._n;
    this._nBytes = (n + 7) >>> 3;
    this._nWords = (n + 31) >>> 5;
    this._n1n2Bytes = (this._n1 * this._n2) >>> 3;
    this._n1n2Words = this._n1n2Bytes >>> 2;
    this._pkSize = SEED_BYTES + this._nBytes;
    this._skSize = SEED_BYTES;
    this._ctSize = this._nBytes + this._n1n2Bytes + SALT_BYTES;
    this._maskN = (1 << (n & 7)) - 1;
    this._rejectionThreshold = Math.floor(0x1000000 / n) * n;
    this._barrettMu = Math.floor(0x100000000 / n);

    this._gf2x = new Gf2x(n);
    this._rs = new ReedSolomon(this._n1, this._k1, this._t1);
    this._rm = new ReedMuller(this._n2 / RM_N3);

    // shake256: blockLen=136, suffix=0x1f, enableXOF
    this._poolXof = new Keccak(136, 0x1f, 32, true);
    // sha3_256: blockLen=136, suffix=0x06, outputLen=32
    this._pool256 = new Keccak(136, 0x06, 32);
    // sha3_512: blockLen=72, suffix=0x06, outputLen=64
    this._pool512 = new Keccak(72, 0x06, 64);

    this._bufSigma = new Uint8Array(this._k1);
    this._bufM = new Uint8Array(this._k1);
    this._bufCdw = new Uint8Array(this._n1);
    const maxWeight = Math.max(this._omega, this._omegaR, this._omegaE);
    this._bufRand = new Uint8Array(4 * maxWeight);
    this._bufVec = new Uint8Array(this._nBytes);
    this._bufEk = new Uint8Array(this._pkSize);
    this._bufCt = new Uint8Array(this._ctSize);
    this._support = new Uint32Array(maxWeight);
    this._supportWord = new Uint32Array(maxWeight);
    this._supportBit = new Uint32Array(maxWeight);
    this._vecX = new Uint32Array(this._nWords);
    this._vecY = new Uint32Array(this._nWords);
    this._vecH = new Uint32Array(this._nWords);
    this._vecS = new Uint32Array(this._nWords);
    this._vecR1 = new Uint32Array(this._nWords);
    this._vecR2 = new Uint32Array(this._nWords);
    this._vecE = new Uint32Array(this._nWords);
    this._vecU = new Uint32Array(this._nWords);
    this._vecV = new Uint32Array(this._nWords);
    this._vecT = new Uint32Array(this._nWords);
  }

  protected _zeroPool(): void {
    this._bufG.fill(0);
    this._bufH.fill(0);
    this._bufI.fill(0);
    this._bufJ.fill(0);
    this._bufSeedPke.fill(0);
    this._bufDomain[0] = 0;
    this._bufCandidate.fill(0);
    this._bufSigma.fill(0);
    this._bufM.fill(0);
    this._bufCdw.fill(0);
    this._bufRand.fill(0);
    this._bufVec.fill(0);
    this._bufEk.fill(0);
    this._bufCt.fill(0);
    this._support.fill(0);
    this._supportWord.fill(0);
    this._supportBit.fill(0);
    this._vecX.fill(0);
    this._vecY.fill(0);
    this._vecH.fill(0);
    this._vecS.fill(0);
    this._vecR1.fill(0);
    this._vecR2.fill(0);
    this._vecE.fill(0);
    this._vecU.fill(0);
    this._vecV.fill(0);
    this._vecT.fill(0);
    this._gf2x.clear();
    this._rs.clear();
    this._rm.clear();
    // reset() zeros state and resets flags; no need for destroy()
    this._poolXof.reset();
    this._pool256.reset();
    this._pool512.reset();
  }

  // XOF.Init and XOF.Absorb: SHAKE256, optionally with a domain separator
  // appended to the seed.
  private _xofInit(seed: Uint8Array, domain?: number): void {
    this._poolXof.reset();
    this._poolXof.updateUnsafe(seed);
    if (domain !== undefined) {
      this._bufDomain[0] = domain;
      this._poolXof.updateUnsafe(this._bufDomain);
    }
  }

  // XOF.GetBytes
  private _xofGetBytes(out: Uint8Array): void {
    this._poolXof.writeIntoUnsafe(out);
  }

  // Hash G: SHA3-512(H(ek) || m || salt || G_domain_separator)
  private _g(hEk: Uint8Array, m: Uint8Array, salt: Uint8Array): Uint8Array {
    this._bufDomain[0] = G_DOMAIN;
    this._pool512.reset();
    this._pool512.updateUnsafe(hEk).updateUnsafe(m).updateUnsafe(salt)
      .updateUnsafe(this._bufDomain).writeIntoUnsafe(this._bufG);
    return this._bufG;
  }

  // Hash H: SHA3-256(ek || H_domain_separator)
  private _h(ek: Uint8Array): Uint8Array {
    this._bufDomain[0] = H_DOMAIN;
    this._pool256.reset();
    this._pool256.updateUnsafe(ek).updateUnsafe(this._bufDomain)
      .writeIntoUnsafe(this._bufH);
    return this._bufH;
  }

  // Hash I: SHA3-512(seed || I_domain_separator)
  private _i(seed: Uint8Array): Uint8Array {
    this._bufDomain[0] = I_DOMAIN;
    this._pool512.reset();
    this._pool512.updateUnsafe(seed).updateUnsafe(this._bufDomain)
      .writeIntoUnsafe(this._bufI);
    return this._bufI;
  }

  // Hash J: SHA3-256(H(ek) || sigma || c || J_domain_separator)
  private _j(hEk: Uint8Array, sigma: Uint8Array, ct: Uint8Array): Uint8Array {
    this._bufDomain[0] = J_DOMAIN;
    this._pool256.reset();
    this._pool256.updateUnsafe(hEk).updateUnsafe(sigma).updateUnsafe(ct)
      .updateUnsafe(this._bufDomain).writeIntoUnsafe(this._bufJ);
    return this._bufJ;
  }

  protected _generateKeyPairCore(): [Uint8Array, Uint8Array] {
    const rnd = new Uint8Array(SEED_BYTES);
    try {
      (this._api as Crypto).getRandomValues(rnd);
      return this._deriveKeyPair(rnd);
    } finally {
      // the seed is the whole private key, so do not leave it behind
      rnd.fill(0);
      this._zeroPool();
    }
  }

  protected _deriveKeyPairCore(seed: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      if (seed.byteLength !== SEED_BYTES) {
        throw new Error(`seed must be ${SEED_BYTES} bytes in length`);
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
    let rnd: Uint8Array | undefined;
    try {
      // validate the key type and that the unused bits of s are zero, i.e.
      // that s is the encoding of an element of F_2^n.
      if (
        pk.length !== this._pkSize ||
        (pk[this._pkSize - 1] & ~this._maskN) !== 0
      ) {
        throw new Error("invalid encapsulation key");
      }
      const k1 = this._k1;
      if (seed == undefined) {
        rnd = new Uint8Array(k1 + SALT_BYTES);
        seed = rnd;
        // m and salt are drawn one by one in this order, as the reference
        // implementation does, so that a deterministic random bit generator
        // gives the same result with both.
        const api = this._api as Crypto;
        api.getRandomValues(rnd.subarray(0, k1));
        api.getRandomValues(rnd.subarray(k1));
      } else if (seed.byteLength !== k1 + SALT_BYTES) {
        throw new Error(`seed must be ${k1 + SALT_BYTES} bytes in length`);
      }
      const m = seed.subarray(0, k1);
      const salt = seed.subarray(k1);

      // (K, theta) = G(H(ek) || m || salt)
      const kTheta = this._g(this._h(pk), m, salt);
      const ct = this._bufCt;
      this._pkeEncrypt(ct, pk, m, kTheta.subarray(SHARED_SECRET_BYTES));
      ct.set(salt, this._nBytes + this._n1n2Bytes);
      return [ct.slice(), kTheta.slice(0, SHARED_SECRET_BYTES)];
    } finally {
      // only wipe a seed we generated; a supplied seed belongs to the caller
      rnd?.fill(0);
      this._zeroPool();
    }
  }

  protected _decapCore(ct: Uint8Array, sk: Uint8Array): Uint8Array {
    try {
      // ciphertext type check
      if (ct.byteLength !== this._ctSize) {
        throw new Error("Invalid ct size");
      }
      // decapsulation key type check
      if (sk.length !== this._skSize) {
        throw new Error("Invalid decapsulation key");
      }

      // The decapsulation key is seed_kem: recompute the key pair of the
      // PKE and the implicit rejection value sigma from it.
      this._xofInit(sk, this._k1);
      this._xofGetBytes(this._bufSeedPke);
      this._xofGetBytes(this._bufSigma);
      this._pkeKeygen(this._bufSeedPke);
      const ek = this._bufEk;

      const m2 = this._bufM;
      this._pkeDecrypt(m2, ct);

      // (K', theta') = G(H(ek) || m' || salt)
      const saltOffset = this._nBytes + this._n1n2Bytes;
      const salt = ct.subarray(saltOffset);
      const hEk = this._h(ek);
      const kTheta = this._g(hEk, m2, salt);
      const ct2 = this._bufCt;
      this._pkeEncrypt(ct2, ek, m2, kTheta.subarray(SHARED_SECRET_BYTES));
      ct2.set(salt, saltOffset);

      const kBar = this._j(hEk, this._bufSigma, ct);
      // Branch-free select. mask is all ones when the re-encryption matches
      // and zero otherwise, so neither the branch predictor nor the memory
      // access pattern depends on the comparison result, which is the bit
      // the FO transform exists to hide.
      const mask = -constantTimeCompare(ct, ct2);
      const ss = new Uint8Array(SHARED_SECRET_BYTES);
      for (let i = 0; i < SHARED_SECRET_BYTES; i++) {
        ss[i] = kBar[i] ^ ((kBar[i] ^ kTheta[i]) & mask);
      }
      return ss;
    } finally {
      this._zeroPool();
    }
  }

  /**
   * Sets up the HqcBase instance by binding the Web Crypto API.
   * If the API is already bound, this method does nothing.
   * @returns {Promise<void>} A promise that resolves when the setup is complete.
   */
  // deno-lint-ignore require-await
  protected async _setup() {
    if (this._api !== undefined) {
      return;
    }
    if (globalThis.crypto === undefined) {
      throw new Error("Web Crypto API is not available");
    }
    this._api = globalThis.crypto;
  }

  // HQC-KEM.Keygen for a given seed_kem.

  /**
   * Derives a key pair from a given seed.
   *
   * @param seed - The seed used for key derivation (seed_kem).
   * @returns An array containing the public key and secret key.
   */
  private _deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array] {
    // seed_pke = XOF(seed_kem || k / 8)
    this._xofInit(seed, this._k1);
    this._xofGetBytes(this._bufSeedPke);
    this._pkeKeygen(this._bufSeedPke);
    // The decapsulation key is in the compressed format: dk_kem = seed_kem.
    // A copy of the seed, whatever subclass of Uint8Array the seed is.
    return [this._bufEk.slice(), new Uint8Array(seed)];
  }

  // HQC-PKE.Keygen: the encryption key is written to _bufEk, and the vector
  // y of the decryption key is left in _vecY.

  /**
   * Derives the key pair of the public-key encryption scheme underlying HQC.
   *
   * @param seedPke - The seed used for key derivation (seed_pke).
   */
  private _pkeKeygen(seedPke: Uint8Array): void {
    // (seed_pke.dk, seed_pke.ek) = I(seed_pke)
    const seeds = this._i(seedPke);
    const seedEk = seeds.subarray(SEED_BYTES);

    this._xofInit(seeds.subarray(0, SEED_BYTES));
    this._sampleFixedWeightVect1(this._vecY, this._omega);
    this._sampleFixedWeightVect1(this._vecX, this._omega);

    this._xofInit(seedEk);
    this._sampleVect(this._vecH);

    // s = x + h * y
    const s = this._vecS;
    const x = this._vecX;
    this._gf2x.mul(s, this._vecY, this._vecH);
    for (let i = 0; i < this._nWords; i++) {
      s[i] ^= x[i];
    }

    // ek = (seed_pke.ek, s)
    this._bufEk.set(seedEk, 0);
    wordsToBytes(this._bufEk, SEED_BYTES, s, this._nBytes);
  }

  // HQC-PKE.Encrypt: the ciphertext (u, v) is written to the head of out.

  /**
   * Encrypts a message with the public-key encryption scheme underlying HQC.
   *
   * @param out - The buffer which receives u and v.
   * @param ek - The encryption key.
   * @param m - The message to be encrypted.
   * @param theta - The seed used for generating random values.
   */
  private _pkeEncrypt(
    out: Uint8Array,
    ek: Uint8Array,
    m: Uint8Array,
    theta: Uint8Array,
  ): void {
    const nBytes = this._nBytes;
    const n1n2Words = this._n1n2Words;

    // (seed_pke.ek, s) = ek
    this._xofInit(ek.subarray(0, SEED_BYTES));
    this._sampleVect(this._vecH);
    bytesToWords(this._vecS, ek, SEED_BYTES, nBytes);

    this._xofInit(theta);
    this._sampleFixedWeightVect2(this._vecR2, this._omegaR);
    this._sampleFixedWeightVect2(this._vecE, this._omegaE);
    this._sampleFixedWeightVect2(this._vecR1, this._omegaR);

    // u = r1 + h * r2
    const u = this._vecU;
    const r1 = this._vecR1;
    this._gf2x.mul(u, this._vecR2, this._vecH);
    for (let i = 0; i < this._nWords; i++) {
      u[i] ^= r1[i];
    }

    // v = C.Encode(m) + Truncate(s * r2 + e)
    const v = this._vecV;
    const e = this._vecE;
    const t = this._vecT;
    this._codeEncode(v, m);
    this._gf2x.mul(t, this._vecR2, this._vecS);
    for (let i = 0; i < n1n2Words; i++) {
      v[i] ^= t[i] ^ e[i];
    }

    wordsToBytes(out, 0, u, nBytes);
    wordsToBytes(out, nBytes, v, this._n1n2Bytes);
  }

  // HQC-PKE.Decrypt, with the vector y of the decryption key in _vecY.

  /**
   * Decrypts a ciphertext with the public-key encryption scheme underlying
   * HQC.
   *
   * @param m - The buffer which receives the message.
   * @param ct - The ciphertext, of which u and v are read.
   */
  private _pkeDecrypt(m: Uint8Array, ct: Uint8Array): void {
    const nBytes = this._nBytes;
    const u = this._vecU;
    const v = this._vecV;
    const t = this._vecT;
    bytesToWords(u, ct, 0, nBytes);
    bytesToWords(v, ct, nBytes, this._n1n2Bytes);

    // m = C.Decode(v - Truncate(u * y))
    this._gf2x.mul(t, this._vecY, u);
    for (let i = 0; i < this._n1n2Words; i++) {
      v[i] ^= t[i];
    }
    this._codeDecode(m, v);
  }

  // C.Encode: the Reed-Solomon code, then the duplicated Reed-Muller code.
  private _codeEncode(v: Uint32Array, m: Uint8Array): void {
    this._rs.encode(this._bufCdw, m);
    this._rm.encode(v, this._bufCdw, this._n1);
  }

  // C.Decode: the duplicated Reed-Muller code, then the Reed-Solomon code.
  private _codeDecode(m: Uint8Array, v: Uint32Array): void {
    this._rm.decode(this._bufCdw, v, this._n1);
    this._rs.decode(m, this._bufCdw);
  }

  // SampleVect: a uniformly random vector.
  private _sampleVect(v: Uint32Array): void {
    const buf = this._bufVec;
    this._xofGetBytes(buf);
    buf[this._nBytes - 1] &= this._maskN;
    bytesToWords(v, buf, 0, this._nBytes);
  }

  // SampleFixedWeightVect$: a uniformly random vector of a given weight,
  // with rejection sampling. It is used for the key generation.
  private _sampleFixedWeightVect1(v: Uint32Array, weight: number): void {
    const support = this._support;
    const candidate = this._bufCandidate;
    const n = this._n;
    const threshold = this._rejectionThreshold;
    const mu = this._barrettMu;
    for (let i = 0; i < weight;) {
      this._xofGetBytes(candidate);
      const c = candidate[0] | (candidate[1] << 8) | (candidate[2] << 16);
      // 1 if the candidate is below the rejection threshold
      let accept = (c - threshold) >>> 31;
      const pos = reduce24(c, n, mu);
      // 1 if the position is already in the support
      let found = 0;
      for (let j = 0; j < i; j++) {
        found |= ((support[j] ^ pos) - 1) >>> 31;
      }
      accept &= found ^ 1;
      support[i] = pos;
      i += accept;
    }
    this._supportToVector(v, weight);
  }

  // SampleFixedWeightVect: a random vector of a given weight without
  // rejection sampling, of which the distribution is slightly biased. It is
  // used for the encryption.
  private _sampleFixedWeightVect2(v: Uint32Array, weight: number): void {
    const support = this._support;
    const n = this._n;
    const rnd = this._bufRand.subarray(0, 4 * weight);
    this._xofGetBytes(rnd);
    for (let i = 0; i < weight; i++) {
      // i + floor(r * (n - i) / 2^32) for the 32-bit r, with the high and
      // the low halves of r multiplied one by one to stay below 2^32.
      const rl = rnd[4 * i] | (rnd[4 * i + 1] << 8);
      const rh = rnd[4 * i + 2] | (rnd[4 * i + 3] << 8);
      const range = n - i;
      support[i] = i +
        ((Math.imul(rh, range) + (Math.imul(rl, range) >>> 16)) >>> 16);
    }
    for (let i = weight - 2; i >= 0; i--) {
      // 1 if the position appears again later in the support
      let found = 0;
      for (let j = i + 1; j < weight; j++) {
        found |= ((support[j] ^ support[i]) - 1) >>> 31;
      }
      const mask = -found;
      support[i] = (mask & i) ^ (~mask & support[i]);
    }
    this._supportToVector(v, weight);
  }

  // ComputeVectorFromSupport
  private _supportToVector(v: Uint32Array, weight: number): void {
    const support = this._support;
    const word = this._supportWord;
    const bit = this._supportBit;
    for (let j = 0; j < weight; j++) {
      word[j] = support[j] >>> 5;
      bit[j] = 1 << (support[j] & 31);
    }
    scatter(v, word, bit, weight);
  }
}

// Sets the bits of a vector from the words and the masks of the positions of
// a support. Every word of the vector is computed from every position, so
// that the memory access pattern does not depend on the positions.
//
// This loop is the hot spot of the sampling. It is kept out of the class so
// that its optimized code does not depend on the parameter set.
function scatter(
  v: Uint32Array,
  word: Uint32Array,
  bit: Uint32Array,
  weight: number,
): void {
  for (let i = 0; i < v.length; i++) {
    let w = 0;
    for (let j = 0; j < weight; j++) {
      w |= bit[j] & (((i ^ word[j]) - 1) >> 31);
    }
    v[i] = w;
  }
}
