/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/src/sha3.ts
 */

/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out [FIPS-202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
 * [Website](https://keccak.team/keccak.html),
 * [the differences between SHA-3 and Keccak](https://crypto.stackexchange.com/questions/15727/what-are-the-key-differences-between-the-draft-sha-3-standard-and-the-keccak-sub).
 *
 * The permutation and the sponge themselves are in `keccak.ts`. This module
 * adds the validating hash interface and the hash functions on top of them.
 * @module
 */
import { KeccakCore } from "./keccak.ts";
// prettier-ignore
import {
  abytes,
  aexists,
  anumber,
  aoutput,
  type CHash,
  type CHashXOF,
  clean,
  createHasher,
  type Hash,
  type HashInfo,
  type HashXOF,
  oidNist,
} from "./utils.ts";

export { keccakP } from "./keccak.ts";

/** Keccak sponge function. */
export class Keccak extends KeccakCore
  implements Hash<Keccak>, HashXOF<Keccak> {
  protected destroyed = false;

  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(
    blockLen: number,
    suffix: number,
    outputLen: number,
    enableXOF = false,
    rounds: number = 24,
  ) {
    super(blockLen, suffix, outputLen, enableXOF, rounds);
    // Can be passed from user as dkLen
    anumber(outputLen, "outputLen");
    // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
    // 0 < blockLen < 200
    if (!(0 < blockLen && blockLen < 200)) {
      throw new Error("only keccak-f1600 function is supported");
    }
  }
  clone(): Keccak {
    return this._cloneInto();
  }
  /** Resets instance to initial (empty) state for reuse. */
  override reset(): void {
    super.reset();
    this.destroyed = false;
  }
  update(data: Uint8Array): this {
    aexists(this);
    abytes(data);
    return this.updateUnsafe(data);
  }
  protected writeInto(out: Uint8Array): Uint8Array {
    aexists(this, false);
    abytes(out);
    return this.writeIntoUnsafe(out);
  }
  xofInto(out: Uint8Array): Uint8Array {
    // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
    if (!this.enableXOF) {
      throw new Error("XOF is not possible for this instance");
    }
    return this.writeInto(out);
  }
  xof(bytes: number): Uint8Array {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out: Uint8Array): Uint8Array {
    aoutput(out, this);
    if (this.finished) throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest(): Uint8Array {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy(): void {
    this.destroyed = true;
    clean(this.state, this._B);
  }
  _cloneInto(to?: Keccak): Keccak {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    // Suffix can change in cSHAKE
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}

const genKeccak = (
  suffix: number,
  blockLen: number,
  outputLen: number,
  info: HashInfo = {},
) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);

// /** SHA3-224 hash function. */
// export const sha3_224: CHash = /* @__PURE__ */ genKeccak(
//   0x06,
//   144,
//   28,
//   /* @__PURE__ */ oidNist(0x07),
// );

/** SHA3-256 hash function. Different from keccak-256. */
export const sha3_256: CHash = /* @__PURE__ */ genKeccak(
  0x06,
  136,
  32,
  /* @__PURE__ */ oidNist(0x08),
);

// /** SHA3-384 hash function. */
// export const sha3_384: CHash = /* @__PURE__ */ genKeccak(
//   0x06,
//   104,
//   48,
//   /* @__PURE__ */ oidNist(0x09),
// );

/** SHA3-512 hash function. */
export const sha3_512: CHash = /* @__PURE__ */ genKeccak(
  0x06,
  72,
  64,
  /* @__PURE__ */ oidNist(0x0a),
);

/** keccak-224 hash function. */
export const keccak_224: CHash = /* @__PURE__ */ genKeccak(0x01, 144, 28);
/** keccak-256 hash function. Different from SHA3-256. */
export const keccak_256: CHash = /* @__PURE__ */ genKeccak(0x01, 136, 32);
/** keccak-384 hash function. */
export const keccak_384: CHash = /* @__PURE__ */ genKeccak(0x01, 104, 48);
/** keccak-512 hash function. */
export const keccak_512: CHash = /* @__PURE__ */ genKeccak(0x01, 72, 64);

export type ShakeOpts = { dkLen?: number };

const genShake = (
  suffix: number,
  blockLen: number,
  outputLen: number,
  info: HashInfo = {},
) =>
  createHasher<Keccak, ShakeOpts>(
    (opts: ShakeOpts = {}) =>
      new Keccak(
        blockLen,
        suffix,
        opts.dkLen === undefined ? outputLen : opts.dkLen,
        true,
      ),
    info,
  );

/** SHAKE128 XOF with 128-bit security. */
export const shake128: CHashXOF<Keccak, ShakeOpts> =
  /* @__PURE__ */
  genShake(0x1f, 168, 16, /* @__PURE__ */ oidNist(0x0b));
/** SHAKE256 XOF with 256-bit security. */
export const shake256: CHashXOF<Keccak, ShakeOpts> =
  /* @__PURE__ */
  genShake(0x1f, 136, 32, /* @__PURE__ */ oidNist(0x0c));

// /** SHAKE128 XOF with 256-bit output (NIST version). */
// export const shake128_32: CHashXOF<Keccak, ShakeOpts> =
//   /* @__PURE__ */
//   genShake(0x1f, 168, 32, /* @__PURE__ */ oidNist(0x0b));
// /** SHAKE256 XOF with 512-bit output (NIST version). */
// export const shake256_64: CHashXOF<Keccak, ShakeOpts> =
//   /* @__PURE__ */
//   genShake(0x1f, 136, 64, /* @__PURE__ */ oidNist(0x0c));
