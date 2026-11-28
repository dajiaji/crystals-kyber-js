import { HqcError } from "./errors.ts";
import { HqcBase } from "./hqcBase.ts";
import type { HqcInterface } from "./interfaces.ts";

/**
 * Synchronous implementation of HQC-3 (NIST security category 3).
 *
 * The public key, the private key and the ciphertext are 4514, 32 and
 * 8978 octets in length respectively.
 *
 * Use {@link createHqc3} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * import { createHqc3 } from "@webpqc/hqc";
 *
 * const recipient = await createHqc3();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createHqc3();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class Hqc3Impl extends HqcBase implements HqcInterface {
  override _n = 35851;
  override _n1 = 56;
  override _n2 = 640;
  override _k1 = 24;
  override _t1 = 16;
  override _omega = 101;
  override _omegaR = 114;
  override _omegaE = 114;

  constructor() {
    super();
    this._initPool();
  }

  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array] {
    try {
      return this._generateKeyPairCore();
    } catch (e: unknown) {
      throw new HqcError(e);
    }
  }

  /** Derives a keypair [publicKey, privateKey] deterministically from a 32-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      return this._deriveKeyPairCore(seed);
    } catch (e: unknown) {
      throw new HqcError(e);
    }
  }

  /**
   * Encapsulates: returns [ciphertext, sharedSecret].
   *
   * The optional 40-octet seed is `m || salt` (24 + 16 octets), which makes
   * the encapsulation deterministic.
   */
  encap(pk: Uint8Array, seed?: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      return this._encapCore(pk, seed);
    } catch (e: unknown) {
      throw new HqcError(e);
    }
  }

  /** Decapsulates: returns sharedSecret. */
  decap(ct: Uint8Array, sk: Uint8Array): Uint8Array {
    try {
      return this._decapCore(ct, sk);
    } catch (e: unknown) {
      throw new HqcError(e);
    }
  }

  /** @internal */
  static async _create(): Promise<Hqc3Impl> {
    const impl = new Hqc3Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized HQC-3 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link HqcInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createHqc3 } from "@webpqc/hqc";
 *
 * const ctx = await createHqc3();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export function createHqc3(): Promise<HqcInterface> {
  return Hqc3Impl._create();
}
