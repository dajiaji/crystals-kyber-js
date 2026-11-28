import { HqcError } from "./errors.ts";
import { HqcBase } from "./hqcBase.ts";
import type { HqcInterface } from "./interfaces.ts";

/**
 * Synchronous implementation of HQC-1 (NIST security category 1).
 *
 * The public key, the private key and the ciphertext are 2241, 32 and
 * 4433 octets in length respectively.
 *
 * Use {@link createHqc1} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * import { createHqc1 } from "@webpqc/hqc";
 *
 * const recipient = await createHqc1();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createHqc1();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class Hqc1Impl extends HqcBase implements HqcInterface {
  override _n = 17669;
  override _n1 = 46;
  override _n2 = 384;
  override _k1 = 16;
  override _t1 = 15;
  override _omega = 67;
  override _omegaR = 76;
  override _omegaE = 76;

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
   * The optional 32-octet seed is `m || salt` (16 + 16 octets), which makes
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
  static async _create(): Promise<Hqc1Impl> {
    const impl = new Hqc1Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized HQC-1 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link HqcInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createHqc1 } from "@webpqc/hqc";
 *
 * const ctx = await createHqc1();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export function createHqc1(): Promise<HqcInterface> {
  return Hqc1Impl._create();
}
