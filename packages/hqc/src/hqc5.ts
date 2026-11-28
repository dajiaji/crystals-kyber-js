import { HqcError } from "./errors.ts";
import { HqcBase } from "./hqcBase.ts";
import type { HqcInterface } from "./interfaces.ts";

/**
 * Synchronous implementation of HQC-5 (NIST security category 5).
 *
 * The public key, the private key and the ciphertext are 7237, 32 and
 * 14421 octets in length respectively.
 *
 * Use {@link createHqc5} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * import { createHqc5 } from "@webpqc/hqc";
 *
 * const recipient = await createHqc5();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createHqc5();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class Hqc5Impl extends HqcBase implements HqcInterface {
  override _n = 57637;
  override _n1 = 90;
  override _n2 = 640;
  override _k1 = 32;
  override _t1 = 29;
  override _omega = 132;
  override _omegaR = 150;
  override _omegaE = 150;

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
   * The optional 48-octet seed is `m || salt` (32 + 16 octets), which makes
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
  static async _create(): Promise<Hqc5Impl> {
    const impl = new Hqc5Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized HQC-5 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link HqcInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createHqc5 } from "@webpqc/hqc";
 *
 * const ctx = await createHqc5();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export function createHqc5(): Promise<HqcInterface> {
  return Hqc5Impl._create();
}
