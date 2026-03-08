import { N } from "./consts.ts";
import { MlKemError } from "./errors.ts";
import type { MlKemInterface } from "./interfaces.ts";
import { MlKemBase } from "./mlKemBase.ts";

/**
 * Synchronous implementation of MlKem768.
 *
 * Use {@link createMlKem768} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { createMlKem768 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { createMlKem768 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = await createMlKem768();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createMlKem768();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class MlKem768Impl extends MlKemBase implements MlKemInterface {
  override _k = 3;
  override _du = 10;
  override _dv = 4;
  override _eta1 = 2;
  override _eta2 = 2;

  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }

  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array] {
    try {
      return this._generateKeyPairCore();
    } catch (e: unknown) {
      throw new MlKemError(e);
    }
  }

  /** Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      return this._deriveKeyPairCore(seed);
    } catch (e: unknown) {
      throw new MlKemError(e);
    }
  }

  /** Encapsulates: returns [ciphertext, sharedSecret]. */
  encap(pk: Uint8Array, seed?: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      return this._encapCore(pk, seed);
    } catch (e: unknown) {
      throw new MlKemError(e);
    }
  }

  /** Decapsulates: returns sharedSecret. */
  decap(ct: Uint8Array, sk: Uint8Array): Uint8Array {
    try {
      return this._decapCore(ct, sk);
    } catch (e: unknown) {
      throw new MlKemError(e);
    }
  }

  /** @internal */
  static async _create(): Promise<MlKem768Impl> {
    const impl = new MlKem768Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized MlKem768 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlKemInterface} instance.
 *
 * @example
 *
 * ```ts
 * const ctx = await createMlKem768();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export function createMlKem768(): Promise<MlKemInterface> {
  return MlKem768Impl._create();
}
