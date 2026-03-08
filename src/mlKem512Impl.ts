import { MlKemError } from "./errors.ts";
import type { MlKemInterface } from "./interfaces.ts";
import { MlKem512Base } from "./mlKem512Base.ts";

/**
 * Synchronous implementation of MlKem512.
 *
 * Use {@link createMlKem512} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { createMlKem512 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { createMlKem512 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = await createMlKem512();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createMlKem512();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class MlKem512Impl extends MlKem512Base implements MlKemInterface {
  constructor() {
    super();
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
  static async _create(): Promise<MlKem512Impl> {
    const impl = new MlKem512Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized MlKem512 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlKemInterface} instance.
 *
 * @example
 *
 * ```ts
 * const ctx = await createMlKem512();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export function createMlKem512(): Promise<MlKemInterface> {
  return MlKem512Impl._create();
}
