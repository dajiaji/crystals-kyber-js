import { MlKemError } from "./errors.ts";
import type { MlKemInterface } from "./interfaces.ts";
import { MlKem1024Base } from "./mlKem1024Base.ts";

/**
 * Synchronous implementation of MlKem1024.
 *
 * Use {@link createMlKem1024} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { createMlKem1024 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { createMlKem1024 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = await createMlKem1024();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createMlKem1024();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class MlKem1024Impl extends MlKem1024Base implements MlKemInterface {
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
  static async _create(): Promise<MlKem1024Impl> {
    const impl = new MlKem1024Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized MlKem1024 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlKemInterface} instance.
 *
 * @example
 *
 * ```ts
 * const ctx = await createMlKem1024();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export function createMlKem1024(): Promise<MlKemInterface> {
  return MlKem1024Impl._create();
}
