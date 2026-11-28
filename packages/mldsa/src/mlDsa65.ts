import { Q } from "./consts.ts";
import { MlDsaError } from "./errors.ts";
import type {
  MlDsaInterface,
  MlDsaSignOptions,
  MlDsaVerifyOptions,
} from "./interfaces.ts";
import { MlDsaBase } from "./mlDsaBase.ts";

/**
 * Synchronous implementation of ML-DSA-65 (NIST security category 3).
 *
 * The public key, the private key and the signature are 1952, 4032 and
 * 3309 octets in length respectively.
 *
 * Use {@link createMlDsa65} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * import { createMlDsa65 } from "@webpqc/mldsa";
 *
 * const signer = await createMlDsa65();
 * const [pk, sk] = signer.generateKeyPair();
 *
 * const msg = new TextEncoder().encode("hello world");
 * const sig = signer.sign(sk, msg);
 *
 * const verifier = await createMlDsa65();
 * const ok = verifier.verify(pk, sig, msg);
 * // ok === true
 * ```
 */
export class MlDsa65Impl extends MlDsaBase implements MlDsaInterface {
  override _k = 6;
  override _l = 5;
  override _eta = 4;
  override _tau = 49;
  override _gamma1Bits = 19;
  override _gamma2 = (Q - 1) / 32;
  override _omega = 55;
  override _cTildeSize = 48;

  constructor() {
    super();
    this._init();
  }

  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array] {
    try {
      return this._generateKeyPairCore();
    } catch (e: unknown) {
      throw new MlDsaError(e);
    }
  }

  /** Derives a keypair [publicKey, privateKey] deterministically from a 32-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array] {
    try {
      return this._deriveKeyPairCore(seed);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    }
  }

  /** Signs a message: returns signature. */
  sign(sk: Uint8Array, msg: Uint8Array, opts?: MlDsaSignOptions): Uint8Array {
    try {
      return this._signCore(sk, msg, opts);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    }
  }

  /** Verifies a signature: returns true if the signature is valid. */
  verify(
    pk: Uint8Array,
    sig: Uint8Array,
    msg: Uint8Array,
    opts?: MlDsaVerifyOptions,
  ): boolean {
    try {
      return this._verifyCore(pk, sig, msg, opts);
    } catch (e: unknown) {
      throw new MlDsaError(e);
    }
  }

  /** @internal */
  static async _create(): Promise<MlDsa65Impl> {
    const impl = new MlDsa65Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized ML-DSA-65 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlDsaInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createMlDsa65 } from "@webpqc/mldsa";
 *
 * const ctx = await createMlDsa65();
 * const [pk, sk] = ctx.generateKeyPair();                    // sync
 * const msg = new TextEncoder().encode("hello world");
 * const sig = ctx.sign(sk, msg);                             // sync
 * const ok = ctx.verify(pk, sig, msg);                       // sync
 * ```
 */
export function createMlDsa65(): Promise<MlDsaInterface> {
  return MlDsa65Impl._create();
}
