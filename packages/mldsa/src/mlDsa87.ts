import { Q } from "./consts.ts";
import { MlDsaError } from "./errors.ts";
import type {
  MlDsaInterface,
  MlDsaSignOptions,
  MlDsaVerifyOptions,
} from "./interfaces.ts";
import { MlDsaBase } from "./mlDsaBase.ts";

/**
 * Synchronous implementation of ML-DSA-87 (NIST security category 5).
 *
 * The public key, the private key and the signature are 2592, 4896 and
 * 4627 octets in length respectively.
 *
 * Use {@link createMlDsa87} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * import { createMlDsa87 } from "@webpqc/mldsa";
 *
 * const signer = await createMlDsa87();
 * const [pk, sk] = signer.generateKeyPair();
 *
 * const msg = new TextEncoder().encode("hello world");
 * const sig = signer.sign(sk, msg);
 *
 * const verifier = await createMlDsa87();
 * const ok = verifier.verify(pk, sig, msg);
 * // ok === true
 * ```
 */
export class MlDsa87Impl extends MlDsaBase implements MlDsaInterface {
  override _k = 8;
  override _l = 7;
  override _eta = 2;
  override _tau = 60;
  override _gamma1Bits = 19;
  override _gamma2 = (Q - 1) / 32;
  override _omega = 75;
  override _cTildeSize = 64;

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
  static async _create(): Promise<MlDsa87Impl> {
    const impl = new MlDsa87Impl();
    await impl._setup();
    return impl;
  }
}

/**
 * Creates a pre-initialized ML-DSA-87 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlDsaInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createMlDsa87 } from "@webpqc/mldsa";
 *
 * const ctx = await createMlDsa87();
 * const [pk, sk] = ctx.generateKeyPair();                    // sync
 * const msg = new TextEncoder().encode("hello world");
 * const sig = ctx.sign(sk, msg);                             // sync
 * const ok = ctx.verify(pk, sig, msg);                       // sync
 * ```
 */
export function createMlDsa87(): Promise<MlDsaInterface> {
  return MlDsa87Impl._create();
}
