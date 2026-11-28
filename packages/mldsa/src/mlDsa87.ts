import type {
  MlDsaSignerInterface,
  MlDsaVerifierInterface,
} from "./interfaces.ts";
import { MlDsaSigner } from "./mlDsaSigner.ts";
import { MlDsaVerifier } from "./mlDsaVerifier.ts";
import { ML_DSA_87 } from "./params.ts";

/**
 * Creates a pre-initialized ML-DSA-87 (NIST security category 5) signer
 * with synchronous key generation and signing.
 *
 * The public key, the private key and the signature are 2592, 4896 and
 * 4627 octets in length respectively.
 *
 * @returns A promise that resolves to an {@link MlDsaSignerInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createMlDsa87Signer, createMlDsa87Verifier } from "@webpqc/mldsa";
 *
 * const signer = await createMlDsa87Signer();
 * const [pk, sk] = signer.generateKeyPair();                 // sync
 *
 * const msg = new TextEncoder().encode("hello world");
 * const sig = signer.sign(sk, msg);                          // sync
 *
 * const verifier = await createMlDsa87Verifier();
 * const ok = verifier.verify(pk, sig, msg);                  // sync
 * // ok === true
 * ```
 */
export function createMlDsa87Signer(): Promise<MlDsaSignerInterface> {
  return MlDsaSigner._create(ML_DSA_87);
}

/**
 * Creates a pre-initialized ML-DSA-87 (NIST security category 5) verifier
 * with synchronous verification.
 *
 * An application which uses only this does not bundle the code for key
 * generation and signing.
 *
 * @returns A promise that resolves to an {@link MlDsaVerifierInterface} instance.
 *
 * @example
 *
 * ```ts
 * import { createMlDsa87Verifier } from "@webpqc/mldsa";
 *
 * async function verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array) {
 *   const verifier = await createMlDsa87Verifier();
 *   return verifier.verify(pk, sig, msg);                    // sync
 * }
 * ```
 */
export function createMlDsa87Verifier(): Promise<MlDsaVerifierInterface> {
  return MlDsaVerifier._create(ML_DSA_87);
}
