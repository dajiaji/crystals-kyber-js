/**
 * Interface for synchronous ML-KEM operations.
 *
 * Use the async factory functions {@link createMlKem512}, {@link createMlKem768},
 * or {@link createMlKem1024} to create instances that implement this interface.
 */
export interface MlKemInterface {
  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array];
  /** Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array];
  /** Encapsulates: returns [ciphertext, sharedSecret]. */
  encap(pk: Uint8Array, seed?: Uint8Array): [Uint8Array, Uint8Array];
  /** Decapsulates: returns sharedSecret. */
  decap(ct: Uint8Array, sk: Uint8Array): Uint8Array;
}
