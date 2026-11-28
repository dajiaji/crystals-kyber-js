/**
 * Interface for synchronous HQC operations.
 *
 * Use the async factory functions {@link createHqc1}, {@link createHqc3},
 * or {@link createHqc5} to create instances that implement this interface.
 */
export interface HqcInterface {
  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array];
  /** Derives a keypair [publicKey, privateKey] deterministically from a 32-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array];
  /**
   * Encapsulates: returns [ciphertext, sharedSecret].
   *
   * The optional seed is `m || salt`, which makes the encapsulation
   * deterministic: 32 octets for HQC-1, 40 for HQC-3 and 48 for HQC-5.
   */
  encap(pk: Uint8Array, seed?: Uint8Array): [Uint8Array, Uint8Array];
  /** Decapsulates: returns sharedSecret. */
  decap(ct: Uint8Array, sk: Uint8Array): Uint8Array;
}
