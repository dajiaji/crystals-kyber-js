/**
 * Options for {@link MlDsaSignerInterface.sign}.
 */
export interface MlDsaSignOptions {
  /** A context string of at most 255 octets. Defaults to the empty string. */
  context?: Uint8Array;
  /**
   * An optional 32-octet seed (`rnd` in FIPS 204) for the signature
   * generation. If omitted, a fresh random value is used (the hedged variant).
   * Passing 32 zero octets gives the deterministic variant.
   */
  seed?: Uint8Array;
}

/**
 * Options for {@link MlDsaVerifierInterface.verify}.
 */
export interface MlDsaVerifyOptions {
  /** The context string the signature was generated with. */
  context?: Uint8Array;
}

/**
 * Interface for synchronous key generation and signing of ML-DSA.
 *
 * Use the async factory functions {@link createMlDsa44Signer},
 * {@link createMlDsa65Signer}, or {@link createMlDsa87Signer} to create
 * instances that implement this interface.
 */
export interface MlDsaSignerInterface {
  /** Generates a keypair [publicKey, privateKey]. */
  generateKeyPair(): [Uint8Array, Uint8Array];
  /** Derives a keypair [publicKey, privateKey] deterministically from a 32-octet seed. */
  deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array];
  /** Signs a message: returns signature. */
  sign(sk: Uint8Array, msg: Uint8Array, opts?: MlDsaSignOptions): Uint8Array;
}

/**
 * Interface for synchronous verification of ML-DSA.
 *
 * Use the async factory functions {@link createMlDsa44Verifier},
 * {@link createMlDsa65Verifier}, or {@link createMlDsa87Verifier} to create
 * instances that implement this interface. An application which only
 * verifies signatures does not bundle the code for signing.
 */
export interface MlDsaVerifierInterface {
  /** Verifies a signature: returns true if the signature is valid. */
  verify(
    pk: Uint8Array,
    sig: Uint8Array,
    msg: Uint8Array,
    opts?: MlDsaVerifyOptions,
  ): boolean;
}
